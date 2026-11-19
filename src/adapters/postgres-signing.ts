import { randomUUID, createPublicKey } from 'node:crypto';
import { z } from 'zod';
import type { AsyncStore } from '../core/async-store.js';
import { StorageError } from '../core/async-store.js';
import { EnvelopeSigner, sha256, verifyEnvelope } from '../core/crypto.js';
import { requireThat, DomainError } from '../core/model.js';
import { SigningKeyRing } from '../security/signing-keyring.js';

const clock =
  '(floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint)';
const kid = z.string().regex(/^[a-f0-9]{24}$/),
  digest = z.string().regex(/^[a-f0-9]{64}$/);
const time = z.number().int().nonnegative().safe();
const node = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/);
const nodes = z
  .array(node)
  .min(1)
  .max(100)
  .refine((values) => new Set(values).size === values.length);
const actor = z.string().trim().min(1).max(128),
  reason = z.string().trim().min(3).max(500);
const states = [
  'scheduled',
  'running',
  'completed',
  'paused',
  'expired',
  'cancelled',
] as const;
interface Policy {
  namespace: string;
  active_kid: string;
  epoch: number;
  context_hash: string;
  required_nodes: string;
  updated_at: number;
}
interface Plan {
  id: string;
  namespace: string;
  previous_kid: string;
  kid: string;
  epoch: number;
  context_hash: string;
  required_nodes: string;
  nonce: string;
  status: (typeof states)[number];
  not_before: number;
  expires_at: number;
  created_at: number;
  updated_at: number;
  revision: number;
  owner_token: string | null;
  lease_until: number | null;
  actor: string;
  reason: string;
  backup_receipt: string | null;
  last_error: string | null;
}
const readiness = z
  .object({
    purpose: z.literal('signing-readiness'),
    namespace: z.string(),
    planId: z.string().uuid(),
    epoch: time,
    nodeId: node,
    kid,
    contextHash: digest,
    nonce: z.string().uuid(),
    validUntil: time,
  })
  .strict();
const backup = z
  .object({
    planId: z.string().uuid(),
    namespace: z.string(),
    epoch: time,
    previousKid: kid,
    kid,
    contextHash: digest,
    sha256: digest,
    reference: z.string().uuid(),
    verifiedAt: time,
  })
  .strict();
export type SigningBackupReceipt = z.infer<typeof backup>;
export interface SigningRotationView {
  id: string;
  namespace: string;
  previousKid: string;
  kid: string;
  epoch: number;
  contextHash: string;
  requiredNodes: string[];
  status: Plan['status'];
  notBefore: number;
  expiresAt: number;
  revision: number;
  actor: string;
  reason: string;
  backup: SigningBackupReceipt | null;
  lastError: string | null;
}
export interface PostgresSigningOptions {
  namespace: string;
  contextHash: string;
  primary: EnvelopeSigner;
  additionalKeys?: readonly EnvelopeSigner[];
  nodeId?: string;
  enabled?: boolean;
  leaseMs?: number;
  readinessMs?: number;
  backupTimeoutMs?: number;
  /** Trusted host callback. It must return only after creating and verifying the actual encrypted database/key backup. Never retried automatically. */
  createBackup?: (
    plan: SigningRotationView,
    signal: AbortSignal,
  ) => Promise<SigningBackupReceipt>;
}
function view(row: Plan): SigningRotationView {
  return {
    id: row.id,
    namespace: row.namespace,
    previousKid: row.previous_kid,
    kid: row.kid,
    epoch: row.epoch,
    contextHash: row.context_hash,
    requiredNodes: nodes.parse(JSON.parse(row.required_nodes)),
    status: row.status,
    notBefore: row.not_before,
    expiresAt: row.expires_at,
    revision: row.revision,
    actor: row.actor,
    reason: row.reason,
    backup: row.backup_receipt
      ? backup.parse(JSON.parse(row.backup_receipt))
      : null,
    lastError: row.last_error,
  };
}
function publicKey(value: string) {
  requireThat(value.length <= 256, 'INVALID_SIGNING_KEY');
  requireThat(
    value.startsWith('-----BEGIN PUBLIC KEY-----'),
    'SIGNING_PUBLIC_KEY_REQUIRED',
  );
  const key = createPublicKey(value);
  requireThat(key.asymmetricKeyType === 'ed25519', 'ED25519_REQUIRED');
  const canonical = key.export({ type: 'spki', format: 'pem' }).toString();
  requireThat(
    value.replaceAll('\r\n', '\n').trim() === canonical.trim(),
    'INVALID_SIGNING_KEY',
  );
  return {
    publicKey: canonical,
    kid: sha256(key.export({ type: 'spki', format: 'der' })).slice(0, 24),
  };
}

/** Shared database controls activation; private keys remain in each host's configured key ring. */
export class PostgresSigningCoordinator {
  private readonly keys: SigningKeyRing;
  private readonly namespace: string;
  private readonly contextHash: string;
  private readonly leaseMs: number;
  private readonly readinessMs: number;
  private readonly timeoutMs: number;
  private busy = false;
  constructor(
    private readonly store: AsyncStore,
    private readonly options: PostgresSigningOptions,
  ) {
    this.options = Object.freeze({
      ...options,
      enabled: z.boolean().default(false).parse(options.enabled),
    });
    requireThat(store.transactionUnit !== true, 'ROOT_STORE_REQUIRED');
    this.namespace = z.string().min(1).max(128).parse(options.namespace);
    this.contextHash = digest.parse(options.contextHash);
    this.keys = new SigningKeyRing(options.primary, options.additionalKeys);
    requireThat(
      !options.enabled || typeof options.createBackup === 'function',
      'SIGNING_BACKUP_REQUIRED',
    );
    if (options.nodeId) node.parse(options.nodeId);
    this.leaseMs = z
      .number()
      .int()
      .min(300)
      .max(900000)
      .parse(options.leaseMs ?? 90000);
    this.readinessMs = z
      .number()
      .int()
      .min(100)
      .max(300000)
      .parse(options.readinessMs ?? 120000);
    this.timeoutMs = z
      .number()
      .int()
      .min(100)
      .max(60000)
      .parse(options.backupTimeoutMs ?? 30000);
  }
  private async transaction<T>(
    work: (unit: AsyncStore) => Promise<T>,
  ): Promise<T> {
    for (let attempt = 0; ; attempt++)
      try {
        return await this.store.transaction(work);
      } catch (error) {
        if (
          attempt >= 2 ||
          !(error instanceof StorageError) ||
          !error.retryable
        )
          throw error;
      }
  }
  private async now(unit: AsyncStore) {
    return (await unit.get<{ now: number }>(`SELECT ${clock} AS now`))!.now;
  }
  private async audit(
    unit: AsyncStore,
    who: string,
    action: string,
    target: string,
    details: object,
  ) {
    await unit.run(
      `INSERT INTO audit VALUES($1,$2,$3,$4,$5,${clock})`,
      randomUUID(),
      who,
      action,
      target,
      JSON.stringify(details),
    );
  }
  private async policy(unit: AsyncStore, lock = '') {
    const row = await unit.get<Policy>(
      `SELECT * FROM signing_policies WHERE namespace=$1 ${lock}`,
      this.namespace,
    );
    requireThat(row, 'SIGNING_POLICY_NOT_CONFIGURED', 409);
    requireThat(
      row.context_hash === this.contextHash,
      'SIGNING_CONTEXT_CHANGED',
      409,
    );
    return row;
  }
  private async register(unit: AsyncStore, pem: string) {
    const key = publicKey(pem);
    await unit.run(
      `INSERT INTO signing_keys VALUES($1,$2,$3,${clock}) ON CONFLICT(namespace,kid) DO NOTHING`,
      this.namespace,
      key.kid,
      key.publicKey,
    );
    const row = await unit.get<{ public_key: string }>(
      'SELECT public_key FROM signing_keys WHERE namespace=$1 AND kid=$2',
      this.namespace,
      key.kid,
    );
    requireThat(
      row?.public_key === key.publicKey,
      'SIGNING_KEY_IMMUTABLE',
      409,
    );
    return key;
  }
  async initialize(input: {
    activeKid: string;
    requiredNodes: string[];
    actor: string;
    reason: string;
  }) {
    const parsed = z
        .object({ activeKid: kid, requiredNodes: nodes, actor, reason })
        .strict()
        .parse(input),
      required = [...parsed.requiredNodes].sort();
    const signer = this.keys.get(parsed.activeKid);
    requireThat(signer, 'SIGNING_KEY_UNAVAILABLE', 503);
    requireThat(
      signer.kid === this.options.primary.kid,
      'SIGNING_INITIAL_KEY_MISMATCH',
      409,
    );
    return this.transaction(async (unit) => {
      await this.register(unit, signer.publicKey);
      const inserted = await unit.run(
        `INSERT INTO signing_policies VALUES($1,$2,1,$3,$4,${clock}) ON CONFLICT(namespace) DO NOTHING`,
        this.namespace,
        signer.kid,
        this.contextHash,
        JSON.stringify(required),
      );
      const policy = await this.policy(unit, 'FOR UPDATE');
      requireThat(
        policy.active_kid === signer.kid &&
          policy.required_nodes === JSON.stringify(required),
        'SIGNING_POLICY_ALREADY_CONFIGURED',
        409,
      );
      if (inserted.changes)
        await this.audit(
          unit,
          parsed.actor,
          'signing.policy-created',
          this.namespace,
          {
            kid: signer.kid,
            nodes: required,
            contextHash: this.contextHash,
            reason: parsed.reason,
          },
        );
      return {
        kid: policy.active_kid,
        epoch: policy.epoch,
        contextHash: policy.context_hash,
        requiredNodes: required,
      };
    });
  }
  async schedule(input: {
    publicKey: string;
    notBefore: number;
    expiresAt: number;
    actor: string;
    reason: string;
    clientsReady: true;
  }) {
    const parsed = z
      .object({
        publicKey: z.string().max(256),
        notBefore: time,
        expiresAt: time,
        actor,
        reason,
        clientsReady: z.literal(true),
      })
      .strict()
      .parse(input);
    return this.transaction(async (unit) => {
      const policy = await this.policy(unit, 'FOR UPDATE'),
        now = await this.now(unit);
      requireThat(
        parsed.notBefore >= now + 1000 &&
          parsed.notBefore <= now + 365 * 86400000 &&
          parsed.expiresAt > parsed.notBefore &&
          parsed.expiresAt - parsed.notBefore <= 86400000,
        'INVALID_SIGNING_WINDOW',
      );
      const key = await this.register(unit, parsed.publicKey);
      requireThat(
        key.kid !== policy.active_kid,
        'SIGNING_KEY_ALREADY_ACTIVE',
        409,
      );
      requireThat(
        !(await unit.get(
          "SELECT id FROM signing_rotations WHERE namespace=$1 AND status IN ('scheduled','running')",
          this.namespace,
        )),
        'SIGNING_PLAN_EXISTS',
        409,
      );
      const id = randomUUID();
      await unit.run(
        `INSERT INTO signing_rotations VALUES($1,$2,$3,$4,$5,$6,$7,$8,'scheduled',$9,$10,${clock},${clock},0,NULL,NULL,$11,$12,NULL,NULL)`,
        id,
        this.namespace,
        policy.active_kid,
        key.kid,
        policy.epoch,
        this.contextHash,
        policy.required_nodes,
        randomUUID(),
        parsed.notBefore,
        parsed.expiresAt,
        parsed.actor,
        parsed.reason,
      );
      await this.audit(unit, parsed.actor, 'signing.scheduled', id, {
        previousKid: policy.active_kid,
        kid: key.kid,
        epoch: policy.epoch,
        notBefore: parsed.notBefore,
        expiresAt: parsed.expiresAt,
        contextHash: this.contextHash,
        clientsReady: true,
        reason: parsed.reason,
      });
      return view(
        (await unit.get<Plan>(
          'SELECT * FROM signing_rotations WHERE id=$1',
          id,
        ))!,
      );
    });
  }
  async status(id?: string) {
    if (id) z.string().uuid().parse(id);
    const row = id
      ? await this.store.get<Plan>(
          'SELECT * FROM signing_rotations WHERE namespace=$1 AND id=$2',
          this.namespace,
          id,
        )
      : await this.store.get<Plan>(
          "SELECT * FROM signing_rotations WHERE namespace=$1 ORDER BY CASE WHEN status IN ('scheduled','running') THEN 0 ELSE 1 END,created_at DESC,id DESC LIMIT 1",
          this.namespace,
        );
    return row ? view(row) : undefined;
  }
  async acknowledge(id: string) {
    z.string().uuid().parse(id);
    requireThat(this.options.nodeId, 'SIGNING_NODE_REQUIRED');
    const nodeId = this.options.nodeId;
    return this.transaction(async (unit) => {
      const policy = await this.policy(unit, 'FOR SHARE'),
        plan = await unit.get<Plan>(
          'SELECT * FROM signing_rotations WHERE namespace=$1 AND id=$2 FOR SHARE',
          this.namespace,
          id,
        ),
        now = await this.now(unit);
      requireThat(
        plan &&
          ['scheduled', 'running'].includes(plan.status) &&
          plan.expires_at > now,
        'SIGNING_PLAN_NOT_ACTIVE',
        409,
      );
      requireThat(
        plan.epoch === policy.epoch &&
          plan.previous_kid === policy.active_kid &&
          plan.context_hash === this.contextHash &&
          plan.required_nodes === policy.required_nodes,
        'SIGNING_PLAN_STALE',
        409,
      );
      requireThat(
        nodes
          .parse(JSON.parse(plan.required_nodes))
          .includes(this.options.nodeId!),
        'SIGNING_NODE_NOT_EXPECTED',
        403,
      );
      const signer = this.keys.get(plan.kid);
      requireThat(signer, 'SIGNING_KEY_UNAVAILABLE', 503);
      const until = Math.min(now + this.readinessMs, plan.expires_at),
        proof = signer.sign(
          {
            purpose: 'signing-readiness',
            namespace: this.namespace,
            planId: id,
            epoch: plan.epoch,
            nodeId: this.options.nodeId,
            kid: plan.kid,
            contextHash: this.contextHash,
            nonce: plan.nonce,
            validUntil: until,
          },
          'plk-signing-ready',
        );
      await unit.run(
        'INSERT INTO signing_readiness VALUES($1,$2,$3,$4) ON CONFLICT(plan_id,node_id) DO UPDATE SET proof=excluded.proof,expires_at=excluded.expires_at',
        id,
        nodeId,
        proof,
        until,
      );
      return {
        planId: id,
        nodeId: this.options.nodeId,
        kid: plan.kid,
        expiresAt: until,
      };
    });
  }
  private async assertReady(unit: AsyncStore, plan: Plan, now: number) {
    const registered = await unit.get<{ public_key: string }>(
      'SELECT public_key FROM signing_keys WHERE namespace=$1 AND kid=$2',
      this.namespace,
      plan.kid,
    );
    requireThat(
      registered && publicKey(registered.public_key).kid === plan.kid,
      'SIGNING_POLICY_INVALID',
      503,
    );
    const rows = await unit.all<{
      node_id: string;
      proof: string;
      expires_at: number;
    }>('SELECT * FROM signing_readiness WHERE plan_id=$1', plan.id);
    for (const nodeId of nodes.parse(JSON.parse(plan.required_nodes))) {
      const row = rows.find((value) => value.node_id === nodeId);
      requireThat(row && row.expires_at > now, 'SIGNING_NODES_NOT_READY', 409);
      let value: z.infer<typeof readiness>;
      try {
        value = readiness.parse(
          verifyEnvelope(row.proof, registered.public_key, 'plk-signing-ready'),
        );
      } catch {
        throw new DomainError('SIGNING_READINESS_INVALID', 409);
      }
      requireThat(
        value.namespace === this.namespace &&
          value.planId === plan.id &&
          value.epoch === plan.epoch &&
          value.nodeId === nodeId &&
          value.kid === plan.kid &&
          value.contextHash === plan.context_hash &&
          value.nonce === plan.nonce &&
          value.validUntil === row.expires_at &&
          value.validUntil <= plan.expires_at &&
          value.validUntil <= now + 300000,
        'SIGNING_READINESS_INVALID',
        409,
      );
    }
  }
  private async changeState(
    unit: AsyncStore,
    plan: Plan,
    status: Plan['status'],
    code: string | null,
    who: string,
  ) {
    await unit.run(
      `UPDATE signing_rotations SET status=$1,last_error=$2,owner_token=NULL,lease_until=NULL,revision=revision+1,updated_at=${clock} WHERE id=$3`,
      status,
      code,
      plan.id,
    );
    await this.audit(unit, who, 'signing.' + status, plan.id, {
      code,
      revision: plan.revision + 1,
    });
  }
  async pause(
    id: string,
    input: { actor: string; reason: string; revision: number },
  ) {
    const parsed = z
      .object({ actor, reason, revision: time })
      .strict()
      .parse(input);
    z.string().uuid().parse(id);
    return this.transaction(async (unit) => {
      const row = await unit.get<Plan>(
        'SELECT * FROM signing_rotations WHERE namespace=$1 AND id=$2 FOR UPDATE',
        this.namespace,
        id,
      );
      requireThat(
        row &&
          ['scheduled', 'running'].includes(row.status) &&
          row.revision === parsed.revision,
        'SIGNING_PLAN_CHANGED',
        409,
      );
      await this.changeState(
        unit,
        row,
        'paused',
        'OPERATOR_PAUSED',
        parsed.actor,
      );
      await this.audit(unit, parsed.actor, 'signing.pause-reason', id, {
        reason: parsed.reason,
      });
      return view(
        (await unit.get<Plan>(
          'SELECT * FROM signing_rotations WHERE id=$1',
          id,
        ))!,
      );
    });
  }
  /** Call before restoring service after a database restore; never revive restored scheduled/running plans. */
  async pauseRestored(input: { actor: string; reason: string }) {
    const parsed = z.object({ actor, reason }).strict().parse(input);
    return this.transaction(async (unit) => {
      const rows = await unit.all<Plan>(
        "SELECT * FROM signing_rotations WHERE namespace=$1 AND status IN ('scheduled','running') FOR UPDATE",
        this.namespace,
      );
      for (const row of rows) {
        await this.changeState(
          unit,
          row,
          'paused',
          'SIGNING_RESTORE_REVIEW_REQUIRED',
          parsed.actor,
        );
        await this.audit(unit, parsed.actor, 'signing.restore-review', row.id, {
          reason: parsed.reason,
        });
        await unit.run(
          'DELETE FROM signing_readiness WHERE plan_id=$1',
          row.id,
        );
      }
      return { paused: rows.length };
    });
  }
  async tick() {
    if (!this.options.enabled || this.busy) return this.status();
    this.busy = true;
    let owned: Plan | undefined,
      token: string | undefined,
      verifiedReceipt: SigningBackupReceipt | undefined;
    let heartbeat: ReturnType<typeof setInterval> | undefined,
      heartbeatWork: Promise<void> | undefined,
      lost = false;
    try {
      owned = await this.transaction(async (unit) => {
        const row = await unit.get<Plan>(
            "SELECT * FROM signing_rotations WHERE namespace=$1 AND status IN ('scheduled','running') ORDER BY created_at,id LIMIT 1 FOR UPDATE",
            this.namespace,
          ),
          now = await this.now(unit);
        if (!row) return undefined;
        if (row.status === 'running') {
          if (row.lease_until! <= now || row.expires_at <= now)
            await this.changeState(
              unit,
              row,
              'paused',
              'SIGNING_LEASE_EXPIRED',
              'signing-worker',
            );
          return undefined;
        }
        if (now >= row.expires_at) {
          await this.changeState(
            unit,
            row,
            'expired',
            'SIGNING_WINDOW_EXPIRED',
            'signing-worker',
          );
          return undefined;
        }
        if (now < row.not_before) return undefined;
        const policy = await this.policy(unit);
        if (
          policy.epoch !== row.epoch ||
          policy.active_kid !== row.previous_kid ||
          policy.required_nodes !== row.required_nodes ||
          row.context_hash !== this.contextHash
        ) {
          await this.changeState(
            unit,
            row,
            'paused',
            'SIGNING_PLAN_STALE',
            'signing-worker',
          );
          return undefined;
        }
        try {
          await this.assertReady(unit, row, now);
        } catch (error) {
          if (
            error instanceof DomainError &&
            error.code === 'SIGNING_NODES_NOT_READY'
          )
            return undefined;
          throw error;
        }
        requireThat(this.options.createBackup, 'SIGNING_BACKUP_REQUIRED', 409);
        token = randomUUID();
        await unit.run(
          `UPDATE signing_rotations SET status='running',owner_token=$1,lease_until=LEAST(${clock}+$2,expires_at),revision=revision+1,updated_at=${clock} WHERE id=$3`,
          token,
          this.leaseMs,
          row.id,
        );
        await this.audit(unit, 'signing-worker', 'signing.running', row.id, {
          epoch: row.epoch,
          kid: row.kid,
        });
        return (await unit.get<Plan>(
          'SELECT * FROM signing_rotations WHERE id=$1',
          row.id,
        ))!;
      });
      if (!owned) return this.status();
      const plan = owned,
        owner = token!;
      heartbeat = setInterval(
        () => {
          if (heartbeatWork) return;
          heartbeatWork = this.transaction(async (unit) => {
            const changed = await unit.run(
              `UPDATE signing_rotations SET lease_until=LEAST(${clock}+$1,expires_at) WHERE id=$2 AND status='running' AND owner_token=$3 AND lease_until>${clock} AND expires_at>${clock}`,
              this.leaseMs,
              plan.id,
              owner,
            );
            requireThat(changed.changes === 1, 'SIGNING_LEASE_LOST', 409);
          })
            .catch(() => {
              lost = true;
            })
            .finally(() => {
              heartbeatWork = undefined;
            });
        },
        Math.max(50, Math.floor(this.leaseMs / 3)),
      );
      const abort = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      let receipt: SigningBackupReceipt;
      try {
        const value = await Promise.race([
          Promise.resolve().then(() =>
            this.options.createBackup!(view(plan), abort.signal),
          ),
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
              abort.abort();
              reject(new DomainError('SIGNING_BACKUP_TIMEOUT', 503));
            }, this.timeoutMs);
          }),
        ]);
        receipt = backup.parse(value);
        requireThat(
          receipt.planId === plan.id &&
            receipt.namespace === this.namespace &&
            receipt.epoch === plan.epoch &&
            receipt.previousKid === plan.previous_kid &&
            receipt.kid === plan.kid &&
            receipt.contextHash === this.contextHash &&
            receipt.verifiedAt >= plan.updated_at,
          'SIGNING_BACKUP_MISMATCH',
          409,
        );
        verifiedReceipt = receipt;
      } finally {
        clearTimeout(timer);
        abort.abort();
      }
      clearInterval(heartbeat);
      heartbeat = undefined;
      await heartbeatWork;
      requireThat(!lost, 'SIGNING_LEASE_LOST', 409);
      await this.transaction(async (unit) => {
        const policy = await this.policy(unit, 'FOR UPDATE'),
          row = await unit.get<Plan>(
            'SELECT * FROM signing_rotations WHERE namespace=$1 AND id=$2 FOR UPDATE',
            this.namespace,
            plan.id,
          ),
          now = await this.now(unit);
        requireThat(
          row?.status === 'running' &&
            row.owner_token === owner &&
            row.lease_until! > now &&
            row.expires_at > now,
          'SIGNING_LEASE_LOST',
          409,
        );
        requireThat(
          policy.epoch === row.epoch &&
            policy.active_kid === row.previous_kid &&
            policy.required_nodes === row.required_nodes &&
            row.context_hash === this.contextHash,
          'SIGNING_PLAN_STALE',
          409,
        );
        requireThat(
          receipt.planId === row.id &&
            receipt.namespace === this.namespace &&
            receipt.epoch === row.epoch &&
            receipt.previousKid === row.previous_kid &&
            receipt.kid === row.kid &&
            receipt.contextHash === this.contextHash &&
            receipt.verifiedAt >= row.updated_at &&
            receipt.verifiedAt <= now,
          'SIGNING_BACKUP_MISMATCH',
          409,
        );
        await this.assertReady(unit, row, now);
        await unit.run(
          `UPDATE signing_policies SET active_kid=$1,epoch=epoch+1,updated_at=${clock} WHERE namespace=$2`,
          row.kid,
          this.namespace,
        );
        await unit.run(
          `UPDATE signing_rotations SET status='completed',backup_receipt=$1,owner_token=NULL,lease_until=NULL,revision=revision+1,updated_at=${clock} WHERE id=$2`,
          JSON.stringify(receipt),
          row.id,
        );
        await this.audit(unit, 'signing-worker', 'signing.completed', row.id, {
          previousKid: row.previous_kid,
          kid: row.kid,
          epoch: row.epoch + 1,
          backup: receipt.sha256,
        });
      });
    } catch (error) {
      if (owned && token)
        try {
          await this.transaction(async (unit) => {
            const row = await unit.get<Plan>(
              'SELECT * FROM signing_rotations WHERE namespace=$1 AND id=$2 FOR UPDATE',
              this.namespace,
              owned!.id,
            );
            if (row?.status === 'running' && row.owner_token === token) {
              if (
                verifiedReceipt &&
                verifiedReceipt.verifiedAt <= (await this.now(unit)) &&
                row.epoch === verifiedReceipt.epoch &&
                row.context_hash === verifiedReceipt.contextHash
              ) {
                await unit.run(
                  'UPDATE signing_rotations SET backup_receipt=$1 WHERE id=$2',
                  JSON.stringify(verifiedReceipt),
                  row.id,
                );
                await this.audit(
                  unit,
                  'signing-worker',
                  'signing.backup-verified',
                  row.id,
                  {
                    sha256: verifiedReceipt.sha256,
                    reference: verifiedReceipt.reference,
                  },
                );
              }
              await this.changeState(
                unit,
                row,
                'paused',
                error instanceof DomainError
                  ? error.code
                  : 'SIGNING_EXECUTION_UNCERTAIN',
                'signing-worker',
              );
            }
          });
        } catch {
          /* Keep the lease and unknown result for database recovery; never repeat the backup. */
        }
      throw error;
    } finally {
      clearInterval(heartbeat);
      await heartbeatWork;
      this.busy = false;
    }
    return this.status(owned!.id);
  }
  start(
    options: { intervalMs?: number; onError?: (code: string) => void } = {},
  ) {
    const interval = z
      .number()
      .int()
      .min(100)
      .max(60000)
      .parse(options.intervalMs ?? 1000);
    let stopping = false,
      running: Promise<void> | undefined;
    const run = () => {
      if (stopping || running) return;
      running = (async () => {
        const plan = await this.status();
        if (
          this.options.nodeId &&
          plan &&
          ['scheduled', 'running'].includes(plan.status)
        ) {
          try {
            await this.acknowledge(plan.id);
          } catch (error) {
            options.onError?.(
              error instanceof DomainError
                ? error.code
                : 'SIGNING_NODE_UNAVAILABLE',
            );
          }
        }
        await this.tick();
      })()
        .catch((error) =>
          options.onError?.(
            error instanceof DomainError
              ? error.code
              : 'SIGNING_WORKER_UNAVAILABLE',
          ),
        )
        .finally(() => {
          running = undefined;
        });
    };
    const timer = setInterval(run, interval);
    run();
    return {
      stop: async () => {
        stopping = true;
        clearInterval(timer);
        await running;
      },
    };
  }
}
