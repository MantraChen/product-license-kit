import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  type AsyncStore,
  type SqlValue as SQLInputValue,
  StorageError,
} from './core/async-store.js';
import {
  AsyncQueries,
  mapAsync,
  filterAsync,
  someAsync,
} from './core/async-queries.js';
import { z } from 'zod';
import { PostgresTaskQueue } from './adapters/postgres-tasks.js';
import { SigningKeyRing } from './security/signing-keyring.js';
import {
  PostgresNotificationWorker,
  notificationQueueNamespace,
} from './adapters/postgres-notifications.js';
import {
  parseCatalog,
  addCalendarMonths,
  requireThat,
  rebindCost,
  notificationResourceSchema,
  type Catalog,
  type IdentityProvider,
  type CursorPage,
  type NotificationResource,
  type NotificationSink,
  type Offer,
  type VerifiedIdentity,
} from './core/model.js';
import {
  EnvelopeSigner,
  normalizeDevicePublicKey,
  randomToken,
  sha256,
  verifyDeviceProof,
  type LicenseClaims,
} from './core/crypto.js';

interface Account {
  id: string;
  provider: string;
  subject: string;
  created_at: number;
}
interface Invitation {
  hash: string;
  provider: string;
  subject: string;
  expires_at: number;
  used_at: number | null;
}
interface Order {
  id: string;
  account_id: string;
  offer_json: string;
  status: string;
  created_at: number;
  paid_at: number | null;
  payment_method: string | null;
  payment_reference: string | null;
}
interface Binding {
  account_id: string;
  group_id: string;
  device_id: string;
  public_key: string;
  key_thumbprint: string;
  fingerprint_json: string;
  bound_at: number;
  free_at: number;
  generation: number;
  enabled: number;
}
interface Challenge {
  id: string;
  account_id: string;
  kind: string;
  payload: string;
  message: string;
  expires_at: number;
  used_at: number | null;
}
interface Distribution {
  id: string;
  account_id: string;
  edition_id: string;
  release_id: string;
  identity_snapshot: string;
  artifact_sha256: string | null;
  manifest: string | null;
  created_at: number;
  finalized_at: number | null;
}
const pageQuery = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(30),
    cursor: z
      .string()
      .min(1)
      .max(1024)
      .regex(/^[A-Za-z0-9_-]+$/)
      .optional(),
  })
  .strict();
const pageCursor = z
  .object({
    scope: z.string(),
    createdAt: z.number().int().nonnegative().safe(),
    id: z.string().uuid(),
  })
  .strict();
export interface Fingerprint {
  schema: string;
  digest: string;
}
export interface Payment {
  method: string;
  reference: string;
  amount: number;
  currency: string;
}
interface PaymentException extends Payment {
  id: string;
  original_order_id: string;
  account_id: string;
  reason: string;
  status: string;
  created_at: number;
  resolved_at: number | null;
  resolution: string | null;
}
export interface AsyncFrameworkOptions {
  store: AsyncStore;
  catalog: Catalog;
  signer: EnvelopeSigner;
  additionalSigningKeys?: readonly EnvelopeSigner[];
  signingContextHash?: string;
  providers: IdentityProvider[];
  issuer: string;
  now?: () => number;
  licenseSeconds?: number;
  orderTtlSeconds?: number;
  /** Synchronous, fail-closed product policy (for example an application's credential status). */
  accountEnabled?: (accountId: string) => boolean;
}

/** Asynchronous domain implementation. Policy and cryptography helpers are shared with Framework. */
export class AsyncFramework {
  readonly store: AsyncStore;
  readonly catalog: Catalog;
  readonly signer: EnvelopeSigner;
  readonly providers: Map<string, IdentityProvider>;
  readonly issuer: string;
  readonly now: () => number;
  readonly licenseSeconds: number;
  readonly orderTtlSeconds: number;
  private readonly accountEnabled: (accountId: string) => boolean;
  private readonly units = new AsyncLocalStorage<AsyncStore>();
  private readonly signingKeys: SigningKeyRing;
  private readonly signingContextHash: string | undefined;
  private retrySafe = true;
  private constructor(options: AsyncFrameworkOptions) {
    this.store = options.store;
    this.catalog = parseCatalog(structuredClone(options.catalog));
    this.signer = options.signer;
    this.signingKeys = new SigningKeyRing(
      options.signer,
      options.additionalSigningKeys,
    );
    this.signingContextHash = options.signingContextHash;
    requireThat(
      this.signingContextHash === undefined ||
        /^[a-f0-9]{64}$/.test(this.signingContextHash),
      'INVALID_SIGNING_CONTEXT',
    );
    const freeze = (value: unknown): void => {
      if (value && typeof value === 'object') {
        for (const child of Object.values(value)) freeze(child);
        Object.freeze(value);
      }
    };
    freeze(this.catalog);
    this.providers = new Map(
      options.providers.map((provider) => [provider.name, provider]),
    );
    requireThat(
      this.providers.size === options.providers.length,
      'DUPLICATE_IDENTITY_PROVIDER',
    );
    this.issuer = options.issuer;
    this.now = options.now ?? Date.now;
    this.licenseSeconds = options.licenseSeconds ?? 900;
    this.orderTtlSeconds = options.orderTtlSeconds ?? 86400;
    this.accountEnabled = options.accountEnabled ?? (() => true);
    requireThat(
      Number.isInteger(this.orderTtlSeconds) &&
        this.orderTtlSeconds >= 60 &&
        this.orderTtlSeconds <= 30 * 86400,
      'INVALID_ORDER_DURATION',
    );
    requireThat(
      Number.isInteger(this.licenseSeconds) &&
        this.licenseSeconds >= 30 &&
        this.licenseSeconds <= 86400,
      'INVALID_LEASE_DURATION',
    );
  }
  static async create(options: AsyncFrameworkOptions) {
    requireThat(options.store.transactionUnit !== true, 'ROOT_STORE_REQUIRED');
    const result = new AsyncFramework(options);
    await result.inTransaction(() => result.initialize());
    return result;
  }
  /** Attach to an already-owned transaction. Await scoped operations sequentially; the host controls commit/retry. */
  using(unit: AsyncStore) {
    requireThat(unit.transactionUnit === true, 'TRANSACTION_UNIT_REQUIRED');
    const scoped = new AsyncFramework({
      store: unit,
      catalog: this.catalog,
      signer: this.signer,
      additionalSigningKeys: this.signingKeys.additional(),
      ...(this.signingContextHash
        ? { signingContextHash: this.signingContextHash }
        : {}),
      providers: [...this.providers.values()],
      issuer: this.issuer,
      now: this.now,
      licenseSeconds: this.licenseSeconds,
      orderTtlSeconds: this.orderTtlSeconds,
      accountEnabled: this.accountEnabled,
    });
    scoped.retrySafe = false;
    return scoped;
  }
  private get db() {
    return new AsyncQueries(this.units.getStore() ?? this.store);
  }
  private activeSigner() {
    return this.signingKeys.active(
      this.units.getStore() ?? this.store,
      this.issuer,
      this.signingContextHash,
    );
  }
  async currentSigningKey() {
    return this.atomic(async () => {
      const signer = await this.activeSigner();
      return { kid: signer.kid, publicKey: signer.publicKey };
    });
  }
  private async inTransaction<T>(work: () => Promise<T>): Promise<T> {
    const current = this.units.getStore();
    if (current)
      return current.transaction((unit) => this.units.run(unit, work));
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.store.transaction((unit) =>
          this.units.run(unit, work),
        );
      } catch (error) {
        if (
          !this.retrySafe ||
          attempt >= 2 ||
          !(error instanceof StorageError) ||
          !(error.retryable || error.postgresCode === '23505')
        )
          throw error;
      }
    }
  }
  private atomic<T>(work: () => Promise<T>): Promise<T> {
    return this.units.getStore() ? work() : this.inTransaction(work);
  }

  private async initialize() {
    await this.db.run(
      "INSERT OR IGNORE INTO order_deadlines SELECT id,?,NULL FROM orders WHERE status='pending'",
      this.now() + this.orderTtlSeconds * 1000,
    );
    for (const row of await this.db.all<{ edition_id: string }>(
      'SELECT DISTINCT edition_id FROM entitlements',
    ))
      requireThat(
        this.catalog.editions.some((e) => e.id === row.edition_id),
        'CATALOG_REMOVES_EXISTING_ENTITLEMENT',
      );
    for (const row of await this.db.all<{ group_id: string }>(
      'SELECT DISTINCT group_id FROM bindings',
    ))
      requireThat(
        this.catalog.groups.some((g) => g.id === row.group_id),
        'CATALOG_REMOVES_EXISTING_DEVICE_GROUP',
      );
  }
  private async audit(
    actor: string,
    action: string,
    target: string,
    details: object = {},
  ): Promise<void> {
    await this.db.run(
      'INSERT INTO audit VALUES (?,?,?,?,?,?)',
      randomUUID(),
      actor,
      action,
      target,
      JSON.stringify(details),
      this.now(),
    );
  }
  private async event(
    topic: string,
    accountId: string,
    resource: NotificationResource = { kind: 'account', id: accountId },
  ): Promise<void> {
    const target = notificationResourceSchema.parse(resource);
    const eventId = randomUUID();
    await this.db.run(
      'INSERT INTO outbox(id,topic,account_id,created_at) VALUES (?,?,?,?)',
      eventId,
      topic,
      accountId,
      this.now(),
    );
    await this.db.run(
      'INSERT INTO outbox_resources VALUES(?,?,?)',
      eventId,
      target.kind,
      target.id,
    );
    const unit = this.units.getStore();
    requireThat(unit, 'TRANSACTION_UNIT_REQUIRED');
    await new PostgresTaskQueue(unit, {
      namespace: notificationQueueNamespace,
    }).enqueue({
      key: eventId,
      payload: { eventId },
    });
  }
  private async account(id: string): Promise<Account> {
    const account = await this.db.get<Account>(
      'SELECT * FROM accounts WHERE id=?',
      id,
    );
    requireThat(account, 'ACCOUNT_NOT_FOUND', 404);
    return account;
  }
  async isAccountActive(accountId: string): Promise<boolean> {
    return this.atomic(async () => {
      return (
        !!(await this.db.get('SELECT 1 FROM accounts WHERE id=?', accountId)) &&
        (
          await this.db.get<{
            active: number;
          }>('SELECT active FROM account_states WHERE account_id=?', accountId)
        )?.active !== 0 &&
        this.accountEnabled(accountId) === true
      );
    });
  }
  async assertAccountActive(accountId: string): Promise<void> {
    return this.atomic(async () => {
      requireThat(
        await this.isAccountActive(accountId),
        'ACCOUNT_DISABLED',
        403,
      );
    });
  }
  async setAccountActive(
    accountId: string,
    active: boolean,
    reason: string,
  ): Promise<void> {
    return this.atomic(async () => {
      requireThat(
        typeof active === 'boolean' &&
          reason.trim().length >= 3 &&
          reason.length <= 500,
        'INVALID_ACCOUNT_STATUS',
      );
      await this.inTransaction(async () => {
        await this.account(accountId);
        await this.db.run(
          `INSERT INTO account_states VALUES(?,?,?,?) ON CONFLICT(account_id)
        DO UPDATE SET active=excluded.active,reason=excluded.reason,updated_at=excluded.updated_at`,
          accountId,
          active ? 1 : 0,
          reason,
          this.now(),
        );
        if (!active) {
          await this.db.run(
            'DELETE FROM sessions WHERE account_id=?',
            accountId,
          );
          await this.db.run(
            'UPDATE challenges SET used_at=? WHERE account_id=? AND used_at IS NULL',
            this.now(),
            accountId,
          );
          await this.db.run(
            'UPDATE bindings SET enabled=0,generation=generation+1 WHERE account_id=? AND enabled=1',
            accountId,
          );
        }
        await this.audit(
          'admin',
          active ? 'account.enabled' : 'account.disabled',
          accountId,
          { reason },
        );
        await this.event(
          active ? 'account.enabled' : 'account.disabled',
          accountId,
        );
      });
    });
  }
  private async owns(accountId: string, editionId: string): Promise<boolean> {
    return !!(await this.db.get(
      'SELECT 1 FROM entitlements WHERE account_id=? AND edition_id=? AND active=1',
      accountId,
      editionId,
    ));
  }
  private groupForEdition(editionId: string): {
    productId: string;
    groupId: string;
  } {
    const edition = this.catalog.editions.find((e) => e.id === editionId);
    requireThat(edition, 'EDITION_NOT_FOUND', 404);
    const product = this.catalog.products.find(
      (p) => p.id === edition.productId,
    )!;
    return { productId: product.id, groupId: product.groupId };
  }
  private async ownsGroup(
    accountId: string,
    groupId: string,
  ): Promise<boolean> {
    return await someAsync(
      this.catalog.editions,
      async (e) =>
        this.groupForEdition(e.id).groupId === groupId &&
        (await this.owns(accountId, e.id)),
    );
  }
  private async credits(accountId: string, groupId: string): Promise<number> {
    return (
      (
        await this.db.get<{
          balance: number;
        }>(
          'SELECT balance FROM credits WHERE account_id=? AND group_id=?',
          accountId,
          groupId,
        )
      )?.balance ?? 0
    );
  }
  private async addCredits(
    accountId: string,
    groupId: string,
    count: number,
  ): Promise<void> {
    await this.db.run(
      `INSERT INTO credits VALUES (?,?,?) ON CONFLICT(account_id,group_id)
      DO UPDATE SET balance=balance+excluded.balance`,
      accountId,
      groupId,
      count,
    );
  }
  /** Stored within the same write transaction as all effects; keys are account + operation scoped. */
  private async command<T>(
    accountId: string,
    operation: string,
    key: string,
    input: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    requireThat(/^[A-Za-z0-9_-]{16,128}$/.test(key), 'INVALID_IDEMPOTENCY_KEY');
    return await this.inTransaction(async () => {
      await this.assertAccountActive(accountId);
      const hash = sha256(JSON.stringify(input));
      const prior = await this.db.get<{
        request_hash: string;
        result_json: string;
      }>(
        'SELECT * FROM commands WHERE account_id=? AND operation=? AND command_key=?',
        accountId,
        operation,
        key,
      );
      if (prior) {
        requireThat(prior.request_hash === hash, 'IDEMPOTENCY_CONFLICT', 409);
        return JSON.parse(prior.result_json) as T;
      }
      const result = await work();
      await this.db.run(
        'INSERT INTO commands VALUES (?,?,?,?,?)',
        accountId,
        operation,
        key,
        hash,
        JSON.stringify(result),
      );
      return result;
    });
  }
  async issueInvitation(
    provider: string,
    subject: string,
  ): Promise<{
    ticket: string;
    expiresAt: number;
  }> {
    return this.atomic(async () => {
      requireThat(this.providers.has(provider), 'IDENTITY_PROVIDER_DISABLED');
      requireThat(
        !(await this.db.get(
          'SELECT 1 FROM accounts WHERE provider=? AND subject=?',
          provider,
          subject,
        )),
        'IDENTITY_ALREADY_REGISTERED',
        409,
      );
      const ticket = randomToken();
      const expiresAt = this.now() + 30 * 60000;
      await this.inTransaction(async () => {
        await this.db.run(
          'UPDATE invitations SET used_at=? WHERE provider=? AND subject=? AND used_at IS NULL',
          this.now(),
          provider,
          subject,
        );
        await this.db.run(
          'INSERT INTO invitations VALUES (?,?,?,?,NULL)',
          sha256(ticket),
          provider,
          subject,
          expiresAt,
        );
        await this.audit(
          'admin',
          'invitation.issued',
          `${provider}:${subject}`,
        );
      });
      return { ticket, expiresAt };
    });
  }
  private async verifyIdentity(
    provider: string,
    proof: string,
  ): Promise<VerifiedIdentity> {
    this.assertExternalIoAllowed();
    const adapter = this.providers.get(provider);
    requireThat(adapter, 'IDENTITY_PROVIDER_DISABLED', 401);
    const identity = await adapter.verify(proof);
    requireThat(
      identity?.provider === provider &&
        typeof identity.subject === 'string' &&
        identity.subject.length > 0 &&
        identity.subject.length <= 128,
      'INVALID_IDENTITY',
      401,
    );
    return { provider: identity.provider, subject: identity.subject };
  }
  private assertExternalIoAllowed() {
    requireThat(
      !this.units.getStore() && this.store.transactionUnit !== true,
      'EXTERNAL_IO_IN_TRANSACTION',
    );
  }
  private async session(accountId: string): Promise<{
    accessToken: string;
    expiresAt: number;
    accountId: string;
  }> {
    await this.assertAccountActive(accountId);
    const accessToken = randomToken();
    const expiresAt = this.now() + 12 * 60 * 60000;
    await this.db.run(
      'INSERT INTO sessions VALUES (?,?,?)',
      sha256(accessToken),
      accountId,
      expiresAt,
    );
    return { accessToken, expiresAt, accountId };
  }
  async register(ticket: string, proof: string) {
    this.assertExternalIoAllowed();
    const invitation = await this.db.get<Invitation>(
      'SELECT * FROM invitations WHERE hash=?',
      sha256(ticket),
    );
    requireThat(
      invitation && !invitation.used_at && invitation.expires_at > this.now(),
      'INVALID_INVITATION',
      401,
    );
    const identity = await this.verifyIdentity(invitation.provider, proof);
    requireThat(
      identity.subject === invitation.subject,
      'IDENTITY_MISMATCH',
      403,
    );
    return await this.inTransaction(async () => {
      const current = await this.db.get<Invitation>(
        'SELECT * FROM invitations WHERE hash=?',
        invitation.hash,
      );
      requireThat(
        current && !current.used_at && current.expires_at > this.now(),
        'INVALID_INVITATION',
        401,
      );
      const accountId = await this.createIdentityAccount(identity);
      await this.db.run(
        'UPDATE invitations SET used_at=? WHERE hash=?',
        this.now(),
        invitation.hash,
      );
      return await this.session(accountId);
    });
  }
  private async createIdentityAccount(
    identity: VerifiedIdentity,
    evidence: object = {},
  ) {
    requireThat(
      !(await this.db.get(
        'SELECT 1 FROM accounts WHERE provider=? AND subject=?',
        identity.provider,
        identity.subject,
      )),
      'IDENTITY_ALREADY_REGISTERED',
      409,
    );
    const accountId = randomUUID();
    await this.db.run(
      'INSERT INTO accounts VALUES (?,?,?,?)',
      accountId,
      identity.provider,
      identity.subject,
      this.now(),
    );
    await this.audit(accountId, 'account.registered', accountId, evidence);
    await this.event('account.registered', accountId);
    return accountId;
  }
  /** Trusted host only, with an already verified provider identity and a consumed registration grant in the same transaction.
   * Never expose as a public HTTP identity/subject endpoint. Does not issue a native bearer or any paid rights. */
  async registerVerifiedIdentity(
    identity: VerifiedIdentity,
    evidence: { source: string; reference: string; reason: string },
  ) {
    identity = z
      .object({
        provider: z.string().min(1).max(80),
        subject: z.string().min(1).max(128),
      })
      .strict()
      .parse(identity);
    evidence = z
      .object({
        source: z.string().regex(/^[A-Za-z0-9._-]{1,80}$/),
        reference: z.string().min(1).max(128),
        reason: z.string().trim().min(3).max(500),
      })
      .strict()
      .parse(evidence);
    requireThat(
      this.providers.has(identity.provider),
      'UNKNOWN_IDENTITY_PROVIDER',
    );
    return this.atomic(async () => ({
      accountId: await this.createIdentityAccount(identity, evidence),
    }));
  }
  async login(provider: string, proof: string) {
    const identity = await this.verifyIdentity(provider, proof);
    return await this.inTransaction(async () => {
      const account = await this.db.get<Account>(
        'SELECT * FROM accounts WHERE provider=? AND subject=?',
        identity.provider,
        identity.subject,
      );
      requireThat(account, 'IDENTITY_NOT_REGISTERED', 401);
      await this.assertAccountActive(account.id);
      await this.audit(account.id, 'session.created', account.id);
      return await this.session(account.id);
    });
  }
  async authenticate(token: string): Promise<string> {
    return this.atomic(async () => {
      const session = await this.db.get<{
        account_id: string;
        expires_at: number;
      }>('SELECT * FROM sessions WHERE hash=?', sha256(token));
      requireThat(
        session && session.expires_at > this.now(),
        'UNAUTHORIZED',
        401,
      );
      await this.assertAccountActive(session.account_id);
      return session.account_id;
    });
  }
  async logout(token: string): Promise<void> {
    return this.atomic(async () => {
      await this.db.run('DELETE FROM sessions WHERE hash=?', sha256(token));
    });
  }
  /** Security recovery never grants a free rebind or changes an existing cooldown. */
  async revokeAccess(
    accountId: string,
    reason: string,
    revokeDevices = false,
  ): Promise<void> {
    return this.atomic(async () => {
      requireThat(
        reason.trim().length >= 3 && reason.length <= 500,
        'INVALID_REASON',
      );
      await this.inTransaction(async () => {
        await this.account(accountId);
        await this.db.run('DELETE FROM sessions WHERE account_id=?', accountId);
        await this.db.run(
          'UPDATE challenges SET used_at=? WHERE account_id=? AND used_at IS NULL',
          this.now(),
          accountId,
        );
        if (revokeDevices) {
          await this.db.run(
            'UPDATE bindings SET enabled=0,generation=generation+1 WHERE account_id=?',
            accountId,
          );
          await this.db.run(
            'UPDATE binding_resets SET generation=generation+1 WHERE account_id=?',
            accountId,
          );
        }
        await this.audit(accountId, 'access.revoked', accountId, {
          reason,
          revokeDevices,
        });
      });
    });
  }
  async changeIdentity(
    accountId: string,
    provider: string,
    subject: string,
    reason: string,
  ): Promise<void> {
    return this.atomic(async () => {
      requireThat(this.providers.has(provider), 'IDENTITY_PROVIDER_DISABLED');
      await this.inTransaction(async () => {
        const old = await this.account(accountId);
        requireThat(
          old.provider !== provider || old.subject !== subject,
          'IDENTITY_UNCHANGED',
          409,
        );
        requireThat(
          !(await this.db.get(
            'SELECT 1 FROM accounts WHERE provider=? AND subject=?',
            provider,
            subject,
          )),
          'IDENTITY_ALREADY_REGISTERED',
          409,
        );
        await this.db.run(
          'UPDATE accounts SET provider=?,subject=? WHERE id=?',
          provider,
          subject,
          accountId,
        );
        await this.db.run('DELETE FROM sessions WHERE account_id=?', accountId);
        await this.db.run(
          'UPDATE challenges SET used_at=? WHERE account_id=? AND used_at IS NULL',
          this.now(),
          accountId,
        );
        await this.db.run(
          'UPDATE invitations SET used_at=? WHERE (provider=? AND subject=?) OR (provider=? AND subject=?)',
          this.now(),
          old.provider,
          old.subject,
          provider,
          subject,
        );
        await this.db.run(
          'UPDATE bindings SET enabled=0 WHERE account_id=?',
          accountId,
        );
        await this.audit('admin', 'identity.changed', accountId, {
          from: { provider: old.provider, subject: old.subject },
          to: { provider, subject },
          reason,
        });
        await this.event('identity.changed', accountId);
      });
    });
  }
  async profile(accountId: string) {
    return this.atomic(async () => {
      const account = await this.account(accountId);
      return {
        account,
        entitlements: await this.db.all(
          'SELECT edition_id,active,order_id FROM entitlements WHERE account_id=?',
          accountId,
        ),
        channels: await this.db.all(
          'SELECT c.edition_id,c.channel FROM entitlement_channels c JOIN entitlements e ON e.account_id=c.account_id AND e.edition_id=c.edition_id WHERE c.account_id=? AND e.active=1',
          accountId,
        ),
        bindings: await this.db.all(
          'SELECT b.group_id,b.device_id,b.key_thumbprint,b.bound_at,b.free_at,b.generation,b.enabled, EXISTS(SELECT 1 FROM binding_resets r WHERE r.account_id=b.account_id AND r.group_id=b.group_id AND r.generation=b.generation) AS reset_pending FROM bindings b WHERE b.account_id=?',
          accountId,
        ),
        credits: await this.db.all(
          'SELECT group_id,balance FROM credits WHERE account_id=?',
          accountId,
        ),
      };
    });
  }
  /** Trusted host only: verify the external evidence before invoking this method.
   * Never creates a payment, overwrites paid provenance, or restores revoked rights. */
  async importEntitlement(
    accountId: string,
    editionId: string,
    evidence: {
      source: string;
      reference: string;
      reason: string;
      betaAccess?: boolean;
    },
  ) {
    evidence = { ...evidence };
    return this.atomic(async () => {
      requireThat(
        /^[A-Za-z0-9._-]{1,80}$/.test(evidence.source) &&
          /^[A-Za-z0-9._:-]{1,256}$/.test(evidence.reference) &&
          evidence.reason.trim().length >= 3 &&
          evidence.reason.length <= 500 &&
          (evidence.betaAccess === undefined ||
            typeof evidence.betaAccess === 'boolean'),
        'INVALID_IMPORT_EVIDENCE',
      );
      return await this.inTransaction(async () => {
        await this.assertAccountActive(accountId);
        this.groupForEdition(editionId);
        const prior = await this.db.get<{
          account_id: string;
        }>(
          'SELECT account_id FROM entitlement_imports WHERE source=? AND reference=? AND edition_id=?',
          evidence.source,
          evidence.reference,
          editionId,
        );
        requireThat(
          !prior || prior.account_id === accountId,
          'ENTITLEMENT_IMPORT_ALREADY_CLAIMED',
          409,
        );
        const owned = await this.db.get<{
          active: number;
        }>(
          'SELECT active FROM entitlements WHERE account_id=? AND edition_id=?',
          accountId,
          editionId,
        );
        if (owned?.active === 0)
          return { editionId, status: 'revoked' as const };
        if (!prior) {
          await this.db.run(
            'INSERT INTO entitlement_imports VALUES(?,?,?,?,?,?)',
            evidence.source,
            evidence.reference,
            editionId,
            accountId,
            evidence.reason,
            this.now(),
          );
          await this.audit('admin', 'entitlement.imported', accountId, {
            editionId,
            ...evidence,
            alreadyOwned: !!owned,
          });
        }
        if (!owned) {
          await this.db.run(
            'INSERT INTO entitlements VALUES(?,?,NULL,1)',
            accountId,
            editionId,
          );
          await this.event('entitlement.imported', accountId, {
            kind: 'entitlement',
            id: editionId,
          });
        }
        if (
          evidence.betaAccess &&
          !(await this.hasReleaseAccess(accountId, editionId, 'beta'))
        ) {
          await this.db.run(
            "INSERT INTO entitlement_channels VALUES(?,?,'beta')",
            accountId,
            editionId,
          );
          await this.audit('admin', 'entitlement.beta-recognized', accountId, {
            editionId,
            ...evidence,
          });
        }
        return {
          editionId,
          status: owned ? ('already-owned' as const) : ('imported' as const),
        };
      });
    });
  }
  async hasReleaseAccess(
    accountId: string,
    editionId: string,
    channel: 'stable' | 'beta',
  ): Promise<boolean> {
    return this.atomic(async () => {
      return (
        (await this.isAccountActive(accountId)) &&
        (await this.owns(accountId, editionId)) &&
        (channel === 'stable' ||
          (channel === 'beta' &&
            !!(await this.db.get(
              "SELECT 1 FROM entitlement_channels WHERE account_id=? AND edition_id=? AND channel='beta'",
              accountId,
              editionId,
            ))))
      );
    });
  }
  async bestUpgradeOffer(
    accountId: string,
    editionId: string,
    channel: 'stable' | 'beta' = 'stable',
  ) {
    return this.atomic(async () => {
      await this.assertAccountActive(accountId);
      this.groupForEdition(editionId);
      requireThat(
        !(await this.hasReleaseAccess(accountId, editionId, channel)),
        channel === 'beta' ? 'CHANNEL_ALREADY_OWNED' : 'EDITION_ALREADY_OWNED',
        409,
      );
      const candidates = await filterAsync(
        this.catalog.offers,
        async (o) =>
          o.editionId === editionId &&
          (o.channel ?? 'stable') === channel &&
          ((o.kind === 'channel' && (await this.owns(accountId, editionId))) ||
            (o.kind === 'upgrade' &&
              (await this.hasReleaseAccess(
                accountId,
                o.requiresEditionId!,
                o.requiresChannel ?? 'stable',
              )))),
      );
      requireThat(
        new Set(candidates.map((o) => o.currency)).size <= 1,
        'AMBIGUOUS_UPGRADE_CURRENCY',
      );
      const offer = candidates.sort(
        (a, b) => a.amount - b.amount || a.id.localeCompare(b.id),
      )[0];
      requireThat(offer, 'UPGRADE_NOT_ELIGIBLE', 403);
      return offer;
    });
  }
  async createOrder(accountId: string, offerId: string, key: string) {
    return this.atomic(async () => {
      return await this.command(
        accountId,
        'order.create',
        key,
        { offerId },
        async () => {
          const offer = this.catalog.offers.find((o) => o.id === offerId);
          requireThat(offer, 'OFFER_NOT_FOUND', 404);
          await this.account(accountId);
          await this.checkOfferEligibility(accountId, offer);
          const orderId = randomUUID();
          await this.db.run(
            'INSERT INTO orders(id,account_id,offer_json,status,created_at) VALUES (?,?,?,?,?)',
            orderId,
            accountId,
            JSON.stringify(offer),
            'pending',
            this.now(),
          );
          const expiresAt = this.now() + this.orderTtlSeconds * 1000;
          await this.db.run(
            'INSERT INTO order_deadlines VALUES(?,?,NULL)',
            orderId,
            expiresAt,
          );
          await this.audit(accountId, 'order.created', orderId, {
            offerId,
            expiresAt,
          });
          return { orderId, status: 'pending', offer, expiresAt };
        },
      );
    });
  }
  private async checkOfferEligibility(
    accountId: string,
    offer: Offer,
  ): Promise<void> {
    await this.assertAccountActive(accountId);
    if (offer.kind === 'rebind')
      requireThat(
        await this.ownsGroup(accountId, offer.groupId!),
        'GROUP_NOT_OWNED',
        403,
      );
    else {
      const channel = offer.channel ?? 'stable';
      requireThat(
        !(await this.hasReleaseAccess(accountId, offer.editionId!, channel)),
        channel === 'beta' ? 'CHANNEL_ALREADY_OWNED' : 'EDITION_ALREADY_OWNED',
        409,
      );
      if (offer.kind === 'channel')
        requireThat(
          await this.owns(accountId, offer.editionId!),
          'UPGRADE_NOT_ELIGIBLE',
          403,
        );
      if (offer.kind === 'upgrade')
        requireThat(
          await this.hasReleaseAccess(
            accountId,
            offer.requiresEditionId!,
            offer.requiresChannel ?? 'stable',
          ),
          'UPGRADE_NOT_ELIGIBLE',
          403,
        );
    }
  }
  async orders(accountId: string) {
    return this.atomic(async () => {
      await this.assertAccountActive(accountId);
      return await mapAsync(
        await this.db.all<Order>(
          'SELECT * FROM orders WHERE account_id=? ORDER BY created_at DESC LIMIT 100',
          accountId,
        ),
        async (row) => await this.orderView(row),
      );
    });
  }
  private async orderView(row: Order) {
    return {
      id: row.id,
      offer: JSON.parse(row.offer_json) as Offer,
      ...(await this.orderLifecycle(row.id)),
      createdAt: row.created_at,
      paidAt: row.paid_at,
    };
  }
  async ordersPage(accountId: string, input: unknown = {}) {
    input = pageQuery.parse(input);
    return this.atomic(async () => {
      await this.assertAccountActive(accountId);
      const page = await this.pageRows<Order>('orders', accountId, input);
      return {
        ...page,
        items: await mapAsync(
          page.items,
          async (row) => await this.orderView(row),
        ),
      };
    });
  }
  private async pageRows<
    T extends {
      id: string;
      created_at: number;
    },
  >(
    table: 'orders' | 'audit' | 'distributions',
    accountId: string | undefined,
    input: unknown,
  ): Promise<CursorPage<T>> {
    const query = pageQuery.parse(input);
    const scope = JSON.stringify([table, accountId ?? null]);
    const clauses: string[] = [];
    const parameters: SQLInputValue[] = [];
    if (accountId !== undefined) {
      clauses.push('account_id=?');
      parameters.push(accountId);
    }
    if (table === 'distributions') {
      clauses.push(
        'finalized_at IS NOT NULL',
        'EXISTS (SELECT 1 FROM entitlements e WHERE e.account_id=distributions.account_id AND e.edition_id=distributions.edition_id AND e.active=1)',
      );
    }
    if (query.cursor) {
      let cursor: z.infer<typeof pageCursor>;
      try {
        cursor = pageCursor.parse(
          JSON.parse(Buffer.from(query.cursor, 'base64url').toString('utf8')),
        );
        requireThat(cursor.scope === scope, 'INVALID_PAGE_CURSOR');
      } catch {
        requireThat(false, 'INVALID_PAGE_CURSOR');
      }
      clauses.push('(created_at<? OR (created_at=? AND id<?))');
      parameters.push(cursor.createdAt, cursor.createdAt, cursor.id);
    }
    const rows = await this.db.all<T>(
      `SELECT * FROM ${table} WHERE ${clauses.length ? clauses.join(' AND ') : '1=1'} ORDER BY created_at DESC,id DESC LIMIT ?`,
      ...parameters,
      query.limit + 1,
    );
    const items = rows.slice(0, query.limit);
    const last = items.at(-1);
    const nextCursor =
      rows.length > query.limit && last
        ? Buffer.from(
            JSON.stringify({ scope, createdAt: last.created_at, id: last.id }),
          ).toString('base64url')
        : null;
    return { items, nextCursor };
  }
  async confirmPayment(
    orderId: string,
    payment: Payment,
    review?: {
      latePaymentReason: string;
    },
  ) {
    payment = this.payment(payment);
    review = review
      ? { latePaymentReason: review.latePaymentReason }
      : undefined;
    return this.atomic(async () => {
      return await this.fulfillPayment(orderId, payment, review);
    });
  }
  private payment(input: Payment): Payment {
    const payment = { ...input, reference: input.reference.trim() };
    requireThat(
      /^[A-Za-z0-9_-]{1,64}$/.test(payment.method) &&
        payment.reference.length >= 3 &&
        payment.reference.length <= 128 &&
        Number.isSafeInteger(payment.amount) &&
        payment.amount > 0 &&
        /^[A-Z]{3}$/.test(payment.currency),
      'INVALID_PAYMENT',
    );
    return payment;
  }
  private async fulfillPayment(
    orderId: string,
    input: Payment,
    review?: {
      latePaymentReason: string;
    },
    exceptionId?: string,
  ) {
    const payment = this.payment(input);
    return await this.inTransaction(async () => {
      const order = await this.db.get<Order>(
        'SELECT * FROM orders WHERE id=?',
        orderId,
      );
      requireThat(order, 'ORDER_NOT_FOUND', 404);
      const offer = JSON.parse(order.offer_json) as Offer;
      requireThat(
        payment.amount === offer.amount && payment.currency === offer.currency,
        'PAYMENT_AMOUNT_MISMATCH',
        409,
      );
      if (order.status === 'paid') {
        requireThat(
          order.payment_method === payment.method &&
            order.payment_reference === payment.reference,
          'PAYMENT_ALREADY_RECORDED',
          409,
        );
        return { orderId, status: 'paid', replayed: true };
      }
      const lifecycle = await this.orderLifecycle(orderId);
      if (lifecycle.status === 'expired') {
        requireThat(
          review &&
            review.latePaymentReason.trim().length >= 3 &&
            review.latePaymentReason.length <= 500,
          'LATE_PAYMENT_REVIEW_REQUIRED',
          409,
        );
      } else requireThat(order.status === 'pending', 'ORDER_NOT_PENDING', 409);
      requireThat(
        !(await this.db.get(
          'SELECT 1 FROM orders WHERE payment_method=? AND trim(payment_reference)=?',
          payment.method,
          payment.reference,
        )),
        'PAYMENT_REFERENCE_REUSED',
        409,
      );
      const reserved = await this.db.get<{
        id: string;
        status: string;
      }>(
        'SELECT id,status FROM payment_exceptions WHERE method=? AND reference=?',
        payment.method,
        payment.reference,
      );
      requireThat(
        !reserved ||
          (reserved.id === exceptionId && reserved.status === 'pending'),
        'PAYMENT_REFERENCE_REUSED',
        409,
      );
      await this.checkOfferEligibility(order.account_id, offer);
      if (offer.kind === 'rebind')
        await this.addCredits(order.account_id, offer.groupId!, offer.credits!);
      else if (!(await this.owns(order.account_id, offer.editionId!)))
        await this.db.run(
          `INSERT INTO entitlements VALUES (?,?,?,1) ON CONFLICT(account_id,edition_id)
        DO UPDATE SET active=1,order_id=excluded.order_id`,
          order.account_id,
          offer.editionId!,
          orderId,
        );
      if (offer.channel === 'beta')
        await this.db.run(
          "INSERT OR IGNORE INTO entitlement_channels VALUES(?,?,'beta')",
          order.account_id,
          offer.editionId!,
        );
      await this.db.run(
        'UPDATE orders SET status=?,paid_at=?,payment_method=?,payment_reference=? WHERE id=?',
        'paid',
        this.now(),
        payment.method,
        payment.reference,
        orderId,
      );
      await this.audit('admin', 'payment.confirmed', orderId, {
        method: payment.method,
        amount: payment.amount,
        currency: payment.currency,
        ...(lifecycle.status === 'expired'
          ? { latePaymentReason: review!.latePaymentReason.trim() }
          : {}),
      });
      await this.event('order.fulfilled', order.account_id, {
        kind: 'order',
        id: orderId,
      });
      return { orderId, status: 'paid', replayed: false };
    });
  }
  /** Register money verified in the receiving account, without granting any rights. */
  async recordPaymentException(
    originalOrderId: string,
    input: Payment,
    reason: string,
  ) {
    input = this.payment(input);
    return this.atomic(async () => {
      const payment = this.payment(input);
      requireThat(
        reason.trim().length >= 3 && reason.length <= 500,
        'INVALID_REASON',
      );
      return await this.inTransaction(async () => {
        const order = await this.db.get<Order>(
          'SELECT * FROM orders WHERE id=?',
          originalOrderId,
        );
        requireThat(order, 'ORDER_NOT_FOUND', 404);
        requireThat(
          !(await this.db.get(
            'SELECT 1 FROM orders WHERE payment_method=? AND trim(payment_reference)=?',
            payment.method,
            payment.reference,
          )),
          'PAYMENT_REFERENCE_REUSED',
          409,
        );
        const prior = await this.db.get<PaymentException>(
          'SELECT * FROM payment_exceptions WHERE method=? AND reference=?',
          payment.method,
          payment.reference,
        );
        if (prior) {
          requireThat(
            prior.original_order_id === originalOrderId &&
              prior.amount === payment.amount &&
              prior.currency === payment.currency,
            'PAYMENT_REFERENCE_REUSED',
            409,
          );
          return { id: prior.id, status: prior.status, replayed: true };
        }
        const id = randomUUID();
        await this.db.run(
          "INSERT INTO payment_exceptions VALUES(?,?,?,?,?,?,?,?,'pending',?,NULL,NULL)",
          id,
          originalOrderId,
          order.account_id,
          payment.method,
          payment.reference,
          payment.amount,
          payment.currency,
          reason.trim(),
          this.now(),
        );
        await this.audit('admin', 'payment.exception-recorded', id, {
          originalOrderId,
          amount: payment.amount,
          currency: payment.currency,
          reason,
        });
        return { id, status: 'pending', replayed: false };
      });
    });
  }
  async paymentExceptions() {
    return this.atomic(async () => {
      return await this.db.all<PaymentException>(
        'SELECT * FROM payment_exceptions ORDER BY created_at DESC,id LIMIT 100',
      );
    });
  }
  async resolvePaymentException(
    id: string,
    resolution:
      | {
          action: 'apply';
          orderId: string;
          reason: string;
        }
      | {
          action: 'refund';
          refundReference: string;
          reason: string;
        },
  ) {
    resolution = { ...resolution };
    return this.atomic(async () => {
      requireThat(
        resolution.reason.trim().length >= 3 && resolution.reason.length <= 500,
        'INVALID_REASON',
      );
      if (resolution.action === 'refund')
        requireThat(
          resolution.refundReference.trim().length >= 3 &&
            resolution.refundReference.length <= 128,
          'INVALID_PAYMENT',
        );
      return await this.inTransaction(async () => {
        const row = await this.db.get<PaymentException>(
          'SELECT * FROM payment_exceptions WHERE id=?',
          id,
        );
        requireThat(row, 'PAYMENT_EXCEPTION_NOT_FOUND', 404);
        const serialized = JSON.stringify(resolution);
        if (row.status !== 'pending') {
          requireThat(
            row.resolution === serialized,
            'PAYMENT_EXCEPTION_RESOLVED',
            409,
          );
          return { id, status: row.status, replayed: true };
        }
        if (resolution.action === 'apply') {
          const target = await this.db.get<Order>(
            'SELECT * FROM orders WHERE id=?',
            resolution.orderId,
          );
          requireThat(
            target && target.account_id === row.account_id,
            'PAYMENT_ACCOUNT_MISMATCH',
            409,
          );
          await this.fulfillPayment(
            target.id,
            row,
            { latePaymentReason: resolution.reason },
            row.id,
          );
        }
        const status = resolution.action === 'apply' ? 'applied' : 'refunded';
        await this.db.run(
          'UPDATE payment_exceptions SET status=?,resolved_at=?,resolution=? WHERE id=?',
          status,
          this.now(),
          serialized,
          id,
        );
        await this.audit(
          'admin',
          `payment.exception-${status}`,
          id,
          resolution,
        );
        return { id, status, replayed: false };
      });
    });
  }
  /** Derive expiry immediately, including before the periodic sweeper runs. */
  async orderLifecycle(orderId: string) {
    return this.atomic(async () => {
      const order = await this.db.get<{
        status: string;
      }>('SELECT status FROM orders WHERE id=?', orderId);
      requireThat(order, 'ORDER_NOT_FOUND', 404);
      const deadline = await this.db.get<{
        expires_at: number;
        expired_at: number | null;
      }>('SELECT * FROM order_deadlines WHERE order_id=?', orderId);
      const expired =
        order.status !== 'paid' &&
        ((order.status === 'pending' &&
          !!deadline &&
          deadline.expires_at <= this.now()) ||
          (order.status === 'cancelled' &&
            deadline?.expired_at !== null &&
            deadline?.expired_at !== undefined));
      return {
        status: expired ? 'expired' : order.status,
        expiresAt: deadline?.expires_at ?? null,
      };
    });
  }
  async expireOrders(): Promise<number> {
    return this.atomic(async () => {
      return await this.inTransaction(async () => {
        const rows = await this.db.all<{
          id: string;
          account_id: string;
        }>(
          "SELECT o.id,o.account_id FROM orders o JOIN order_deadlines d ON d.order_id=o.id WHERE o.status='pending' AND d.expires_at<=?",
          this.now(),
        );
        for (const row of rows) {
          await this.db.run(
            "UPDATE orders SET status='cancelled' WHERE id=?",
            row.id,
          );
          await this.db.run(
            'UPDATE order_deadlines SET expired_at=? WHERE order_id=?',
            this.now(),
            row.id,
          );
          await this.audit('system', 'order.expired', row.id);
        }
        return rows.length;
      });
    });
  }
  async cancelOrder(accountId: string, orderId: string): Promise<void> {
    return this.atomic(async () => {
      await this.inTransaction(async () => {
        await this.assertAccountActive(accountId);
        const row = await this.db.get<Order>(
          'SELECT * FROM orders WHERE id=? AND account_id=?',
          orderId,
          accountId,
        );
        requireThat(row, 'ORDER_NOT_FOUND', 404);
        requireThat(
          (await this.orderLifecycle(orderId)).status === 'pending',
          'ORDER_NOT_PENDING',
          409,
        );
        await this.db.run(
          "UPDATE orders SET status='cancelled' WHERE id=?",
          orderId,
        );
        await this.audit(accountId, 'order.cancelled', orderId);
      });
    });
  }
  async grantCredits(
    accountId: string,
    groupId: string,
    count: number,
    reason: string,
    key: string,
  ) {
    return this.atomic(async () => {
      requireThat(
        Number.isInteger(count) && count > 0 && count <= 100,
        'INVALID_CREDITS',
      );
      return await this.command(
        accountId,
        'admin.credits',
        key,
        { groupId, count, reason },
        async () => {
          await this.account(accountId);
          requireThat(
            this.catalog.groups.some((g) => g.id === groupId),
            'GROUP_NOT_FOUND',
            404,
          );
          await this.addCredits(accountId, groupId, count);
          await this.audit('admin', 'credits.granted', accountId, {
            groupId,
            count,
            reason,
          });
          return { balance: await this.credits(accountId, groupId) };
        },
      );
    });
  }
  /** Trusted administrator only. Explicitly sets or restores access without fabricating a payment. */
  async setEntitlementAccess(
    accountId: string,
    editionId: string,
    access: 'none' | 'stable' | 'beta',
    reason: string,
    key: string,
  ) {
    return this.atomic(async () => {
      requireThat(
        ['none', 'stable', 'beta'].includes(access) &&
          reason.trim().length >= 3 &&
          reason.length <= 500,
        'INVALID_ENTITLEMENT_CHANGE',
      );
      await this.assertAccountActive(accountId);
      this.groupForEdition(editionId);
      return await this.command(
        accountId,
        'admin.entitlement',
        key,
        { editionId, access, reason },
        async () => {
          await this.db.run(
            'INSERT INTO entitlements VALUES(?,?,NULL,?) ON CONFLICT(account_id,edition_id) DO UPDATE SET active=excluded.active',
            accountId,
            editionId,
            access === 'none' ? 0 : 1,
          );
          await this.db.run(
            'DELETE FROM entitlement_channels WHERE account_id=? AND edition_id=?',
            accountId,
            editionId,
          );
          if (access === 'beta')
            await this.db.run(
              "INSERT INTO entitlement_channels VALUES(?,?,'beta')",
              accountId,
              editionId,
            );
          await this.audit('admin', 'entitlement.access-set', accountId, {
            editionId,
            access,
            reason,
          });
          await this.event('entitlement.updated', accountId, {
            kind: 'entitlement',
            id: editionId,
          });
          return { editionId, access };
        },
      );
    });
  }
  async revokeEntitlement(
    accountId: string,
    editionId: string,
    reason: string,
  ): Promise<void> {
    return this.atomic(async () => {
      await this.inTransaction(async () => {
        requireThat(
          await this.owns(accountId, editionId),
          'ENTITLEMENT_NOT_FOUND',
          404,
        );
        await this.db.run(
          'UPDATE entitlements SET active=0 WHERE account_id=? AND edition_id=?',
          accountId,
          editionId,
        );
        await this.db.run(
          'DELETE FROM entitlement_channels WHERE account_id=? AND edition_id=?',
          accountId,
          editionId,
        );
        await this.audit('admin', 'entitlement.revoked', accountId, {
          editionId,
          reason,
        });
        await this.event('entitlement.revoked', accountId, {
          kind: 'entitlement',
          id: editionId,
        });
      });
    });
  }
  /** Preview never spends a credit; callers must confirm the observed generation and cost. */
  async deviceResetStatus(accountId: string, groupId: string) {
    return this.atomic(async () => {
      await this.assertAccountActive(accountId);
      requireThat(
        this.catalog.groups.some((g) => g.id === groupId),
        'GROUP_NOT_FOUND',
        404,
      );
      const binding = await this.db.get<Binding>(
        'SELECT * FROM bindings WHERE account_id=? AND group_id=?',
        accountId,
        groupId,
      );
      const pending =
        binding &&
        !!(await this.db.get(
          'SELECT 1 FROM binding_resets WHERE account_id=? AND group_id=? AND generation=?',
          accountId,
          groupId,
          binding.generation,
        ));
      const credits = await this.credits(accountId, groupId);
      const cost =
        !binding || pending || !(await this.ownsGroup(accountId, groupId))
          ? null
          : binding.free_at <= this.now()
            ? ('free' as const)
            : credits > 0
              ? ('credit' as const)
              : null;
      return {
        state: pending
          ? ('reset-pending' as const)
          : binding
            ? ('bound' as const)
            : ('unbound' as const),
        generation: binding?.generation ?? null,
        freeAt: binding?.free_at ?? null,
        credits,
        cost,
        canReset: cost !== null,
      };
    });
  }
  async resetDevice(
    accountId: string,
    groupId: string,
    expectedGeneration: number,
    expectedCost: 'free' | 'credit',
    key: string,
  ) {
    return this.atomic(async () => {
      requireThat(
        Number.isSafeInteger(expectedGeneration) &&
          expectedGeneration > 0 &&
          ['free', 'credit'].includes(expectedCost),
        'INVALID_RESET_REQUEST',
      );
      return await this.command(
        accountId,
        'device.reset',
        key,
        { groupId, expectedGeneration, expectedCost },
        async () => {
          requireThat(
            await this.ownsGroup(accountId, groupId),
            'GROUP_NOT_OWNED',
            403,
          );
          const state = await this.deviceResetStatus(accountId, groupId);
          requireThat(
            state.state === 'bound' && state.generation === expectedGeneration,
            'DEVICE_BINDING_CHANGED',
            409,
          );
          requireThat(state.cost, 'REBIND_COOLDOWN', 409);
          requireThat(
            state.cost === expectedCost,
            'DEVICE_RESET_COST_CHANGED',
            409,
          );
          const group = this.catalog.groups.find((g) => g.id === groupId)!;
          const binding = (await this.db.get<Binding>(
            'SELECT * FROM bindings WHERE account_id=? AND group_id=?',
            accountId,
            groupId,
          ))!;
          const generation = binding.generation + 1;
          const freeAt = addCalendarMonths(
            this.now(),
            group.cooldownMonths,
            group.utcOffsetMinutes,
          );
          if (state.cost === 'credit')
            await this.db.run(
              'UPDATE credits SET balance=balance-1 WHERE account_id=? AND group_id=?',
              accountId,
              groupId,
            );
          await this.db.run(
            'UPDATE bindings SET enabled=0,generation=?,free_at=? WHERE account_id=? AND group_id=?',
            generation,
            freeAt,
            accountId,
            groupId,
          );
          await this.db.run(
            'INSERT INTO binding_resets VALUES(?,?,?,?)',
            accountId,
            groupId,
            generation,
            this.now(),
          );
          await this.db.run(
            `UPDATE challenges SET used_at=? WHERE account_id=? AND used_at IS NULL AND
        ((kind='enroll' AND json_extract(payload,'$.groupId')=?) OR (kind='license' AND json_extract(payload,'$.deviceId')=?))`,
            this.now(),
            accountId,
            groupId,
            binding.device_id,
          );
          await this.audit(accountId, 'device.reset', binding.device_id, {
            groupId,
            cost: state.cost,
            generation,
            freeAt,
          });
          await this.event('device.reset', accountId, {
            kind: 'device',
            id: binding.device_id,
          });
          return {
            groupId,
            generation,
            freeAt,
            cost: state.cost,
            credits: await this.credits(accountId, groupId),
          };
        },
      );
    });
  }
  private async challenge(accountId: string, kind: string, payload: object) {
    await this.assertAccountActive(accountId);
    const id = randomUUID();
    const expiresAt = this.now() + 5 * 60000;
    const message = JSON.stringify([
      'product-license-kit',
      1,
      kind,
      id,
      accountId,
      payload,
      randomToken(),
    ]);
    await this.db.run(
      'INSERT INTO challenges VALUES (?,?,?,?,?,?,NULL)',
      id,
      accountId,
      kind,
      JSON.stringify(payload),
      message,
      expiresAt,
    );
    return { challengeId: id, message, expiresAt };
  }
  async enrollmentChallenge(
    accountId: string,
    groupId: string,
    publicKey: string,
    fingerprint: Fingerprint,
  ) {
    fingerprint = { ...fingerprint };
    return this.atomic(async () => {
      await this.assertAccountActive(accountId);
      requireThat(
        await this.ownsGroup(accountId, groupId),
        'GROUP_NOT_OWNED',
        403,
      );
      let normalized: ReturnType<typeof normalizeDevicePublicKey>;
      try {
        normalized = normalizeDevicePublicKey(publicKey);
      } catch {
        requireThat(false, 'INVALID_DEVICE_KEY');
      }
      return await this.challenge(accountId, 'enroll', {
        groupId,
        publicKey: normalized.pem,
        thumbprint: normalized.thumbprint,
        fingerprint,
      });
    });
  }
  async activate(
    accountId: string,
    challengeId: string,
    signature: string,
    key: string,
  ) {
    return this.atomic(async () => {
      return await this.command(
        accountId,
        'device.activate',
        key,
        { challengeId, signature },
        async () => {
          const challenge = await this.loadChallenge(challengeId, 'enroll');
          requireThat(
            challenge.account_id === accountId,
            'CHALLENGE_NOT_FOUND',
            404,
          );
          const payload = JSON.parse(challenge.payload) as {
            groupId: string;
            publicKey: string;
            thumbprint: string;
            fingerprint: Fingerprint;
          };
          requireThat(
            verifyDeviceProof(payload.publicKey, challenge.message, signature),
            'INVALID_DEVICE_PROOF',
            401,
          );
          requireThat(
            await this.ownsGroup(accountId, payload.groupId),
            'GROUP_NOT_OWNED',
            403,
          );
          const group = this.catalog.groups.find(
            (g) => g.id === payload.groupId,
          )!;
          const previous = await this.db.get<Binding>(
            'SELECT * FROM bindings WHERE account_id=? AND group_id=?',
            accountId,
            group.id,
          );
          const keyOwner = await this.db.get<Binding>(
            'SELECT * FROM bindings WHERE group_id=? AND key_thumbprint=?',
            group.id,
            payload.thumbprint,
          );
          requireThat(
            !keyOwner || keyOwner.account_id === accountId,
            'DEVICE_KEY_ALREADY_BOUND',
            409,
          );
          let cost: 'initial' | 'same-device' | 'free' | 'credit' | 'reset' =
            'initial';
          let deviceId: string = randomUUID();
          let generation = 1;
          let freeAt = addCalendarMonths(
            this.now(),
            group.cooldownMonths,
            group.utcOffsetMinutes,
          );
          if (previous) {
            generation = previous.generation + 1;
            if (
              await this.db.get(
                'SELECT 1 FROM binding_resets WHERE account_id=? AND group_id=? AND generation=?',
                accountId,
                group.id,
                previous.generation,
              )
            ) {
              cost = 'reset';
              freeAt = previous.free_at;
            } else if (
              previous.key_thumbprint === payload.thumbprint &&
              (JSON.parse(previous.fingerprint_json) as Fingerprint).schema ===
                payload.fingerprint.schema &&
              (JSON.parse(previous.fingerprint_json) as Fingerprint).digest ===
                payload.fingerprint.digest
            ) {
              cost = 'same-device';
              deviceId = previous.device_id;
              freeAt = previous.free_at;
              generation = previous.enabled ? previous.generation : generation;
            } else
              cost = rebindCost(
                previous.free_at,
                this.now(),
                await this.credits(accountId, group.id),
              );
          }
          if (cost === 'credit')
            await this.db.run(
              'UPDATE credits SET balance=balance-1 WHERE account_id=? AND group_id=?',
              accountId,
              group.id,
            );
          const boundAt =
            cost === 'same-device' ? previous!.bound_at : this.now();
          await this.db.run(
            `INSERT INTO bindings VALUES (?,?,?,?,?,?,?,?,?,1)
        ON CONFLICT(account_id,group_id) DO UPDATE SET device_id=excluded.device_id,public_key=excluded.public_key,
        key_thumbprint=excluded.key_thumbprint,fingerprint_json=excluded.fingerprint_json,bound_at=excluded.bound_at,
        free_at=excluded.free_at,generation=excluded.generation,enabled=1`,
            accountId,
            group.id,
            deviceId,
            payload.publicKey,
            payload.thumbprint,
            JSON.stringify(payload.fingerprint),
            boundAt,
            freeAt,
            generation,
          );
          await this.db.run(
            'DELETE FROM binding_resets WHERE account_id=? AND group_id=?',
            accountId,
            group.id,
          );
          await this.db.run(
            'UPDATE challenges SET used_at=? WHERE id=?',
            this.now(),
            challengeId,
          );
          await this.audit(accountId, 'device.activated', deviceId, {
            groupId: group.id,
            cost,
            generation,
            freeAt,
            previousDevice: previous?.device_id ?? null,
          });
          await this.event('device.activated', accountId, {
            kind: 'device',
            id: deviceId,
          });
          return {
            deviceId,
            groupId: group.id,
            keyThumbprint: payload.thumbprint,
            generation,
            freeAt,
            cost,
          };
        },
      );
    });
  }
  private async loadChallenge(id: string, kind: string): Promise<Challenge> {
    const row = await this.db.get<Challenge>(
      'SELECT * FROM challenges WHERE id=?',
      id,
    );
    requireThat(
      row &&
        row.kind === kind &&
        row.used_at === null &&
        row.expires_at > this.now(),
      'INVALID_CHALLENGE',
      401,
    );
    return row;
  }
  async licenseChallenge(
    deviceId: string,
    editionId: string,
    channel: 'stable' | 'beta' = 'stable',
  ) {
    return this.atomic(async () => {
      const binding = await this.db.get<Binding>(
        'SELECT * FROM bindings WHERE device_id=? AND enabled=1',
        deviceId,
      );
      requireThat(
        binding && (await this.owns(binding.account_id, editionId)),
        'LICENSE_UNAVAILABLE',
        403,
      );
      await this.assertAccountActive(binding.account_id);
      requireThat(
        await this.hasReleaseAccess(binding.account_id, editionId, channel),
        'LICENSE_UNAVAILABLE',
        403,
      );
      requireThat(
        this.groupForEdition(editionId).groupId === binding.group_id,
        'LICENSE_UNAVAILABLE',
        403,
      );
      return await this.challenge(binding.account_id, 'license', {
        deviceId,
        editionId,
        channel,
        generation: binding.generation,
      });
    });
  }
  async issueLicense(challengeId: string, signature: string) {
    return this.atomic(async () => {
      return await this.inTransaction(async () => {
        const challenge = await this.loadChallenge(challengeId, 'license');
        await this.assertAccountActive(challenge.account_id);
        const payload = JSON.parse(challenge.payload) as {
          deviceId: string;
          editionId: string;
          channel?: 'stable' | 'beta';
          generation: number;
        };
        const binding = await this.db.get<Binding>(
          'SELECT * FROM bindings WHERE device_id=? AND enabled=1',
          payload.deviceId,
        );
        requireThat(
          binding &&
            binding.account_id === challenge.account_id &&
            binding.generation === payload.generation &&
            (await this.owns(binding.account_id, payload.editionId)) &&
            this.groupForEdition(payload.editionId).groupId ===
              binding.group_id,
          'LICENSE_UNAVAILABLE',
          403,
        );
        requireThat(
          verifyDeviceProof(binding.public_key, challenge.message, signature),
          'INVALID_DEVICE_PROOF',
          401,
        );
        requireThat(
          await this.hasReleaseAccess(
            binding.account_id,
            payload.editionId,
            payload.channel ?? 'stable',
          ),
          'LICENSE_UNAVAILABLE',
          403,
        );
        const seconds = Math.floor(this.now() / 1000);
        const claims: LicenseClaims = {
          iss: this.issuer,
          aud: this.groupForEdition(payload.editionId).productId,
          sub: binding.account_id,
          edition: payload.editionId,
          channel: payload.channel ?? 'stable',
          fingerprint: JSON.parse(binding.fingerprint_json) as Fingerprint,
          device: binding.device_id,
          keyThumbprint: binding.key_thumbprint,
          generation: binding.generation,
          ownership: 'perpetual',
          iat: seconds,
          nbf: seconds,
          exp: seconds + this.licenseSeconds,
        };
        const token = (await this.activeSigner()).sign(claims, 'plk-license');
        await this.db.run(
          'UPDATE challenges SET used_at=? WHERE id=?',
          this.now(),
          challengeId,
        );
        return { token, expiresAt: claims.exp * 1000 };
      });
    });
  }
  async reserveDistribution(
    accountId: string,
    editionId: string,
    releaseId: string,
    key: string,
  ) {
    return this.atomic(async () => {
      return await this.command(
        accountId,
        'distribution.reserve',
        key,
        { editionId, releaseId },
        async () => {
          const account = await this.account(accountId);
          requireThat(
            await this.owns(accountId, editionId),
            'EDITION_NOT_OWNED',
            403,
          );
          const id = randomUUID();
          await this.db.run(
            'INSERT INTO distributions VALUES (?,?,?,?,?,NULL,NULL,?,NULL)',
            id,
            accountId,
            editionId,
            releaseId,
            JSON.stringify({
              provider: account.provider,
              subject: account.subject,
            }),
            this.now(),
          );
          await this.audit('admin', 'distribution.reserved', id, {
            accountId,
            editionId,
            releaseId,
          });
          return { distributionId: id, marker: `PLK-DISTRIBUTION:${id}` };
        },
      );
    });
  }
  async finalizeDistribution(id: string, artifactSha256: string) {
    return this.atomic(async () => {
      requireThat(
        /^[a-f0-9]{64}$/.test(artifactSha256),
        'INVALID_ARTIFACT_HASH',
      );
      return await this.inTransaction(async () => {
        const row = await this.db.get<Distribution>(
          'SELECT * FROM distributions WHERE id=?',
          id,
        );
        requireThat(row, 'DISTRIBUTION_NOT_FOUND', 404);
        await this.assertAccountActive(row.account_id);
        requireThat(
          await this.owns(row.account_id, row.edition_id),
          'EDITION_NOT_OWNED',
          403,
        );
        if (row.manifest) {
          requireThat(
            row.artifact_sha256 === artifactSha256,
            'DISTRIBUTION_IMMUTABLE',
            409,
          );
          return { manifest: row.manifest };
        }
        const manifest = (await this.activeSigner()).sign(
          {
            distributionId: row.id,
            editionId: row.edition_id,
            releaseId: row.release_id,
            sha256: artifactSha256,
            issuedAt: this.now(),
          },
          'plk-distribution',
        );
        await this.db.run(
          'UPDATE distributions SET artifact_sha256=?,manifest=?,finalized_at=? WHERE id=?',
          artifactSha256,
          manifest,
          this.now(),
          id,
        );
        await this.audit('admin', 'distribution.finalized', id, {
          artifactSha256,
        });
        await this.event('distribution.ready', row.account_id, {
          kind: 'distribution',
          id: row.id,
        });
        return { manifest };
      });
    });
  }
  async distributions(accountId: string) {
    return this.atomic(async () => {
      return (await this.distributionsPage(accountId, { limit: 100 })).items;
    });
  }
  private distributionView(row: Distribution) {
    return {
      id: row.id,
      editionId: row.edition_id,
      releaseId: row.release_id,
      manifest: row.manifest,
      sha256: row.artifact_sha256,
    };
  }
  async distributionsPage(accountId: string, input: unknown = {}) {
    input = pageQuery.parse(input);
    return this.atomic(async () => {
      await this.assertAccountActive(accountId);
      const page = await this.pageRows<Distribution>(
        'distributions',
        accountId,
        input,
      );
      return {
        ...page,
        items: page.items.map((row) => this.distributionView(row)),
      };
    });
  }
  async traceDistribution(id: string) {
    return this.atomic(async () => {
      const row = await this.db.get<Distribution>(
        'SELECT * FROM distributions WHERE id=?',
        id,
      );
      requireThat(row, 'DISTRIBUTION_NOT_FOUND', 404);
      return row;
    });
  }
  /** Durable multi-worker dispatcher; ambiguous external results are quarantined for review. */
  async dispatchNotifications(
    sink: NotificationSink,
    limit = 20,
  ): Promise<{ delivered: number; failed: number }> {
    this.assertExternalIoAllowed();
    const result = await new PostgresNotificationWorker(this.store, {
      accountEnabled: (id) => this.isAccountActive(id),
    }).run(sink, limit);
    return { delivered: result.delivered, failed: result.failed };
  }
  async auditLog() {
    return this.atomic(async () => {
      return await this.db.all(
        'SELECT * FROM audit ORDER BY created_at DESC,id DESC LIMIT 100',
      );
    });
  }
  async auditPage(input: unknown = {}) {
    input = pageQuery.parse(input);
    return this.atomic(async () => {
      return await this.pageRows<{
        id: string;
        actor: string;
        action: string;
        target: string;
        details: string;
        created_at: number;
      }>('audit', undefined, input);
    });
  }
  async cleanupExpired(): Promise<void> {
    return this.atomic(async () => {
      await this.expireOrders();
      await this.inTransaction(async () => {
        await this.db.run(
          'DELETE FROM sessions WHERE expires_at<=?',
          this.now(),
        );
        await this.db.run(
          'DELETE FROM challenges WHERE expires_at<=?',
          this.now(),
        );
        await this.db.run(
          'DELETE FROM invitations WHERE expires_at<=?',
          this.now(),
        );
      });
    });
  }
}
