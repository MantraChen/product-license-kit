import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { AsyncStore } from '../core/async-store.js';
import { requireThat } from '../core/model.js';
import { sha256 } from '../core/crypto.js';

const clock =
  '(floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint)';
const keySchema = z.string().min(1).max(200);
const codeSchema = z.string().regex(/^[A-Z][A-Z0-9_]{2,79}$/);
const uuid = z.string().uuid();
export const taskStates = [
  'pending',
  'leased',
  'sending',
  'succeeded',
  'uncertain',
  'dead',
  'expired',
  'cancelled',
] as const;
export type TaskState = (typeof taskStates)[number];
interface Row {
  id: string;
  namespace: string;
  task_key: string;
  payload: string;
  input_hash: string;
  state: TaskState;
  attempts: number;
  max_attempts: number;
  generation: number;
  lease_token: string | null;
  lease_until: number | null;
  next_at: number;
  expires_at: number;
  created_at: number;
  updated_at: number;
  last_error: string | null;
  result: string | null;
  resolution: string | null;
}
export interface Task {
  id: string;
  key: string;
  payload: unknown;
  state: TaskState;
  attempts: number;
  maxAttempts: number;
  generation: number;
  nextAt: number;
  expiresAt: number;
  createdAt: number;
  updatedAt: number;
  lastError: string | null;
  result: unknown;
  resolution: string | null;
}
export interface TaskLease extends Task {
  token: string;
  leaseUntil: number;
}
export interface EnqueueTask {
  key: string;
  payload: unknown;
  maxAttempts?: number;
  delayMs?: number;
  ttlMs?: number;
}
export interface TaskResolution {
  outcome: 'succeeded' | 'retry' | 'cancelled';
  reason: string;
  actor: string;
  generation: number;
  confirmedNotSent?: true;
  result?: unknown;
}
function json(value: unknown) {
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch {
    requireThat(false, 'INVALID_TASK_JSON');
  }
  requireThat(
    text !== undefined && Buffer.byteLength(text) <= 16384,
    'INVALID_TASK_JSON',
  );
  return text;
}
function task(row: Row): Task {
  return {
    id: row.id,
    key: row.task_key,
    payload: JSON.parse(row.payload),
    state: row.state,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    generation: row.generation,
    nextAt: row.next_at,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastError: row.last_error,
    result: row.result === null ? null : JSON.parse(row.result),
    resolution: row.resolution,
  };
}
export class PostgresTaskQueue {
  private readonly namespace: string;
  private readonly leaseMs: number;
  constructor(
    private readonly store: AsyncStore,
    options: { namespace: string; leaseMs?: number },
  ) {
    requireThat(
      /^[A-Za-z0-9._-]{1,80}$/.test(options.namespace),
      'INVALID_TASK_OPTIONS',
    );
    this.namespace = options.namespace;
    this.leaseMs = options.leaseMs ?? 90000;
    requireThat(
      Number.isInteger(this.leaseMs) &&
        this.leaseMs >= 100 &&
        this.leaseMs <= 900000,
      'INVALID_TASK_OPTIONS',
    );
  }
  private root() {
    requireThat(!this.store.transactionUnit, 'ROOT_STORE_REQUIRED');
  }
  private target(unit?: AsyncStore) {
    requireThat(
      !unit || unit.transactionUnit === true,
      'TRANSACTION_UNIT_REQUIRED',
    );
    return unit ?? this.store;
  }
  async enqueue(input: EnqueueTask) {
    const key = keySchema.parse(input.key),
      payload = json(input.payload),
      max = input.maxAttempts ?? 6,
      delay = input.delayMs ?? 0,
      ttl = input.ttlMs ?? 86400000;
    requireThat(
      Number.isInteger(max) &&
        max >= 1 &&
        max <= 100 &&
        Number.isSafeInteger(delay) &&
        delay >= 0 &&
        Number.isSafeInteger(ttl) &&
        ttl >= 1000 &&
        ttl <= 30 * 86400000 &&
        delay < ttl,
      'INVALID_TASK_OPTIONS',
    );
    const hash = sha256(JSON.stringify([payload, max, delay, ttl]));
    const inserted = await this.store.get<Row>(
      `WITH clock AS (SELECT ${clock} AS ms)
      INSERT INTO task_jobs(id,namespace,task_key,payload,input_hash,state,max_attempts,next_at,expires_at,created_at,updated_at)
      SELECT $1,$2,$3,$4,$5,'pending',$6,ms+$7,ms+$8,ms,ms FROM clock
      ON CONFLICT(namespace,task_key) DO NOTHING RETURNING *`,
      randomUUID(),
      this.namespace,
      key,
      payload,
      hash,
      max,
      delay,
      ttl,
    );
    const row =
      inserted ??
      (await this.store.get<Row>(
        'SELECT * FROM task_jobs WHERE namespace=$1 AND task_key=$2',
        this.namespace,
        key,
      ));
    requireThat(row && row.input_hash === hash, 'TASK_KEY_CONFLICT', 409);
    return { ...task(row), replayed: !inserted };
  }
  async get(key: string) {
    const row = await this.store.get<Row>(
      'SELECT * FROM task_jobs WHERE namespace=$1 AND task_key=$2',
      this.namespace,
      keySchema.parse(key),
    );
    return row ? task(row) : undefined;
  }
  async list(
    input: { state?: TaskState; limit?: number; cursor?: string } = {},
  ) {
    const query = z
      .object({
        state: z.enum(taskStates).optional(),
        limit: z.number().int().min(1).max(100).default(30),
        cursor: z
          .string()
          .min(1)
          .max(1024)
          .regex(/^[A-Za-z0-9_-]+$/)
          .optional(),
      })
      .strict()
      .parse(input);
    let time = 9007199254740991,
      id = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    if (query.cursor) {
      try {
        const cursor = z
          .object({
            namespace: z.literal(this.namespace),
            state: z.string().nullable(),
            time: z.number().int().nonnegative().safe(),
            id: uuid,
          })
          .strict()
          .parse(
            JSON.parse(Buffer.from(query.cursor, 'base64url').toString('utf8')),
          );
        requireThat(
          cursor.state === (query.state ?? null),
          'INVALID_TASK_CURSOR',
        );
        time = cursor.time;
        id = cursor.id;
      } catch {
        requireThat(false, 'INVALID_TASK_CURSOR');
      }
    }
    const rows = await this.store.all<Row>(
      `SELECT * FROM task_jobs WHERE namespace=$1 AND ($2::text IS NULL OR state=$2)
      AND (created_at<$3 OR (created_at=$3 AND id<$4)) ORDER BY created_at DESC,id DESC LIMIT $5`,
      this.namespace,
      query.state ?? null,
      time,
      id,
      query.limit + 1,
    );
    const items = rows.slice(0, query.limit),
      last = items.at(-1);
    return {
      items: items.map(task),
      nextCursor:
        rows.length > query.limit && last
          ? Buffer.from(
              JSON.stringify({
                namespace: this.namespace,
                state: query.state ?? null,
                time: last.created_at,
                id: last.id,
              }),
            ).toString('base64url')
          : null,
    };
  }
  async sweep(limit = 100) {
    this.root();
    requireThat(
      Number.isInteger(limit) && limit >= 1 && limit <= 1000,
      'INVALID_TASK_LIMIT',
    );
    return (
      await this.store.run(
        `WITH clock AS (SELECT ${clock} AS ms),stale AS (
      SELECT id FROM task_jobs,clock WHERE namespace=$1 AND
      ((state='sending' AND (lease_until<=ms OR expires_at<=ms)) OR
       (state IN ('pending','leased') AND (expires_at<=ms OR (attempts>=max_attempts AND (state='pending' OR lease_until<=ms)))))
      ORDER BY created_at,id LIMIT $2 FOR UPDATE OF task_jobs SKIP LOCKED)
      UPDATE task_jobs j SET state=CASE WHEN j.state='sending' THEN 'uncertain' WHEN j.expires_at<=ms THEN 'expired' ELSE 'dead' END,
      last_error=CASE WHEN j.state='sending' THEN 'EXTERNAL_RESULT_UNCERTAIN' WHEN j.expires_at<=ms THEN 'TASK_EXPIRED' ELSE 'ATTEMPTS_EXHAUSTED' END,
      lease_token=NULL,lease_until=NULL,updated_at=ms FROM stale,clock WHERE j.id=stale.id`,
        this.namespace,
        limit,
      )
    ).changes;
  }
  /** Optional bounded allowlist; task names remain SQL values. Empty keys never claims unrelated work. */
  async claim(
    input: { keys?: readonly string[] } = {},
  ): Promise<TaskLease | undefined> {
    this.root();
    const { keys } = z
      .object({ keys: z.array(keySchema).max(100).optional() })
      .strict()
      .parse(input);
    await this.sweep();
    const row = await this.store.get<Row>(
      `WITH clock AS (SELECT ${clock} AS ms),candidate AS (
      SELECT id FROM task_jobs,clock WHERE namespace=$1 AND next_at<=ms AND expires_at>ms AND attempts<max_attempts
      AND ($4::text IS NULL OR task_key IN (SELECT jsonb_array_elements_text($4::jsonb)))
      AND (state='pending' OR (state='leased' AND lease_until<=ms)) ORDER BY next_at,created_at,id
      LIMIT 1 FOR UPDATE OF task_jobs SKIP LOCKED)
      UPDATE task_jobs j SET state='leased',attempts=attempts+1,generation=generation+1,lease_token=$2,
      lease_until=least(ms+$3,expires_at),updated_at=ms FROM candidate,clock WHERE j.id=candidate.id RETURNING j.*`,
      this.namespace,
      randomUUID(),
      this.leaseMs,
      keys === undefined ? null : JSON.stringify([...new Set(keys)]),
    );
    return row
      ? { ...task(row), token: row.lease_token!, leaseUntil: row.lease_until! }
      : undefined;
  }
  /** Return an owned, still unstarted lease for routing handoff without charging a delivery attempt. Sending cannot be released. */
  async release(lease: TaskLease, unit?: AsyncStore) {
    this.root();
    const row = this.owned(
      await this.target(unit).get<Row>(
        `WITH clock AS (SELECT ${clock} AS ms)
       UPDATE task_jobs SET state='pending',attempts=attempts-1,next_at=ms,last_error=NULL,lease_token=NULL,lease_until=NULL,updated_at=ms
       FROM clock WHERE id=$1 AND lease_token=$2 AND generation=$3 AND namespace=$4 AND state='leased'
       AND lease_until>ms AND expires_at>ms RETURNING task_jobs.*`,
        ...this.fence(lease),
      ),
    );
    return task(row);
  }
  private fence(lease: TaskLease) {
    return [
      uuid.parse(lease.id),
      uuid.parse(lease.token),
      z.number().int().positive().safe().parse(lease.generation),
      this.namespace,
    ] as const;
  }
  private owned(row: Row | undefined) {
    requireThat(row, 'TASK_LEASE_LOST', 409);
    return row;
  }
  async heartbeat(lease: TaskLease) {
    this.root();
    const row = this.owned(
      await this.store.get<Row>(
        `WITH clock AS (SELECT ${clock} AS ms)
      UPDATE task_jobs SET lease_until=least(ms+$5,expires_at),updated_at=ms FROM clock
      WHERE id=$1 AND lease_token=$2 AND generation=$3 AND namespace=$4 AND state IN ('leased','sending')
      AND lease_until>ms AND expires_at>ms RETURNING task_jobs.*`,
        ...this.fence(lease),
        this.leaseMs,
      ),
    );
    return {
      ...task(row),
      token: row.lease_token!,
      leaseUntil: row.lease_until!,
    };
  }
  async beginExternal(lease: TaskLease, unit?: AsyncStore) {
    this.root();
    const row = this.owned(
      await this.target(unit).get<Row>(
        `WITH clock AS (SELECT ${clock} AS ms)
      UPDATE task_jobs SET state='sending',updated_at=ms FROM clock WHERE id=$1 AND lease_token=$2 AND generation=$3 AND namespace=$4
      AND state='leased' AND lease_until>ms AND expires_at>ms RETURNING task_jobs.*`,
        ...this.fence(lease),
      ),
    );
    return {
      ...task(row),
      token: row.lease_token!,
      leaseUntil: row.lease_until!,
    };
  }
  async complete(lease: TaskLease, result: unknown = null, unit?: AsyncStore) {
    this.root();
    const serialized = json(result);
    const row = this.owned(
      await this.target(unit).get<Row>(
        `WITH clock AS (SELECT ${clock} AS ms)
      UPDATE task_jobs SET state='succeeded',result=$5,last_error=NULL,lease_token=NULL,lease_until=NULL,updated_at=ms FROM clock
      WHERE id=$1 AND lease_token=$2 AND generation=$3 AND namespace=$4 AND state IN ('leased','sending')
      AND lease_until>ms AND expires_at>ms RETURNING task_jobs.*`,
        ...this.fence(lease),
        serialized,
      ),
    );
    return task(row);
  }
  async fail(
    lease: TaskLease,
    code: string,
    options: { retryable?: boolean; definitelyNotSent?: true } = {},
  ) {
    this.root();
    const error = codeSchema.parse(code),
      retry = options.retryable === true ? 1 : 0,
      safe = options.definitelyNotSent === true ? 1 : 0;
    const row = this.owned(
      await this.store.get<Row>(
        `WITH clock AS (SELECT ${clock} AS ms)
      UPDATE task_jobs SET state=CASE WHEN state='sending' AND $7=0 THEN 'uncertain'
        WHEN $6=0 OR attempts>=max_attempts THEN 'dead'
        WHEN ms+least(3600000,1000*power(2,least(attempts-1,12)))>=expires_at THEN 'expired' ELSE 'pending' END,
      next_at=ms+least(3600000,1000*power(2,least(attempts-1,12)))::bigint,
      last_error=$5,lease_token=NULL,lease_until=NULL,updated_at=ms FROM clock
      WHERE id=$1 AND lease_token=$2 AND generation=$3 AND namespace=$4 AND state IN ('leased','sending')
      AND lease_until>ms AND expires_at>ms RETURNING task_jobs.*`,
        ...this.fence(lease),
        error,
        retry,
        safe,
      ),
    );
    return task(row);
  }
  async resolve(key: string, input: TaskResolution, unit?: AsyncStore) {
    this.root();
    const value = z
        .object({
          outcome: z.enum(['succeeded', 'retry', 'cancelled']),
          reason: z.string().trim().min(3).max(500),
          actor: z.string().min(1).max(128),
          generation: z.number().int().positive().safe(),
          confirmedNotSent: z.literal(true).optional(),
          result: z.unknown().optional(),
        })
        .strict()
        .parse(input),
      result = json(value.result ?? null);
    requireThat(
      value.outcome !== 'retry' || value.confirmedNotSent === true,
      'TASK_RETRY_REQUIRES_CONFIRMED_NOT_SENT',
      409,
    );
    const taskKey = keySchema.parse(key);
    const apply = async (unit: AsyncStore) => {
      const row = await unit.get<Row>(
        `WITH clock AS (SELECT ${clock} AS ms)
        UPDATE task_jobs SET state=CASE WHEN $3='retry' THEN 'pending' ELSE $3 END,
        attempts=CASE WHEN $3='retry' THEN 0 ELSE attempts END,next_at=ms,result=$4,resolution=$5,last_error=NULL,updated_at=ms
        FROM clock WHERE namespace=$1 AND task_key=$2 AND generation=$6 AND state IN ('uncertain','dead') AND ($3<>'retry' OR expires_at>ms)
        RETURNING task_jobs.*`,
        this.namespace,
        taskKey,
        value.outcome,
        result,
        value.reason,
        value.generation,
      );
      requireThat(row, 'TASK_NOT_REVIEWABLE', 409);
      await unit.run(
        'INSERT INTO task_job_reviews VALUES($1,$2,$3,$4,$5,$6,$7)',
        row.id,
        row.generation,
        value.actor,
        value.outcome,
        value.reason,
        sha256(result),
        row.updated_at,
      );
      return task(row);
    };
    return unit ? apply(this.target(unit)) : this.store.transaction(apply);
  }
}
