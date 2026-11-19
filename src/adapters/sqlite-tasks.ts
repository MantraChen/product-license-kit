import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { SqliteStore } from './sqlite.js';
import { sha256 } from '../core/crypto.js';
import { requireThat } from '../core/model.js';
import type {
  Task,
  TaskLease,
  TaskResolution,
  EnqueueTask,
} from './postgres-tasks.js';

const clock = "CAST(unixepoch('subsec')*1000 AS INTEGER)";
interface Row {
  id: string;
  task_key: string;
  payload: string;
  input_hash: string;
  state: Task['state'];
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
const uuid = z.string().uuid(),
  key = z.string().min(1).max(200),
  code = z.string().regex(/^[A-Z][A-Z0-9_]{2,79}$/);
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
/** Same fenced task lifecycle as PostgreSQL; all mutations compose with a synchronous SQLite transaction. */
export class SqliteTaskQueue {
  private readonly namespace: string;
  private readonly leaseMs: number;
  constructor(
    private readonly store: SqliteStore,
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
  enqueue(input: EnqueueTask) {
    const taskKey = key.parse(input.key),
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
    return this.store.transaction(() => {
      const prior = this.store.get<Row>(
        'SELECT * FROM task_jobs WHERE namespace=? AND task_key=?',
        this.namespace,
        taskKey,
      );
      if (prior) {
        requireThat(prior.input_hash === hash, 'TASK_KEY_CONFLICT', 409);
        return { ...task(prior), replayed: true };
      }
      const id = randomUUID();
      this.store.run(
        `INSERT INTO task_jobs(id,namespace,task_key,payload,input_hash,state,max_attempts,next_at,expires_at,created_at,updated_at)
        VALUES(?,?,?,?,?,'pending',?,${clock}+?,${clock}+?,${clock},${clock})`,
        id,
        this.namespace,
        taskKey,
        payload,
        hash,
        max,
        delay,
        ttl,
      );
      return {
        ...task(this.store.get<Row>('SELECT * FROM task_jobs WHERE id=?', id)!),
        replayed: false,
      };
    });
  }
  get(taskKey: string) {
    const row = this.store.get<Row>(
      'SELECT * FROM task_jobs WHERE namespace=? AND task_key=?',
      this.namespace,
      key.parse(taskKey),
    );
    return row ? task(row) : undefined;
  }
  list(input: { state?: Task['state']; limit?: number; cursor?: string } = {}) {
    const states = [
      'pending',
      'leased',
      'sending',
      'succeeded',
      'uncertain',
      'dead',
      'expired',
      'cancelled',
    ] as const;
    const query = z
      .object({
        state: z.enum(states).optional(),
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
    if (query.cursor)
      try {
        const value = z
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
          value.state === (query.state ?? null),
          'INVALID_TASK_CURSOR',
        );
        time = value.time;
        id = value.id;
      } catch {
        requireThat(false, 'INVALID_TASK_CURSOR');
      }
    const rows = this.store.all<Row>(
        `SELECT * FROM task_jobs WHERE namespace=? AND (? IS NULL OR state=?) AND (created_at<? OR (created_at=? AND id<?)) ORDER BY created_at DESC,id DESC LIMIT ?`,
        this.namespace,
        query.state ?? null,
        query.state ?? null,
        time,
        time,
        id,
        query.limit + 1,
      ),
      items = rows.slice(0, query.limit),
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
  sweep(limit = 100) {
    requireThat(
      Number.isInteger(limit) && limit >= 1 && limit <= 1000,
      'INVALID_TASK_LIMIT',
    );
    return this.store.transaction(() => {
      this.store.run(
        `UPDATE task_jobs SET state=CASE WHEN state='sending' THEN 'uncertain' WHEN expires_at<=${clock} THEN 'expired' ELSE 'dead' END,
        last_error=CASE WHEN state='sending' THEN 'EXTERNAL_RESULT_UNCERTAIN' WHEN expires_at<=${clock} THEN 'TASK_EXPIRED' ELSE 'ATTEMPTS_EXHAUSTED' END,
        lease_token=NULL,lease_until=NULL,updated_at=${clock} WHERE id IN (SELECT id FROM task_jobs WHERE namespace=? AND
          ((state='sending' AND (lease_until<=${clock} OR expires_at<=${clock})) OR
          (state IN ('pending','leased') AND (expires_at<=${clock} OR (attempts>=max_attempts AND (state='pending' OR lease_until<=${clock})))))
          ORDER BY created_at,id LIMIT ?)`,
        this.namespace,
        limit,
      );
      return this.store.get<{ n: number }>('SELECT changes() n')!.n;
    });
  }
  claim(): TaskLease | undefined {
    return this.store.transaction(() => {
      this.sweep();
      const row = this.store.get<Row>(
        `SELECT * FROM task_jobs WHERE namespace=? AND next_at<=${clock} AND expires_at>${clock} AND attempts<max_attempts
        AND (state='pending' OR (state='leased' AND lease_until<=${clock})) ORDER BY next_at,created_at,id LIMIT 1`,
        this.namespace,
      );
      if (!row) return undefined;
      const token = randomUUID();
      this.store.run(
        `UPDATE task_jobs SET state='leased',attempts=attempts+1,generation=generation+1,lease_token=?,lease_until=min(${clock}+?,expires_at),updated_at=${clock} WHERE id=?`,
        token,
        this.leaseMs,
        row.id,
      );
      const current = this.store.get<Row>(
        'SELECT * FROM task_jobs WHERE id=?',
        row.id,
      )!;
      return { ...task(current), token, leaseUntil: current.lease_until! };
    });
  }
  private owned(lease: TaskLease) {
    const row = this.store.get<Row>(
      `SELECT * FROM task_jobs WHERE id=? AND namespace=? AND lease_token=? AND generation=? AND state IN ('leased','sending') AND lease_until>${clock} AND expires_at>${clock}`,
      uuid.parse(lease.id),
      this.namespace,
      uuid.parse(lease.token),
      z.number().int().positive().safe().parse(lease.generation),
    );
    requireThat(row, 'TASK_LEASE_LOST', 409);
    return row;
  }
  assertOwned(lease: TaskLease) {
    return this.store.transaction(() => task(this.owned(lease)));
  }
  heartbeat(lease: TaskLease): TaskLease {
    return this.store.transaction(() => {
      this.owned(lease);
      this.store.run(
        `UPDATE task_jobs SET lease_until=min(${clock}+?,expires_at),updated_at=${clock} WHERE id=?`,
        this.leaseMs,
        lease.id,
      );
      const row = this.store.get<Row>(
        'SELECT * FROM task_jobs WHERE id=?',
        lease.id,
      )!;
      return {
        ...task(row),
        token: row.lease_token!,
        leaseUntil: row.lease_until!,
      };
    });
  }
  beginExternal(lease: TaskLease): TaskLease {
    return this.store.transaction(() => {
      requireThat(this.owned(lease).state === 'leased', 'TASK_LEASE_LOST', 409);
      this.store.run(
        `UPDATE task_jobs SET state='sending',updated_at=${clock} WHERE id=?`,
        lease.id,
      );
      const row = this.store.get<Row>(
        'SELECT * FROM task_jobs WHERE id=?',
        lease.id,
      )!;
      return {
        ...task(row),
        token: row.lease_token!,
        leaseUntil: row.lease_until!,
      };
    });
  }
  complete(lease: TaskLease, result: unknown = null) {
    const value = json(result);
    return this.store.transaction(() => {
      this.owned(lease);
      this.store.run(
        `UPDATE task_jobs SET state='succeeded',result=?,last_error=NULL,lease_token=NULL,lease_until=NULL,updated_at=${clock} WHERE id=?`,
        value,
        lease.id,
      );
      return task(
        this.store.get<Row>('SELECT * FROM task_jobs WHERE id=?', lease.id)!,
      );
    });
  }
  fail(
    lease: TaskLease,
    errorCode: string,
    options: { retryable?: boolean; definitelyNotSent?: true } = {},
  ) {
    code.parse(errorCode);
    return this.store.transaction(() => {
      const row = this.owned(lease),
        now = this.store.get<{ now: number }>(`SELECT ${clock} now`)!.now;
      const next =
        now + Math.min(3600000, 1000 * 2 ** Math.min(row.attempts - 1, 12));
      const state =
        row.state === 'sending' && !options.definitelyNotSent
          ? 'uncertain'
          : !options.retryable || row.attempts >= row.max_attempts
            ? 'dead'
            : next >= row.expires_at
              ? 'expired'
              : 'pending';
      this.store.run(
        'UPDATE task_jobs SET state=?,next_at=?,last_error=?,lease_token=NULL,lease_until=NULL,updated_at=? WHERE id=?',
        state,
        next,
        errorCode,
        now,
        row.id,
      );
      return task(
        this.store.get<Row>('SELECT * FROM task_jobs WHERE id=?', row.id)!,
      );
    });
  }
  resolve(taskKey: string, input: TaskResolution) {
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
    return this.store.transaction(() => {
      const row = this.store.get<Row>(
        `SELECT * FROM task_jobs WHERE namespace=? AND task_key=? AND generation=? AND state IN ('uncertain','dead') AND (?<>'retry' OR expires_at>${clock})`,
        this.namespace,
        key.parse(taskKey),
        value.generation,
        value.outcome,
      );
      requireThat(row, 'TASK_NOT_REVIEWABLE', 409);
      const now = this.store.get<{ now: number }>(`SELECT ${clock} now`)!.now;
      this.store.run(
        'UPDATE task_jobs SET state=?,attempts=?,next_at=?,result=?,resolution=?,last_error=NULL,updated_at=? WHERE id=?',
        value.outcome === 'retry' ? 'pending' : value.outcome,
        value.outcome === 'retry' ? 0 : row.attempts,
        now,
        result,
        value.reason,
        now,
        row.id,
      );
      this.store.run(
        'INSERT INTO task_job_reviews VALUES(?,?,?,?,?,?,?)',
        row.id,
        row.generation,
        value.actor,
        value.outcome,
        value.reason,
        sha256(result),
        now,
      );
      return task(
        this.store.get<Row>('SELECT * FROM task_jobs WHERE id=?', row.id)!,
      );
    });
  }
}
