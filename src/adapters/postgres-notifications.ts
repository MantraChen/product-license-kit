import { z } from 'zod';
import { StorageError, type AsyncStore } from '../core/async-store.js';
import {
  DomainError,
  NotificationNotSentError,
  notificationResourceSchema,
  requireThat,
  type Notification,
  type NotificationSink,
} from '../core/model.js';
import {
  PostgresTaskQueue,
  type TaskLease,
  type TaskResolution,
} from './postgres-tasks.js';

export const notificationQueueNamespace = 'plk.notifications';
interface EventRow {
  id: string;
  topic: string;
  account_id: string;
  created_at: number;
  delivered_at: number | null;
  provider: string;
  subject: string;
  resource_kind: string | null;
  resource_id: string | null;
  active: number | null;
}
export class PostgresNotificationWorker {
  readonly queue: PostgresTaskQueue;
  private readonly leaseMs: number;
  private readonly sendTimeoutMs: number;
  private readonly accountEnabled: (
    accountId: string,
  ) => boolean | Promise<boolean>;
  private readonly providers: readonly string[] | undefined;
  constructor(
    private readonly store: AsyncStore,
    options: {
      leaseMs?: number;
      sendTimeoutMs?: number;
      accountEnabled?: (accountId: string) => boolean | Promise<boolean>;
      /** Optional identity routes for independent platform consumers. Omit only when the sink routes every configured provider. */
      providers?: readonly string[];
    } = {},
  ) {
    requireThat(!store.transactionUnit, 'ROOT_STORE_REQUIRED');
    this.leaseMs = options.leaseMs ?? 90000;
    this.sendTimeoutMs = options.sendTimeoutMs ?? 8000;
    requireThat(
      Number.isInteger(this.sendTimeoutMs) &&
        this.sendTimeoutMs >= 100 &&
        this.sendTimeoutMs <= 60000,
      'INVALID_NOTIFICATION_OPTIONS',
    );
    this.queue = new PostgresTaskQueue(store, {
      namespace: notificationQueueNamespace,
      leaseMs: this.leaseMs,
    });
    this.accountEnabled = options.accountEnabled ?? (() => true);
    this.providers =
      options.providers === undefined
        ? undefined
        : [
            ...new Set(
              z
                .array(z.string().regex(/^[A-Za-z0-9._-]{1,80}$/))
                .min(1)
                .max(32)
                .parse(options.providers),
            ),
          ].sort();
  }
  private keepAlive(initial: TaskLease) {
    let stopped = false,
      lost = false,
      timer: ReturnType<typeof setTimeout> | undefined,
      pending: Promise<void> | undefined;
    const tick = () => {
      timer = setTimeout(
        () => {
          pending = this.queue
            .heartbeat(initial)
            .then(
              () => {},
              () => {
                lost = true;
              },
            )
            .finally(() => {
              if (!stopped && !lost) tick();
            });
        },
        Math.max(25, Math.floor(this.leaseMs / 3)),
      );
    };
    tick();
    return {
      lost: () => lost,
      stop: async () => {
        stopped = true;
        clearTimeout(timer);
        await pending;
      },
    };
  }
  private async write<T>(work: (unit: AsyncStore) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
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
  }
  /** Host must authenticate the operator and verify platform evidence before invoking. */
  async resolve(eventId: string, input: TaskResolution) {
    const id = z.string().uuid().parse(eventId),
      snapshot = structuredClone(input);
    return this.write(async (unit) => {
      requireThat(
        await unit.get('SELECT 1 FROM outbox WHERE id=$1', id),
        'NOTIFICATION_EVENT_MISSING',
        404,
      );
      const result = await this.queue.resolve(id, snapshot, unit);
      if (snapshot.outcome === 'succeeded')
        await unit.run(
          `UPDATE outbox SET delivered_at=floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint WHERE id=$1`,
          id,
        );
      return result;
    });
  }
  private async claim() {
    if (!this.providers) return this.queue.claim();
    const candidates = await this.store.all<{ task_key: string }>(
      `WITH clock AS (SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AS ms)
       SELECT j.task_key FROM task_jobs j JOIN outbox o ON o.id=j.task_key JOIN accounts a ON a.id=o.account_id,clock
       WHERE j.namespace=$1 AND a.provider IN (SELECT jsonb_array_elements_text($2::jsonb))
       AND j.next_at<=ms AND j.expires_at>ms AND j.attempts<j.max_attempts
       AND (j.state='pending' OR (j.state='leased' AND j.lease_until<=ms))
       ORDER BY j.next_at,j.created_at,j.id LIMIT 100`,
      notificationQueueNamespace,
      JSON.stringify(this.providers),
    );
    return this.queue.claim({ keys: candidates.map((row) => row.task_key) });
  }
  async run(sink: NotificationSink, limit = 20) {
    requireThat(
      Number.isInteger(limit) && limit >= 1 && limit <= 100,
      'INVALID_NOTIFICATION_LIMIT',
    );
    let delivered = 0,
      failed = 0,
      skipped = 0,
      uncertain = 0;
    for (let index = 0; index < limit; index++) {
      let lease = await this.claim();
      if (!lease) break;
      const keepAlive = this.keepAlive(lease);
      let calledSink = false;
      try {
        const { eventId } = z
          .object({ eventId: z.string().uuid() })
          .strict()
          .parse(lease.payload);
        requireThat(lease.key === eventId, 'INVALID_NOTIFICATION_TASK');
        const row = await this.store.get<EventRow>(
          `SELECT o.*,a.provider,a.subject,s.active,r.kind AS resource_kind,r.resource_id
          FROM outbox o JOIN accounts a ON a.id=o.account_id LEFT JOIN account_states s ON s.account_id=a.id
          LEFT JOIN outbox_resources r ON r.event_id=o.id WHERE o.id=$1`,
          eventId,
        );
        requireThat(row, 'NOTIFICATION_EVENT_MISSING', 404);
        if (this.providers && !this.providers.includes(row.provider)) {
          await keepAlive.stop();
          await this.queue.release(lease);
          skipped++;
          continue;
        }
        if (row.delivered_at !== null) {
          await keepAlive.stop();
          await this.queue.complete(lease, { alreadyDelivered: true });
          skipped++;
          continue;
        }
        requireThat(
          row.active !== 0 && (await this.accountEnabled(row.account_id)),
          'ACCOUNT_DISABLED',
          403,
        );
        const resource =
          row.resource_kind === null
            ? undefined
            : notificationResourceSchema.parse({
                kind: row.resource_kind,
                id: row.resource_id,
              });
        const event: Notification = {
          id: row.id,
          topic: row.topic,
          accountId: row.account_id,
          createdAt: row.created_at,
          ...(resource ? { resource } : {}),
        };
        requireThat(!keepAlive.lost(), 'TASK_LEASE_LOST', 409);
        const currentLease = lease;
        const sending = await this.write(async (unit) => {
          const identity = await unit.get<{
            provider: string;
            subject: string;
            active: number | null;
          }>(
            'SELECT a.provider,a.subject,s.active FROM accounts a LEFT JOIN account_states s ON s.account_id=a.id WHERE a.id=$1',
            row.account_id,
          );
          requireThat(identity, 'NOTIFICATION_EVENT_MISSING', 404);
          if (
            identity.provider !== row.provider ||
            identity.subject !== row.subject ||
            (this.providers && !this.providers.includes(identity.provider))
          ) {
            await this.queue.release(currentLease, unit);
            return undefined;
          }
          requireThat(identity.active !== 0, 'ACCOUNT_DISABLED', 403);
          const sending = await this.queue.beginExternal(currentLease, unit);
          await unit.run(
            'UPDATE outbox SET attempts=attempts+1 WHERE id=$1',
            eventId,
          );
          return sending;
        });
        if (!sending) {
          await keepAlive.stop();
          skipped++;
          continue;
        }
        lease = sending;
        requireThat(!keepAlive.lost(), 'TASK_LEASE_LOST', 409);
        calledSink = true;
        let timeout: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            sink.send(event, { provider: row.provider, subject: row.subject }),
            new Promise<never>((_resolve, reject) => {
              timeout = setTimeout(
                () => reject(new Error('NOTIFICATION_TIMEOUT')),
                this.sendTimeoutMs,
              );
            }),
          ]);
        } finally {
          clearTimeout(timeout);
        }
        await keepAlive.stop();
        requireThat(!keepAlive.lost(), 'TASK_LEASE_LOST', 409);
        const completedLease = lease;
        await this.write(async (unit) => {
          await this.queue.complete(completedLease, { accepted: true }, unit);
          await unit.run(
            `UPDATE outbox SET delivered_at=floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint WHERE id=$1`,
            eventId,
          );
        });
        delivered++;
      } catch (error) {
        await keepAlive.stop();
        failed++;
        const notSent =
          !calledSink || error instanceof NotificationNotSentError;
        const retryable =
          error instanceof NotificationNotSentError ||
          (!calledSink &&
            !(error instanceof DomainError || error instanceof z.ZodError));
        const code =
          error instanceof NotificationNotSentError
            ? error.code
            : error instanceof DomainError &&
                /^[A-Z][A-Z0-9_]{2,79}$/.test(error.code)
              ? error.code
              : calledSink
                ? 'EXTERNAL_RESULT_UNCERTAIN'
                : 'NOTIFICATION_PREPARATION_FAILED';
        try {
          const result = await this.queue.fail(lease, code, {
            retryable,
            ...(notSent ? { definitelyNotSent: true as const } : {}),
          });
          if (result.state === 'uncertain') uncertain++;
        } catch {
          if (calledSink)
            uncertain++; /* Expired or unavailable leases are quarantined by sweep; never resend here. */
        }
      } finally {
        await keepAlive.stop();
      }
    }
    return { delivered, failed, skipped, uncertain };
  }
}
