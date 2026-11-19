import { createHmac } from 'node:crypto';
import type { FastifyRateLimitStore, FastifyRateLimitStoreCtor } from '@fastify/rate-limit';
import { type AsyncStore, StorageError } from '../core/async-store.js';
import { requireThat } from '../core/model.js';

const clock = '(floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint)';
export interface SharedRateLimitOptions {
  namespace: string;
  secret: string;
}
export class PostgresRateLimiter {
  private readonly namespace: string;
  private readonly secret: string;
  constructor(
    private readonly store: AsyncStore,
    options: SharedRateLimitOptions,
  ) {
    requireThat(!store.transactionUnit, 'ROOT_STORE_REQUIRED');
    requireThat(/^[A-Za-z0-9._-]{1,80}$/.test(options.namespace), 'INVALID_RATE_LIMIT_OPTIONS');
    requireThat(
      options.secret.length >= 32 && options.secret.length <= 256 && !options.secret.startsWith('replace-'),
      'INVALID_RATE_LIMIT_OPTIONS',
    );
    this.namespace = options.namespace;
    this.secret = options.secret;
  }
  private bucket(key: string, scope: string, windowMs: number, max: number) {
    requireThat(
      typeof key === 'string' &&
        key.length > 0 &&
        key.length <= 1024 &&
        scope.length <= 1024 &&
        Number.isSafeInteger(windowMs) &&
        windowMs >= 100 &&
        windowMs <= 86400000 &&
        Number.isSafeInteger(max) &&
        max >= 1 &&
        max <= 1000000,
      'INVALID_RATE_LIMIT_OPTIONS',
    );
    return createHmac('sha256', this.secret)
      .update(JSON.stringify([this.namespace, scope, key]))
      .digest('hex');
  }
  async increment(key: string, windowMs: number, max: number, scope = 'global') {
    const bucket = this.bucket(key, scope, windowMs, max);
    const result = await this.store.get<{ current: number; ttl: number }>(
      `WITH clock AS (SELECT ${clock} AS ms)
      INSERT INTO rate_limit_buckets AS b VALUES($1,$2::integer,$3::integer,1,(SELECT ms FROM clock)+$2::integer)
      ON CONFLICT(bucket_key) DO UPDATE SET
        current=CASE WHEN b.expires_at<=(SELECT ms FROM clock) THEN 1 ELSE least(b.current+1,$3::integer+1) END,
        expires_at=CASE WHEN b.expires_at<=(SELECT ms FROM clock) THEN (SELECT ms FROM clock)+$2::integer ELSE b.expires_at END
      WHERE b.window_ms=$2::integer AND b.max_requests=$3::integer
      RETURNING current,greatest(expires_at-(SELECT ms FROM clock),0) AS ttl`,
      bucket,
      windowMs,
      max,
    );
    if (!result) throw new StorageError('RATE_LIMIT_POLICY_MISMATCH');
    return result;
  }
  async read(key: string, windowMs: number, max: number, scope = 'global') {
    const result = await this.store.get<{
      current: number;
      ttl: number;
      window_ms: number;
      max_requests: number;
    }>(
      `SELECT current,greatest(expires_at-${clock},0) AS ttl,window_ms,max_requests FROM rate_limit_buckets WHERE bucket_key=$1`,
      this.bucket(key, scope, windowMs, max),
    );
    if (result && (result.window_ms !== windowMs || result.max_requests !== max))
      throw new StorageError('RATE_LIMIT_POLICY_MISMATCH');
    return result && result.ttl > 0 ? { current: result.current, ttl: result.ttl } : { current: 0, ttl: 0 };
  }
  async cleanup(limit = 1000) {
    requireThat(Number.isInteger(limit) && limit >= 1 && limit <= 10000, 'INVALID_CLEANUP_LIMIT');
    return (
      await this.store.run(
        `WITH expired AS (SELECT bucket_key FROM rate_limit_buckets WHERE expires_at<=${clock}
      ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)
      DELETE FROM rate_limit_buckets b USING expired e WHERE b.bucket_key=e.bucket_key AND b.expires_at<=${clock}`,
        limit,
      )
    ).changes;
  }
  /** Uses Fastify's trusted-proxy / IPv6 key policy; database keys contain HMAC digests only. */
  fastifyStore(): FastifyRateLimitStoreCtor {
    const owner = this;
    class SharedStore implements FastifyRateLimitStore {
      private scope = 'global';
      constructor(options: unknown = {}) {
        const value = options as { continueExceeding?: boolean; exponentialBackoff?: boolean };
        requireThat(
          !value.continueExceeding && !value.exponentialBackoff,
          'UNSUPPORTED_SHARED_RATE_LIMIT_POLICY',
        );
      }
      incr(
        key: string,
        callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
        windowMs: number,
        max: number,
      ) {
        void owner.increment(key, windowMs, max, this.scope).then(
          (result) => callback(null, result),
          (error) => callback(error),
        );
      }
      read(
        key: string,
        callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
        windowMs: number,
        max: number,
      ) {
        void owner.read(key, windowMs, max, this.scope).then(
          (result) => callback(null, result),
          (error) => callback(error),
        );
      }
      child(options: unknown) {
        // @fastify/rate-limit supplies merged parameters containing routeInfo.
        const value = options as {
          routeInfo?: { method?: string | string[]; url?: string; path?: string };
          continueExceeding?: boolean;
          exponentialBackoff?: boolean;
        };
        requireThat(
          !value.continueExceeding && !value.exponentialBackoff && value.routeInfo,
          'UNSUPPORTED_SHARED_RATE_LIMIT_POLICY',
        );
        const route = value.routeInfo,
          methods = Array.isArray(route.method) ? [...route.method].sort() : [route.method];
        const path = route.url ?? route.path;
        requireThat(
          path && methods.every((method) => typeof method === 'string'),
          'INVALID_SHARED_RATE_LIMIT_SCOPE',
        );
        const child = new SharedStore();
        child.scope = JSON.stringify([methods, path]);
        return child;
      }
    }
    return SharedStore;
  }
}
