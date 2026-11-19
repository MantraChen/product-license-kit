import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { z } from 'zod';
import { AsyncFramework } from '../async-service.js';
import { StorageError, type AsyncStore } from '../core/async-store.js';
import { requireThat, type VerifiedIdentity } from '../core/model.js';
import { randomToken, secretEqual, sha256 } from '../core/crypto.js';
import { newTotpSecret, verifyTotp } from '../security/totp.js';
import { PostgresRateLimiter } from './postgres-rate-limit.js';

export const portalPermissions = [
  'accounts.read',
  'accounts.write',
  'entitlements.write',
  'credits.write',
  'invitations.write',
  'payments.confirm',
  'audit.read',
  'operators.write',
] as const;
export type PortalPermission = (typeof portalPermissions)[number];
const permissionList = z
  .array(z.enum(portalPermissions))
  .max(portalPermissions.length)
  .transform((items) => [...new Set(items)].sort());
const reasonSchema = z.string().trim().min(3).max(500),
  uuid = z.string().uuid();
const short = 5 * 60000,
  userLifetime = 12 * 3600000,
  rememberLifetime = 30 * 86400000,
  staffLifetime = 2 * 3600000,
  staffIdle = 30 * 60000;
type Session = {
  hash: string;
  namespace: string;
  account_id: string;
  provider: string;
  subject: string;
  csrf: string;
  stage: 'setup' | 'mfa' | 'active';
  core_hash: string | null;
  core_token: string | null;
  setup_secret: string | null;
  remember: number;
  created_at: number;
  expires_at: number;
  mfa_at: number | null;
  last_seen: number;
};
type Operator = {
  permissions: string;
  enabled: number;
  revision: number;
  updated_at: number;
};
export interface PortalOAuthAdapter {
  authorizationUrl(state: string): string;
  verify(code: string): Promise<VerifiedIdentity>;
}
export interface PostgresPortalOptions {
  namespace: string;
  origin: string;
  /** A separate, stable, private 32-byte key. Required again after database restoration. */
  encryptionKey: Uint8Array;
  provider: string;
  authorizationOrigin: string;
  oauth: PortalOAuthAdapter;
  /** Explicit opt-in. Recheck current guild/role admission after OAuth; called outside the database transaction. */
  registrationAdmission?: (identity: VerifiedIdentity) => Promise<boolean>;
}
/** Browser BFF state over the same PostgreSQL transaction boundary as AsyncFramework. Never exports core bearer tokens. */
export class PostgresPortal {
  readonly namespace: string;
  readonly origin: string;
  readonly secureCookies: boolean;
  readonly rateLimiter: PostgresRateLimiter;
  private readonly key: Buffer;
  private readonly provider: string;
  private readonly oauth: PortalOAuthAdapter;
  private readonly authorizationOrigin: string;
  private readonly contextHash: string;
  private readonly registrationAdmission:
    ((identity: VerifiedIdentity) => Promise<boolean>) | undefined;
  private constructor(
    readonly framework: AsyncFramework,
    private readonly store: AsyncStore,
    options: PostgresPortalOptions,
  ) {
    requireThat(
      !store.transactionUnit && framework.store === store,
      'PORTAL_STORE_MISMATCH',
    );
    this.namespace = z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,80}$/)
      .parse(options.namespace);
    this.provider = z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,80}$/)
      .parse(options.provider);
    const origin = new URL(options.origin),
      authOrigin = new URL(options.authorizationOrigin);
    for (const url of [origin, authOrigin])
      requireThat(
        !url.username &&
          !url.password &&
          !url.search &&
          !url.hash &&
          url.pathname === '/' &&
          (url.protocol === 'https:' ||
            (url.protocol === 'http:' &&
              ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))),
        'PORTAL_ORIGIN_INVALID',
      );
    this.origin = origin.origin;
    this.authorizationOrigin = authOrigin.origin;
    this.secureCookies = origin.protocol === 'https:';
    requireThat(
      options.encryptionKey.byteLength === 32,
      'PORTAL_ENCRYPTION_KEY_INVALID',
    );
    this.key = Buffer.from(options.encryptionKey);
    this.oauth = {
      authorizationUrl: options.oauth.authorizationUrl.bind(options.oauth),
      verify: options.oauth.verify.bind(options.oauth),
    };
    this.registrationAdmission = options.registrationAdmission;
    this.contextHash = sha256(
      JSON.stringify([
        this.namespace,
        this.origin,
        this.provider,
        this.authorizationOrigin,
        framework.issuer,
        sha256(this.key),
      ]),
    );
    this.rateLimiter = new PostgresRateLimiter(store, {
      namespace: 'portal-' + sha256(this.namespace).slice(0, 24),
      secret: createHmac('sha256', this.key)
        .update('portal-rate:' + this.namespace)
        .digest('hex'),
    });
  }
  /** Host adapter subkey; callers must protect this key like the portal configuration. Never exposed by the BFF. */
  deriveAdapterKey(namespace: string) {
    z.string()
      .regex(/^[A-Za-z0-9._-]{1,80}$/)
      .parse(namespace);
    return createHmac('sha256', this.key)
      .update('plk-bot-v1:' + this.namespace + ':' + namespace)
      .digest();
  }
  get identityProvider() {
    return this.provider;
  }
  static async create(
    framework: AsyncFramework,
    store: AsyncStore,
    options: PostgresPortalOptions,
  ) {
    const portal = new PostgresPortal(framework, store, options);
    await store.run(
      'INSERT INTO portal_settings VALUES($1,$2,$3) ON CONFLICT(namespace) DO NOTHING',
      portal.namespace,
      portal.contextHash,
      sha256(portal.key),
    );
    await portal.tx(async () => {});
    return portal;
  }
  private seal(value: string, purpose: string) {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(this.namespace + ':' + purpose));
    const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return Buffer.concat([
      Buffer.from([1]),
      iv,
      cipher.getAuthTag(),
      data,
    ]).toString('base64url');
  }
  private open(value: string, purpose: string) {
    try {
      requireThat(
        value.length <= 32768 && /^[A-Za-z0-9_-]+$/.test(value),
        'PORTAL_SECRET_INVALID',
        503,
      );
      const data = Buffer.from(value, 'base64url');
      requireThat(
        data.length > 29 &&
          data[0] === 1 &&
          data.toString('base64url') === value,
        'PORTAL_SECRET_INVALID',
        503,
      );
      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.key,
        data.subarray(1, 13),
      );
      decipher.setAAD(Buffer.from(this.namespace + ':' + purpose));
      decipher.setAuthTag(data.subarray(13, 29));
      return Buffer.concat([
        decipher.update(data.subarray(29)),
        decipher.final(),
      ]).toString('utf8');
    } catch {
      requireThat(false, 'PORTAL_SECRET_INVALID', 503);
    }
  }
  private async tx<T>(
    work: (
      unit: AsyncStore,
      framework: AsyncFramework,
      now: number,
    ) => Promise<T>,
  ): Promise<T> {
    for (let attempt = 0; ; attempt++)
      try {
        return await this.store.transaction(async (unit) => {
          const settings = await unit.get<{
            context_hash: string;
            key_hash: string;
          }>(
            'SELECT context_hash,key_hash FROM portal_settings WHERE namespace=$1 FOR SHARE',
            this.namespace,
          );
          requireThat(
            settings?.context_hash === this.contextHash &&
              settings.key_hash === sha256(this.key),
            'PORTAL_CONTEXT_CHANGED',
            503,
          );
          const now = (await unit.get<{ now: number }>(
            'SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AS now',
          ))!.now;
          return work(unit, this.framework.using(unit), now);
        });
      } catch (error) {
        if (
          attempt >= 2 ||
          !(error instanceof StorageError) ||
          !error.retryable
        )
          throw error;
      }
  }
  private async audit(
    unit: AsyncStore,
    actor: string,
    action: string,
    target: string,
    details: object,
    now: number,
  ) {
    await unit.run(
      'INSERT INTO audit VALUES($1,$2,$3,$4,$5,$6)',
      randomUUID(),
      actor,
      'portal.' + action,
      target,
      JSON.stringify({ ...details, namespace: this.namespace }),
      now,
    );
  }
  private permissions(row: Operator | undefined) {
    return row?.enabled === 1
      ? permissionList.parse(JSON.parse(row.permissions))
      : [];
  }
  private token(value: string) {
    requireThat(/^[A-Za-z0-9_-]{43}$/.test(value), 'PORTAL_AUTH_REQUIRED', 401);
    return sha256(value);
  }
  private async session(
    unit: AsyncStore,
    framework: AsyncFramework,
    now: number,
    token: string,
    csrf?: string,
    active = true,
    fresh = false,
    permission?: PortalPermission,
  ) {
    const row = await unit.get<Session>(
      'SELECT * FROM portal_sessions WHERE hash=$1 AND namespace=$2 FOR UPDATE',
      this.token(token),
      this.namespace,
    );
    requireThat(row && row.expires_at > now, 'PORTAL_AUTH_REQUIRED', 401);
    if (csrf !== undefined)
      requireThat(secretEqual(row.csrf, csrf), 'CSRF_REJECTED', 403);
    const identity = await unit.get<{ provider: string; subject: string }>(
      'SELECT provider,subject FROM accounts WHERE id=$1',
      row.account_id,
    );
    requireThat(
      identity &&
        identity.provider === row.provider &&
        identity.subject === row.subject,
      'PORTAL_AUTH_REQUIRED',
      401,
    );
    await framework.assertAccountActive(row.account_id);
    requireThat(
      row.core_token &&
        row.core_hash &&
        (await framework.authenticate(
          this.open(row.core_token, 'session:' + row.hash),
        )) === row.account_id,
      'PORTAL_AUTH_REQUIRED',
      401,
    );
    const operator = await unit.get<Operator>(
        'SELECT * FROM portal_operators WHERE namespace=$1 AND account_id=$2',
        this.namespace,
        row.account_id,
      ),
      permissions = this.permissions(operator);
    if (row.stage === 'active' && permissions.length)
      requireThat(
        row.created_at + staffLifetime > now && row.last_seen + staffIdle > now,
        'PORTAL_AUTH_REQUIRED',
        401,
      );
    if (active) {
      requireThat(
        row.stage === 'active' && row.core_token && row.core_hash,
        'PORTAL_MFA_REQUIRED',
        401,
      );
      requireThat(
        (await framework.authenticate(
          this.open(row.core_token, 'session:' + row.hash),
        )) === row.account_id,
        'PORTAL_AUTH_REQUIRED',
        401,
      );
      if (fresh)
        requireThat(
          row.mfa_at !== null && row.mfa_at + short > now,
          'MFA_REAUTH_REQUIRED',
          403,
        );
      if (permission)
        requireThat(
          row.mfa_at !== null &&
            (!operator?.enabled || row.mfa_at >= operator.updated_at),
          'MFA_REAUTH_REQUIRED',
          403,
        );
      if (permission)
        requireThat(
          permissions.includes(permission),
          'PORTAL_PERMISSION_DENIED',
          403,
        );
    }
    await unit.run(
      'UPDATE portal_sessions SET last_seen=$2 WHERE hash=$1',
      row.hash,
      now,
    );
    return { row, permissions, operator };
  }
  async beginOAuth(remember: boolean, registration?: string) {
    requireThat(typeof remember === 'boolean', 'INVALID_REQUEST');
    if (registration !== undefined) {
      this.token(registration);
      requireThat(
        this.registrationAdmission,
        'PORTAL_REGISTRATION_DISABLED',
        403,
      );
    }
    const state = randomToken(),
      browser = randomToken(),
      destination = new URL(this.oauth.authorizationUrl(state));
    requireThat(
      destination.origin === this.authorizationOrigin &&
        !destination.username &&
        !destination.password &&
        !destination.hash,
      'PORTAL_AUTHORIZATION_URL_INVALID',
      503,
    );
    await this.tx(async (unit, _framework, now) => {
      await unit.run(
        'DELETE FROM portal_oauth_states WHERE namespace=$1 AND expires_at<=$2',
        this.namespace,
        now,
      );
      await unit.run(
        'INSERT INTO portal_oauth_states VALUES($1,$2,$3,$4,$5)',
        sha256(state),
        this.namespace,
        sha256(browser),
        remember ? 1 : 0,
        now + short,
      );
      if (registration !== undefined) {
        await this.registrationGrant(unit, sha256(registration), now);
        await unit.run(
          'INSERT INTO portal_registration_states VALUES($1,$2)',
          sha256(state),
          sha256(registration),
        );
      }
    });
    return { browser, authorizationUrl: destination.href };
  }
  private async registrationGrant(unit: AsyncStore, hash: string, now: number) {
    const grant = await unit.get<{
      hash: string;
      provider: string;
      subject: string;
      namespace: string;
      expires_at: number;
      used_at: number | null;
      revoked_at: number | null;
      epoch: number;
      active_epoch: number;
      paused: number;
    }>(
      `SELECT h.*,s.epoch AS active_epoch,s.paused FROM bot_handoffs h JOIN bot_settings s ON s.namespace=h.namespace
       WHERE h.hash=$1 AND h.portal_namespace=$2 FOR UPDATE OF h`,
      hash,
      this.namespace,
    );
    requireThat(
      grant &&
        grant.provider === this.provider &&
        grant.expires_at > now &&
        grant.used_at === null &&
        grant.revoked_at === null &&
        grant.epoch === grant.active_epoch &&
        grant.paused === 0,
      'REGISTRATION_GRANT_INVALID',
      401,
    );
    return grant;
  }
  async completeOAuth(state: string, browser: string, code: string) {
    this.token(state);
    this.token(browser);
    z.string().min(1).max(4096).parse(code);
    // Consume state in its own committed transaction before any platform I/O. A lost acknowledgement never replays code exchange.
    const claimed = await this.tx(async (unit, _framework, now) => {
      const row = await unit.get<{
        browser_hash: string;
        remember: number;
        expires_at: number;
      }>(
        'SELECT * FROM portal_oauth_states WHERE hash=$1 AND namespace=$2 FOR UPDATE',
        sha256(state),
        this.namespace,
      );
      requireThat(
        row &&
          row.expires_at > now &&
          secretEqual(row.browser_hash, sha256(browser)),
        'OAUTH_STATE_INVALID',
        401,
      );
      const registration = await unit.get<{ handoff_hash: string }>(
        'SELECT handoff_hash FROM portal_registration_states WHERE state_hash=$1',
        sha256(state),
      );
      await unit.run(
        'DELETE FROM portal_oauth_states WHERE hash=$1',
        sha256(state),
      );
      return { ...row, registration: registration?.handoff_hash };
    });
    const identity = z
      .object({
        provider: z.literal(this.provider),
        subject: z.string().min(1).max(128),
      })
      .strict()
      .parse(await this.oauth.verify(code));
    if (claimed.registration)
      requireThat(
        this.registrationAdmission &&
          (await this.registrationAdmission(identity)),
        'REGISTRATION_ADMISSION_DENIED',
        403,
      );
    const token = randomToken(),
      hash = sha256(token);
    await this.tx(async (unit, framework, now) => {
      let account = await unit.get<{ id: string }>(
        'SELECT id FROM accounts WHERE provider=$1 AND subject=$2',
        identity.provider,
        identity.subject,
      );
      if (claimed.registration) {
        const grant = await this.registrationGrant(
          unit,
          claimed.registration,
          now,
        );
        requireThat(
          grant.provider === identity.provider &&
            grant.subject === identity.subject,
          'REGISTRATION_IDENTITY_MISMATCH',
          403,
        );
        requireThat(!account, 'IDENTITY_ALREADY_REGISTERED', 409);
        account = {
          id: (
            await framework.registerVerifiedIdentity(identity, {
              source: 'kook-bot',
              reference: grant.hash,
              reason: 'Identity-bound one-use OAuth registration',
            })
          ).accountId,
        };
        await unit.run(
          'UPDATE bot_handoffs SET used_at=$2,account_id=$3 WHERE hash=$1',
          grant.hash,
          now,
          account.id,
        );
      }
      requireThat(account, 'IDENTITY_NOT_REGISTERED', 401);
      await framework.assertAccountActive(account.id);
      const mfa = await unit.get(
          'SELECT 1 FROM portal_mfa WHERE namespace=$1 AND account_id=$2',
          this.namespace,
          account.id,
        ),
        coreToken = randomToken();
      await unit.run(
        'INSERT INTO sessions VALUES($1,$2,$3)',
        sha256(coreToken),
        account.id,
        now + short,
      );
      await unit.run(
        'INSERT INTO portal_sessions VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULL,$12)',
        hash,
        this.namespace,
        account.id,
        identity.provider,
        identity.subject,
        randomToken(),
        mfa ? 'mfa' : 'setup',
        sha256(coreToken),
        this.seal(coreToken, 'session:' + hash),
        mfa ? null : this.seal(newTotpSecret(), 'setup:' + hash),
        claimed.remember,
        now,
        now + short,
      );
      await this.audit(
        unit,
        account.id,
        'oauth.verified',
        account.id,
        { provider: identity.provider, mfaRequired: true },
        now,
      );
    });
    return { token, maxAge: 300 };
  }
  async current(token: string) {
    return this.tx(async (unit, framework, now) => {
      const { row, permissions, operator } = await this.session(
        unit,
        framework,
        now,
        token,
        undefined,
        false,
      );
      const setup =
        row.stage === 'setup'
          ? this.open(row.setup_secret!, 'setup:' + row.hash)
          : undefined;
      return {
        stage: row.stage,
        csrf: row.csrf,
        expiresAt: Math.min(
          row.expires_at,
          permissions.length ? row.created_at + staffLifetime : row.expires_at,
        ),
        permissions,
        reauthRequired:
          row.mfa_at === null ||
          row.mfa_at + short <= now ||
          (!!operator?.enabled && row.mfa_at < operator.updated_at),
        ...(setup
          ? {
              setup: {
                secret: setup,
                uri:
                  'otpauth://totp/' +
                  encodeURIComponent(
                    this.framework.issuer + ':' + row.account_id,
                  ) +
                  '?' +
                  new URLSearchParams({
                    secret: setup,
                    issuer: this.framework.issuer,
                    algorithm: 'SHA1',
                    digits: '6',
                    period: '30',
                  }),
              },
            }
          : {}),
        ...(row.stage === 'active' ? { accountId: row.account_id } : {}),
      };
    });
  }
  private async checkCode(
    unit: AsyncStore,
    row: Session,
    code: string,
    now: number,
  ) {
    const mfa = await unit.get<{ secret: string; last_counter: number }>(
      'SELECT secret,last_counter FROM portal_mfa WHERE namespace=$1 AND account_id=$2 FOR UPDATE',
      this.namespace,
      row.account_id,
    );
    if (row.stage === 'setup') {
      requireThat(!mfa, 'PORTAL_ENROLLMENT_CHANGED', 409);
      const secret = this.open(row.setup_secret!, 'setup:' + row.hash),
        counter = verifyTotp(secret, code, now, -1);
      requireThat(counter !== null, 'MFA_CODE_INVALID', 401);
      await unit.run(
        'INSERT INTO portal_mfa VALUES($1,$2,$3,$4,$5)',
        this.namespace,
        row.account_id,
        this.seal(secret, 'mfa:' + row.account_id),
        counter,
        now,
      );
      return true;
    }
    requireThat(mfa, 'PORTAL_MFA_REQUIRED', 401);
    if (/^[A-Za-z0-9_-]{32}$/.test(code)) {
      const consumed = await unit.run(
        'DELETE FROM portal_recovery WHERE namespace=$1 AND account_id=$2 AND hash=$3',
        this.namespace,
        row.account_id,
        sha256(code),
      );
      requireThat(consumed.changes === 1, 'MFA_CODE_INVALID', 401);
      await this.audit(
        unit,
        row.account_id,
        'mfa.recovery-used',
        row.account_id,
        {},
        now,
      );
      return false;
    }
    const counter = verifyTotp(
      this.open(mfa.secret, 'mfa:' + row.account_id),
      code,
      now,
      mfa.last_counter,
    );
    requireThat(counter !== null, 'MFA_CODE_INVALID', 401);
    await unit.run(
      'UPDATE portal_mfa SET last_counter=$3 WHERE namespace=$1 AND account_id=$2',
      this.namespace,
      row.account_id,
      counter,
    );
    return false;
  }
  private async budget(token: string) {
    const row = await this.store.get<{ account_id: string }>(
      'SELECT account_id FROM portal_sessions WHERE hash=$1 AND namespace=$2 AND expires_at>floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint',
      this.token(token),
      this.namespace,
    );
    requireThat(row, 'PORTAL_AUTH_REQUIRED', 401);
    const rate = await this.rateLimiter.increment(
      row.account_id,
      short,
      10,
      'mfa-account',
    );
    requireThat(rate.current <= 10, 'MFA_RATE_LIMITED', 429);
  }
  async verifyMfa(token: string, csrf: string, code: string) {
    z.string().min(1).max(64).parse(code);
    await this.budget(token);
    return this.tx(async (unit, framework, now) => {
      const { row, permissions } = await this.session(
        unit,
        framework,
        now,
        token,
        csrf,
        false,
      );
      if (row.stage === 'active')
        await this.session(unit, framework, now, token);
      const enrolled = await this.checkCode(unit, row, code, now),
        newToken = randomToken(),
        hash = sha256(newToken);
      const expiry = permissions.length
        ? Math.min(row.created_at + staffLifetime, now + staffLifetime)
        : row.stage === 'active'
          ? row.expires_at
          : now + (row.remember ? rememberLifetime : userLifetime);
      requireThat(expiry > now, 'PORTAL_AUTH_REQUIRED', 401);
      const coreToken = randomToken();
      await unit.run(
        'INSERT INTO sessions VALUES($1,$2,$3)',
        sha256(coreToken),
        row.account_id,
        expiry,
      );
      await framework.authenticate(coreToken);
      const recoveryCodes: string[] = [];
      if (enrolled) {
        for (let i = 0; i < 10; i++) {
          const value = randomBytes(24).toString('base64url');
          recoveryCodes.push(value);
          await unit.run(
            'INSERT INTO portal_recovery VALUES($1,$2,$3)',
            this.namespace,
            row.account_id,
            sha256(value),
          );
        }
      }
      await unit.run(
        'DELETE FROM portal_reset_intents WHERE session_hash=$1',
        row.hash,
      );
      await unit.run(
        "UPDATE portal_sessions SET hash=$2,csrf=$3,stage='active',core_hash=$4,core_token=$5,setup_secret=NULL,expires_at=$6,mfa_at=$7,last_seen=$7 WHERE hash=$1",
        row.hash,
        hash,
        randomToken(),
        sha256(coreToken),
        this.seal(coreToken, 'session:' + hash),
        expiry,
        now,
      );
      if (row.core_hash)
        await unit.run('DELETE FROM sessions WHERE hash=$1', row.core_hash);
      await this.audit(
        unit,
        row.account_id,
        enrolled ? 'mfa.enrolled' : 'mfa.verified',
        row.account_id,
        { recoveryCodesIssued: enrolled ? 10 : 0 },
        now,
      );
      return {
        token: newToken,
        maxAge: Math.floor((expiry - now) / 1000),
        recoveryCodes,
      };
    });
  }
  async rotateRecoveryCodes(token: string, csrf: string, code: string) {
    z.string()
      .regex(/^\d{6}$/)
      .parse(code);
    await this.budget(token);
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(
        unit,
        framework,
        now,
        token,
        csrf,
        true,
      );
      await this.checkCode(unit, row, code, now);
      await unit.run(
        'DELETE FROM portal_recovery WHERE namespace=$1 AND account_id=$2',
        this.namespace,
        row.account_id,
      );
      const codes = Array.from({ length: 10 }, () =>
        randomBytes(24).toString('base64url'),
      );
      for (const code of codes)
        await unit.run(
          'INSERT INTO portal_recovery VALUES($1,$2,$3)',
          this.namespace,
          row.account_id,
          sha256(code),
        );
      await this.audit(
        unit,
        row.account_id,
        'mfa.recovery-rotated',
        row.account_id,
        {},
        now,
      );
      return { recoveryCodes: codes };
    });
  }
  async logout(token: string, csrf: string) {
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(
        unit,
        framework,
        now,
        token,
        csrf,
        false,
      );
      if (row.core_hash)
        await unit.run('DELETE FROM sessions WHERE hash=$1', row.core_hash);
      await unit.run('DELETE FROM portal_sessions WHERE hash=$1', row.hash);
      await this.audit(
        unit,
        row.account_id,
        'session.closed',
        row.account_id,
        {},
        now,
      );
      return { ok: true };
    });
  }
  async userData(
    token: string,
    kind: 'profile' | 'orders' | 'distributions',
    page: unknown = {},
  ): Promise<unknown> {
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(unit, framework, now, token);
      if (kind === 'profile')
        return {
          profile: await framework.profile(row.account_id),
          catalog: framework.catalog,
        };
      return kind === 'orders'
        ? framework.ordersPage(row.account_id, page)
        : framework.distributionsPage(row.account_id, page);
    });
  }
  async createOrder(token: string, csrf: string, input: unknown) {
    const parsed = z
      .object({
        offerId: z.string().min(1).max(80),
        commandKey: z.string().uuid(),
      })
      .strict()
      .parse(input);
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(unit, framework, now, token, csrf);
      return framework.createOrder(
        row.account_id,
        parsed.offerId,
        parsed.commandKey,
      );
    });
  }
  async resetPreview(token: string, csrf: string, groupId: string) {
    z.string().min(1).max(80).parse(groupId);
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(
          unit,
          framework,
          now,
          token,
          csrf,
          true,
          true,
        ),
        snapshot = await framework.deviceResetStatus(row.account_id, groupId);
      requireThat(snapshot.canReset, 'DEVICE_RESET_UNAVAILABLE', 409);
      const intent = randomToken();
      await unit.run(
        'DELETE FROM portal_reset_intents WHERE session_hash=$1 AND (expires_at<=$2 OR consumed_at IS NULL)',
        row.hash,
        now,
      );
      await unit.run(
        'INSERT INTO portal_reset_intents VALUES($1,$2,$3,$4,$5,$6,$7,NULL,NULL)',
        sha256(intent),
        this.namespace,
        row.hash,
        groupId,
        JSON.stringify(snapshot),
        randomToken(),
        now + short,
      );
      return { intent, ...snapshot, expiresAt: now + short };
    });
  }
  async resetConfirm(
    token: string,
    csrf: string,
    intent: string,
    confirmed: boolean,
  ) {
    requireThat(confirmed === true, 'DEVICE_RESET_CONFIRMATION_REQUIRED');
    this.token(intent);
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(
          unit,
          framework,
          now,
          token,
          csrf,
          true,
          true,
        ),
        plan = await unit.get<{
          snapshot: string;
          group_id: string;
          command_key: string;
          expires_at: number;
          consumed_at: number | null;
          result: string | null;
        }>(
          'SELECT * FROM portal_reset_intents WHERE hash=$1 AND namespace=$2 AND session_hash=$3 FOR UPDATE',
          sha256(intent),
          this.namespace,
          row.hash,
        );
      requireThat(plan && plan.expires_at > now, 'RESET_INTENT_INVALID', 409);
      if (plan.consumed_at !== null) return JSON.parse(plan.result!) as object;
      const state = await framework.deviceResetStatus(
        row.account_id,
        plan.group_id,
      );
      requireThat(
        JSON.stringify(state) === plan.snapshot &&
          state.generation !== null &&
          state.cost !== null,
        'DEVICE_RESET_PREVIEW_CHANGED',
        409,
      );
      const result = await framework.resetDevice(
        row.account_id,
        plan.group_id,
        state.generation,
        state.cost,
        plan.command_key,
      );
      await unit.run(
        'UPDATE portal_reset_intents SET consumed_at=$2,result=$3 WHERE hash=$1',
        sha256(intent),
        now,
        JSON.stringify(result),
      );
      await this.audit(
        unit,
        row.account_id,
        'device.reset-confirmed',
        row.account_id,
        {
          groupId: plan.group_id,
          cost: result.cost,
          generation: result.generation,
        },
        now,
      );
      return result;
    });
  }
  /** Explicit private deployment bootstrap only; never overwrites an existing operator roster. */
  async bootstrapOperator(
    accountId: string,
    permissions: readonly PortalPermission[],
    reason: string,
  ) {
    uuid.parse(accountId);
    const grants = permissionList.parse(permissions);
    reason = reasonSchema.parse(reason);
    requireThat(
      grants.includes('operators.write'),
      'PORTAL_INITIAL_OWNER_REQUIRED',
    );
    return this.tx(async (unit, framework, now) => {
      await unit.get(
        'SELECT namespace FROM portal_settings WHERE namespace=$1 FOR UPDATE',
        this.namespace,
      );
      await framework.assertAccountActive(accountId);
      const current = await unit.all<{
        account_id: string;
        permissions: string;
        enabled: number;
      }>('SELECT * FROM portal_operators WHERE namespace=$1', this.namespace);
      if (current.length) {
        requireThat(
          current.some(
            (row) =>
              row.account_id === accountId &&
              row.enabled === 1 &&
              JSON.stringify(
                this.permissions({ ...row, revision: 0, updated_at: 0 }),
              ) === JSON.stringify(grants),
          ),
          'PORTAL_OPERATOR_BOOTSTRAP_CLOSED',
          409,
        );
        return { created: false };
      }
      await unit.run(
        'INSERT INTO portal_operators VALUES($1,$2,$3,1,0,$4)',
        this.namespace,
        accountId,
        JSON.stringify(grants),
        now,
      );
      await this.audit(
        unit,
        'deployment',
        'operator.bootstrapped',
        accountId,
        { permissions: grants, reason },
        now,
      );
      return { created: true };
    });
  }
  async adminData(
    token: string,
    kind: 'operators' | 'audit' | 'account',
    input?: unknown,
  ): Promise<unknown> {
    return this.tx(async (unit, framework, now) => {
      await this.session(
        unit,
        framework,
        now,
        token,
        undefined,
        true,
        false,
        kind === 'operators'
          ? 'operators.write'
          : kind === 'audit'
            ? 'audit.read'
            : 'accounts.read',
      );
      if (kind === 'audit') return framework.auditPage(input ?? {});
      if (kind === 'account') return framework.profile(uuid.parse(input));
      return unit.all<{
        account_id: string;
        permissions: string;
        enabled: number;
        revision: number;
        updated_at: number;
      }>(
        'SELECT account_id,permissions,enabled,revision,updated_at FROM portal_operators WHERE namespace=$1 ORDER BY account_id LIMIT 100',
        this.namespace,
      );
    });
  }
  async adminWrite(
    token: string,
    csrf: string,
    action: string,
    input: unknown,
  ) {
    const base = z
      .object({ accountId: uuid.optional(), reason: reasonSchema })
      .passthrough()
      .parse(input);
    const permissions: Record<string, PortalPermission> = {
      'account-status': 'accounts.write',
      'revoke-entitlement': 'entitlements.write',
      'grant-credits': 'credits.write',
      operator: 'operators.write',
      invitation: 'invitations.write',
      payment: 'payments.confirm',
    };
    requireThat(permissions[action], 'INVALID_ADMIN_ACTION');
    // Snapshot and validate the complete request before yielding to storage.
    const schemas = {
      'account-status': z
        .object({ accountId: uuid, reason: reasonSchema, active: z.boolean() })
        .strict(),
      'revoke-entitlement': z
        .object({
          accountId: uuid,
          reason: reasonSchema,
          editionId: z.string().min(1).max(80),
        })
        .strict(),
      'grant-credits': z
        .object({
          accountId: uuid,
          reason: reasonSchema,
          groupId: z.string().min(1).max(80),
          count: z.number().int().min(1).max(100),
          commandKey: uuid,
        })
        .strict(),
      operator: z
        .object({
          accountId: uuid,
          reason: reasonSchema,
          permissions: permissionList,
          enabled: z.boolean(),
          revision: z.number().int().safe().nonnegative().nullable(),
        })
        .strict(),
      invitation: z
        .object({
          reason: reasonSchema,
          provider: z.string().min(1).max(80),
          subject: z.string().min(1).max(128),
        })
        .strict(),
      payment: z
        .object({
          accountId: uuid,
          reason: reasonSchema,
          orderId: uuid,
          method: z.string().min(1).max(80),
          reference: z.string().min(1).max(128),
          amount: z.number().int().safe().positive(),
          currency: z.string().length(3),
          confirmed: z.literal(true),
        })
        .strict(),
    };
    const parsed = schemas[action as keyof typeof schemas]!.parse(
      structuredClone(input),
    );
    return this.tx(async (unit, framework, now) => {
      const { row } = await this.session(
        unit,
        framework,
        now,
        token,
        csrf,
        true,
        true,
        permissions[action],
      );
      let result: unknown;
      if (action === 'operator') {
        const request = schemas.operator.parse(parsed);
        await unit.get(
          'SELECT namespace FROM portal_settings WHERE namespace=$1 FOR UPDATE',
          this.namespace,
        );
        await framework.assertAccountActive(request.accountId);
        const current = await unit.get<Operator>(
          'SELECT * FROM portal_operators WHERE namespace=$1 AND account_id=$2 FOR UPDATE',
          this.namespace,
          request.accountId,
        );
        requireThat(
          current
            ? current.revision === request.revision
            : request.revision === null,
          'PORTAL_OPERATOR_CHANGED',
          409,
        );
        if (
          !request.enabled ||
          !request.permissions.includes('operators.write')
        ) {
          const others = await unit.all<Operator & { account_id: string }>(
            'SELECT * FROM portal_operators WHERE namespace=$1 AND account_id<>$2 AND enabled=1',
            this.namespace,
            request.accountId,
          );
          let hasOwner = false;
          for (const item of others)
            if (
              this.permissions(item).includes('operators.write') &&
              (await framework.isAccountActive(item.account_id))
            ) {
              hasOwner = true;
              break;
            }
          requireThat(hasOwner, 'PORTAL_LAST_OWNER_REQUIRED', 409);
        }
        if (!current)
          requireThat(
            (await unit.get<{ n: number }>(
              'SELECT count(*)::int AS n FROM portal_operators WHERE namespace=$1',
              this.namespace,
            ))!.n < 100,
            'PORTAL_OPERATOR_LIMIT',
            409,
          );
        const revision = (current?.revision ?? -1) + 1;
        await unit.run(
          'INSERT INTO portal_operators VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(namespace,account_id) DO UPDATE SET permissions=$3,enabled=$4,revision=$5,updated_at=$6',
          this.namespace,
          request.accountId,
          JSON.stringify(request.permissions),
          request.enabled ? 1 : 0,
          revision,
          now,
        );
        result = { revision };
      } else if (action === 'account-status') {
        const request = schemas['account-status'].parse(parsed);
        requireThat(
          request.active || request.accountId !== row.account_id,
          'PORTAL_SELF_DISABLE_FORBIDDEN',
          409,
        );
        if (!request.active) {
          const operator = await unit.get<Operator>(
            'SELECT * FROM portal_operators WHERE namespace=$1 AND account_id=$2',
            this.namespace,
            request.accountId,
          );
          requireThat(
            !this.permissions(operator).includes('operators.write'),
            'PORTAL_OWNER_DISABLE_FORBIDDEN',
            409,
          );
        }
        await framework.setAccountActive(
          request.accountId,
          request.active,
          request.reason,
        );
        result = { ok: true };
      } else if (action === 'revoke-entitlement') {
        const request = schemas['revoke-entitlement'].parse(parsed);
        await framework.revokeEntitlement(
          request.accountId,
          request.editionId,
          request.reason,
        );
        result = { ok: true };
      } else if (action === 'grant-credits') {
        const request = schemas['grant-credits'].parse(parsed);
        result = await framework.grantCredits(
          request.accountId,
          request.groupId,
          request.count,
          request.reason,
          request.commandKey,
        );
      } else if (action === 'invitation') {
        const request = schemas.invitation.parse(parsed);
        result = await framework.issueInvitation(
          request.provider,
          request.subject,
        );
      } else {
        const request = schemas.payment.parse(parsed);
        const order = await unit.get<{ account_id: string }>(
          'SELECT account_id FROM orders WHERE id=$1',
          request.orderId,
        );
        requireThat(
          order?.account_id === request.accountId,
          'ORDER_NOT_FOUND',
          404,
        );
        result = await framework.confirmPayment(request.orderId, {
          method: request.method,
          reference: request.reference,
          amount: request.amount,
          currency: request.currency,
        });
      }
      await this.audit(
        unit,
        row.account_id,
        'admin.' + action,
        base.accountId ?? 'invitation',
        { reason: base.reason },
        now,
      );
      return result ?? { ok: true };
    });
  }
  async cleanup(limit = 1000) {
    requireThat(
      Number.isInteger(limit) && limit >= 1 && limit <= 10000,
      'INVALID_CLEANUP_LIMIT',
    );
    return this.tx(async (unit, _framework, now) => {
      const expired = await unit.all<{
        hash: string;
        core_hash: string | null;
      }>(
        'SELECT hash,core_hash FROM portal_sessions WHERE namespace=$1 AND expires_at<=$2 ORDER BY expires_at LIMIT $3 FOR UPDATE SKIP LOCKED',
        this.namespace,
        now,
        limit,
      );
      for (const row of expired) {
        if (row.core_hash)
          await unit.run('DELETE FROM sessions WHERE hash=$1', row.core_hash);
        await unit.run('DELETE FROM portal_sessions WHERE hash=$1', row.hash);
      }
      await unit.run(
        'DELETE FROM portal_oauth_states WHERE namespace=$1 AND expires_at<=$2',
        this.namespace,
        now,
      );
      await unit.run(
        'DELETE FROM portal_reset_intents WHERE namespace=$1 AND expires_at<=$2',
        this.namespace,
        now,
      );
      return { sessions: expired.length };
    });
  }
}
