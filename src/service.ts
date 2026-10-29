import { randomUUID } from 'node:crypto';
import { SqliteStore } from './adapters/sqlite.js';
import { addCalendarMonths, requireThat, rebindCost, type Catalog, type IdentityProvider,
  type NotificationSink, type Offer, type VerifiedIdentity } from './core/model.js';
import { EnvelopeSigner, normalizePublicKey, randomToken, sha256, verifyProof, type LicenseClaims } from './core/crypto.js';

interface Account { id: string; provider: string; subject: string; created_at: number }
interface Invitation { hash: string; provider: string; subject: string; expires_at: number; used_at: number | null }
interface Order {
  id: string; account_id: string; offer_json: string; status: string; created_at: number;
  paid_at: number | null; payment_method: string | null; payment_reference: string | null;
}
interface Binding {
  account_id: string; group_id: string; device_id: string; public_key: string; key_thumbprint: string;
  fingerprint_json: string; bound_at: number; free_at: number; generation: number; enabled: number;
}
interface Challenge {
  id: string; account_id: string; kind: string; payload: string; message: string; expires_at: number; used_at: number | null;
}
interface Distribution {
  id: string; account_id: string; edition_id: string; release_id: string;
  identity_snapshot: string; artifact_sha256: string | null; manifest: string | null;
  created_at: number; finalized_at: number | null;
}
export interface Fingerprint { schema: string; digest: string }
export interface FrameworkOptions {
  store: SqliteStore; catalog: Catalog; signer: EnvelopeSigner;
  providers: IdentityProvider[]; issuer: string; now?: () => number; licenseSeconds?: number;
}

export class Framework {
  readonly store: SqliteStore;
  readonly catalog: Catalog;
  readonly signer: EnvelopeSigner;
  readonly providers: Map<string, IdentityProvider>;
  readonly issuer: string;
  readonly now: () => number;
  readonly licenseSeconds: number;
  constructor(options: FrameworkOptions) {
    this.store = options.store; this.catalog = options.catalog; this.signer = options.signer;
    this.providers = new Map(options.providers.map(p => [p.name, p]));
    requireThat(this.providers.size === options.providers.length, 'DUPLICATE_IDENTITY_PROVIDER');
    this.issuer = options.issuer; this.now = options.now ?? Date.now;
    this.licenseSeconds = options.licenseSeconds ?? 900;
    requireThat(Number.isInteger(this.licenseSeconds) && this.licenseSeconds >= 30 && this.licenseSeconds <= 86400, 'INVALID_LEASE_DURATION');
    for (const row of this.store.all<{ edition_id: string }>('SELECT DISTINCT edition_id FROM entitlements')) {
      requireThat(this.catalog.editions.some(e => e.id === row.edition_id), 'CATALOG_REMOVES_EXISTING_ENTITLEMENT');
    }
    for (const row of this.store.all<{ group_id: string }>('SELECT DISTINCT group_id FROM bindings')) {
      requireThat(this.catalog.groups.some(g => g.id === row.group_id), 'CATALOG_REMOVES_EXISTING_DEVICE_GROUP');
    }
  }
  private audit(actor: string, action: string, target: string, details: object = {}): void {
    this.store.run('INSERT INTO audit VALUES (?,?,?,?,?,?)', randomUUID(), actor, action, target, JSON.stringify(details), this.now());
  }
  private event(topic: string, accountId: string): void {
    this.store.run('INSERT INTO outbox(id,topic,account_id,created_at) VALUES (?,?,?,?)', randomUUID(), topic, accountId, this.now());
  }
  private account(id: string): Account {
    const account = this.store.get<Account>('SELECT * FROM accounts WHERE id=?', id);
    requireThat(account, 'ACCOUNT_NOT_FOUND', 404); return account;
  }
  private owns(accountId: string, editionId: string): boolean {
    return !!this.store.get('SELECT 1 FROM entitlements WHERE account_id=? AND edition_id=? AND active=1', accountId, editionId);
  }
  private groupForEdition(editionId: string): { productId: string; groupId: string } {
    const edition = this.catalog.editions.find(e => e.id === editionId);
    requireThat(edition, 'EDITION_NOT_FOUND', 404);
    const product = this.catalog.products.find(p => p.id === edition.productId)!;
    return { productId: product.id, groupId: product.groupId };
  }
  private ownsGroup(accountId: string, groupId: string): boolean {
    return this.catalog.editions.some(e => this.groupForEdition(e.id).groupId === groupId && this.owns(accountId, e.id));
  }
  private credits(accountId: string, groupId: string): number {
    return this.store.get<{ balance: number }>('SELECT balance FROM credits WHERE account_id=? AND group_id=?', accountId, groupId)?.balance ?? 0;
  }
  private addCredits(accountId: string, groupId: string, count: number): void {
    this.store.run(`INSERT INTO credits VALUES (?,?,?) ON CONFLICT(account_id,group_id)
      DO UPDATE SET balance=balance+excluded.balance`, accountId, groupId, count);
  }
  /** Stored within the same write transaction as all effects; keys are account + operation scoped. */
  private command<T>(accountId: string, operation: string, key: string, input: unknown, work: () => T): T {
    requireThat(/^[A-Za-z0-9_-]{16,128}$/.test(key), 'INVALID_IDEMPOTENCY_KEY');
    return this.store.transaction(() => {
      const hash = sha256(JSON.stringify(input));
      const prior = this.store.get<{ request_hash: string; result_json: string }>(
        'SELECT * FROM commands WHERE account_id=? AND operation=? AND command_key=?', accountId, operation, key);
      if (prior) {
        requireThat(prior.request_hash === hash, 'IDEMPOTENCY_CONFLICT', 409);
        return JSON.parse(prior.result_json) as T;
      }
      const result = work();
      this.store.run('INSERT INTO commands VALUES (?,?,?,?,?)', accountId, operation, key, hash, JSON.stringify(result));
      return result;
    });
  }
  issueInvitation(provider: string, subject: string): { ticket: string; expiresAt: number } {
    requireThat(this.providers.has(provider), 'IDENTITY_PROVIDER_DISABLED');
    requireThat(!this.store.get('SELECT 1 FROM accounts WHERE provider=? AND subject=?', provider, subject), 'IDENTITY_ALREADY_REGISTERED', 409);
    const ticket = randomToken(); const expiresAt = this.now() + 30 * 60_000;
    this.store.transaction(() => {
      this.store.run('UPDATE invitations SET used_at=? WHERE provider=? AND subject=? AND used_at IS NULL', this.now(), provider, subject);
      this.store.run('INSERT INTO invitations VALUES (?,?,?,?,NULL)', sha256(ticket), provider, subject, expiresAt);
      this.audit('admin', 'invitation.issued', `${provider}:${subject}`);
    });
    return { ticket, expiresAt };
  }
  private async verifyIdentity(provider: string, proof: string): Promise<VerifiedIdentity> {
    const adapter = this.providers.get(provider);
    requireThat(adapter, 'IDENTITY_PROVIDER_DISABLED', 401);
    const identity = await adapter.verify(proof);
    requireThat(identity.provider === provider && identity.subject.length > 0 && identity.subject.length <= 128, 'INVALID_IDENTITY', 401);
    return identity;
  }
  private session(accountId: string): { accessToken: string; expiresAt: number; accountId: string } {
    const accessToken = randomToken(); const expiresAt = this.now() + 12 * 60 * 60_000;
    this.store.run('INSERT INTO sessions VALUES (?,?,?)', sha256(accessToken), accountId, expiresAt);
    return { accessToken, expiresAt, accountId };
  }
  async register(ticket: string, proof: string) {
    const invitation = this.store.get<Invitation>('SELECT * FROM invitations WHERE hash=?', sha256(ticket));
    requireThat(invitation && !invitation.used_at && invitation.expires_at > this.now(), 'INVALID_INVITATION', 401);
    const identity = await this.verifyIdentity(invitation.provider, proof);
    requireThat(identity.subject === invitation.subject, 'IDENTITY_MISMATCH', 403);
    return this.store.transaction(() => {
      const current = this.store.get<Invitation>('SELECT * FROM invitations WHERE hash=?', invitation.hash)!;
      requireThat(!current.used_at && current.expires_at > this.now(), 'INVALID_INVITATION', 401);
      requireThat(!this.store.get('SELECT 1 FROM accounts WHERE provider=? AND subject=?', identity.provider, identity.subject), 'IDENTITY_ALREADY_REGISTERED', 409);
      const accountId = randomUUID();
      this.store.run('INSERT INTO accounts VALUES (?,?,?,?)', accountId, identity.provider, identity.subject, this.now());
      this.store.run('UPDATE invitations SET used_at=? WHERE hash=?', this.now(), invitation.hash);
      this.audit(accountId, 'account.registered', accountId); this.event('account.registered', accountId);
      return this.session(accountId);
    });
  }
  async login(provider: string, proof: string) {
    const identity = await this.verifyIdentity(provider, proof);
    return this.store.transaction(() => {
      const account = this.store.get<Account>('SELECT * FROM accounts WHERE provider=? AND subject=?', identity.provider, identity.subject);
      requireThat(account, 'IDENTITY_NOT_REGISTERED', 401);
      this.audit(account.id, 'session.created', account.id); return this.session(account.id);
    });
  }
  authenticate(token: string): string {
    const session = this.store.get<{ account_id: string; expires_at: number }>('SELECT * FROM sessions WHERE hash=?', sha256(token));
    requireThat(session && session.expires_at > this.now(), 'UNAUTHORIZED', 401); return session.account_id;
  }
  logout(token: string): void { this.store.run('DELETE FROM sessions WHERE hash=?', sha256(token)); }
  changeIdentity(accountId: string, provider: string, subject: string, reason: string): void {
    requireThat(this.providers.has(provider), 'IDENTITY_PROVIDER_DISABLED');
    this.store.transaction(() => {
      const old = this.account(accountId);
      requireThat(old.provider !== provider || old.subject !== subject, 'IDENTITY_UNCHANGED', 409);
      requireThat(!this.store.get('SELECT 1 FROM accounts WHERE provider=? AND subject=?', provider, subject), 'IDENTITY_ALREADY_REGISTERED', 409);
      this.store.run('UPDATE accounts SET provider=?,subject=? WHERE id=?', provider, subject, accountId);
      this.store.run('DELETE FROM sessions WHERE account_id=?', accountId);
      this.store.run('UPDATE challenges SET used_at=? WHERE account_id=? AND used_at IS NULL', this.now(), accountId);
      this.store.run('UPDATE invitations SET used_at=? WHERE (provider=? AND subject=?) OR (provider=? AND subject=?)',
        this.now(), old.provider, old.subject, provider, subject);
      this.store.run('UPDATE bindings SET enabled=0 WHERE account_id=?', accountId);
      this.audit('admin', 'identity.changed', accountId, { from: { provider: old.provider, subject: old.subject }, to: { provider, subject }, reason });
      this.event('identity.changed', accountId);
    });
  }
  profile(accountId: string) {
    const account = this.account(accountId);
    return {
      account, entitlements: this.store.all('SELECT edition_id,active,order_id FROM entitlements WHERE account_id=?', accountId),
      bindings: this.store.all('SELECT group_id,device_id,key_thumbprint,bound_at,free_at,generation,enabled FROM bindings WHERE account_id=?', accountId),
      credits: this.store.all('SELECT group_id,balance FROM credits WHERE account_id=?', accountId),
    };
  }
  createOrder(accountId: string, offerId: string, key: string) {
    return this.command(accountId, 'order.create', key, { offerId }, () => {
      const offer = this.catalog.offers.find(o => o.id === offerId);
      requireThat(offer, 'OFFER_NOT_FOUND', 404); this.account(accountId);
      this.checkOfferEligibility(accountId, offer);
      const orderId = randomUUID();
      this.store.run('INSERT INTO orders(id,account_id,offer_json,status,created_at) VALUES (?,?,?,?,?)',
        orderId, accountId, JSON.stringify(offer), 'pending', this.now());
      this.audit(accountId, 'order.created', orderId, { offerId });
      return { orderId, status: 'pending', offer };
    });
  }
  private checkOfferEligibility(accountId: string, offer: Offer): void {
    if (offer.kind === 'rebind') requireThat(this.ownsGroup(accountId, offer.groupId!), 'GROUP_NOT_OWNED', 403);
    else {
      requireThat(!this.owns(accountId, offer.editionId!), 'EDITION_ALREADY_OWNED', 409);
      if (offer.kind === 'upgrade') requireThat(this.owns(accountId, offer.requiresEditionId!), 'UPGRADE_NOT_ELIGIBLE', 403);
    }
  }
  orders(accountId: string) {
    return this.store.all<Order>('SELECT * FROM orders WHERE account_id=? ORDER BY created_at DESC LIMIT 100', accountId)
      .map(row => ({ id: row.id, offer: JSON.parse(row.offer_json) as Offer, status: row.status, createdAt: row.created_at, paidAt: row.paid_at }));
  }
  confirmPayment(orderId: string, payment: { method: string; reference: string; amount: number; currency: string }) {
    return this.store.transaction(() => {
      const order = this.store.get<Order>('SELECT * FROM orders WHERE id=?', orderId);
      requireThat(order, 'ORDER_NOT_FOUND', 404);
      const offer = JSON.parse(order.offer_json) as Offer;
      requireThat(payment.amount === offer.amount && payment.currency === offer.currency, 'PAYMENT_AMOUNT_MISMATCH', 409);
      if (order.status === 'paid') {
        requireThat(order.payment_method === payment.method && order.payment_reference === payment.reference, 'PAYMENT_ALREADY_RECORDED', 409);
        return { orderId, status: 'paid', replayed: true };
      }
      requireThat(order.status === 'pending', 'ORDER_NOT_PENDING', 409);
      requireThat(!this.store.get('SELECT 1 FROM orders WHERE payment_method=? AND payment_reference=?', payment.method, payment.reference), 'PAYMENT_REFERENCE_REUSED', 409);
      this.checkOfferEligibility(order.account_id, offer);
      if (offer.kind === 'rebind') this.addCredits(order.account_id, offer.groupId!, offer.credits!);
      else this.store.run(`INSERT INTO entitlements VALUES (?,?,?,1) ON CONFLICT(account_id,edition_id)
        DO UPDATE SET active=1,order_id=excluded.order_id`, order.account_id, offer.editionId!, orderId);
      this.store.run('UPDATE orders SET status=?,paid_at=?,payment_method=?,payment_reference=? WHERE id=?',
        'paid', this.now(), payment.method, payment.reference, orderId);
      this.audit('admin', 'payment.confirmed', orderId, { method: payment.method, amount: payment.amount, currency: payment.currency });
      this.event('order.fulfilled', order.account_id);
      return { orderId, status: 'paid', replayed: false };
    });
  }
  cancelOrder(accountId: string, orderId: string): void {
    this.store.transaction(() => {
      const row = this.store.get<Order>('SELECT * FROM orders WHERE id=? AND account_id=?', orderId, accountId);
      requireThat(row, 'ORDER_NOT_FOUND', 404); requireThat(row.status === 'pending', 'ORDER_NOT_PENDING', 409);
      this.store.run("UPDATE orders SET status='cancelled' WHERE id=?", orderId);
      this.audit(accountId, 'order.cancelled', orderId);
    });
  }
  grantCredits(accountId: string, groupId: string, count: number, reason: string, key: string) {
    requireThat(Number.isInteger(count) && count > 0 && count <= 100, 'INVALID_CREDITS');
    return this.command(accountId, 'admin.credits', key, { groupId, count, reason }, () => {
      this.account(accountId); requireThat(this.catalog.groups.some(g => g.id === groupId), 'GROUP_NOT_FOUND', 404);
      this.addCredits(accountId, groupId, count);
      this.audit('admin', 'credits.granted', accountId, { groupId, count, reason });
      return { balance: this.credits(accountId, groupId) };
    });
  }
  revokeEntitlement(accountId: string, editionId: string, reason: string): void {
    this.store.transaction(() => {
      requireThat(this.owns(accountId, editionId), 'ENTITLEMENT_NOT_FOUND', 404);
      this.store.run('UPDATE entitlements SET active=0 WHERE account_id=? AND edition_id=?', accountId, editionId);
      this.audit('admin', 'entitlement.revoked', accountId, { editionId, reason });
      this.event('entitlement.revoked', accountId);
    });
  }
  private challenge(accountId: string, kind: string, payload: object) {
    const id = randomUUID(); const expiresAt = this.now() + 5 * 60_000;
    const message = JSON.stringify(['product-license-kit', 1, kind, id, accountId, payload, randomToken()]);
    this.store.run('INSERT INTO challenges VALUES (?,?,?,?,?,?,NULL)', id, accountId, kind, JSON.stringify(payload), message, expiresAt);
    return { challengeId: id, message, expiresAt };
  }
  enrollmentChallenge(accountId: string, groupId: string, publicKey: string, fingerprint: Fingerprint) {
    requireThat(this.ownsGroup(accountId, groupId), 'GROUP_NOT_OWNED', 403);
    let normalized: ReturnType<typeof normalizePublicKey>;
    try { normalized = normalizePublicKey(publicKey); } catch { requireThat(false, 'INVALID_DEVICE_KEY'); }
    return this.challenge(accountId, 'enroll', { groupId, publicKey: normalized.pem, thumbprint: normalized.thumbprint, fingerprint });
  }
  activate(accountId: string, challengeId: string, signature: string, key: string) {
    return this.command(accountId, 'device.activate', key, { challengeId, signature }, () => {
      const challenge = this.loadChallenge(challengeId, 'enroll');
      requireThat(challenge.account_id === accountId, 'CHALLENGE_NOT_FOUND', 404);
      const payload = JSON.parse(challenge.payload) as { groupId: string; publicKey: string; thumbprint: string; fingerprint: Fingerprint };
      requireThat(verifyProof(payload.publicKey, challenge.message, signature), 'INVALID_DEVICE_PROOF', 401);
      requireThat(this.ownsGroup(accountId, payload.groupId), 'GROUP_NOT_OWNED', 403);
      const group = this.catalog.groups.find(g => g.id === payload.groupId)!;
      const previous = this.store.get<Binding>('SELECT * FROM bindings WHERE account_id=? AND group_id=?', accountId, group.id);
      const keyOwner = this.store.get<Binding>('SELECT * FROM bindings WHERE group_id=? AND key_thumbprint=?', group.id, payload.thumbprint);
      requireThat(!keyOwner || keyOwner.account_id === accountId, 'DEVICE_KEY_ALREADY_BOUND', 409);
      let cost: 'initial' | 'same-device' | 'free' | 'credit' = 'initial';
      let deviceId: string = randomUUID(); let generation = 1; let freeAt = addCalendarMonths(this.now(), group.cooldownMonths, group.utcOffsetMinutes);
      if (previous) {
        generation = previous.generation + 1;
        if (previous.key_thumbprint === payload.thumbprint) {
          cost = 'same-device'; deviceId = previous.device_id; freeAt = previous.free_at;
          generation = previous.enabled ? previous.generation : generation;
        } else cost = rebindCost(previous.free_at, this.now(), this.credits(accountId, group.id));
      }
      if (cost === 'credit') this.store.run('UPDATE credits SET balance=balance-1 WHERE account_id=? AND group_id=?', accountId, group.id);
      const boundAt = cost === 'same-device' ? previous!.bound_at : this.now();
      this.store.run(`INSERT INTO bindings VALUES (?,?,?,?,?,?,?,?,?,1)
        ON CONFLICT(account_id,group_id) DO UPDATE SET device_id=excluded.device_id,public_key=excluded.public_key,
        key_thumbprint=excluded.key_thumbprint,fingerprint_json=excluded.fingerprint_json,bound_at=excluded.bound_at,
        free_at=excluded.free_at,generation=excluded.generation,enabled=1`, accountId, group.id, deviceId,
        payload.publicKey, payload.thumbprint, JSON.stringify(payload.fingerprint), boundAt, freeAt, generation);
      this.store.run('UPDATE challenges SET used_at=? WHERE id=?', this.now(), challengeId);
      this.audit(accountId, 'device.activated', deviceId, { groupId: group.id, cost, generation, freeAt, previousDevice: previous?.device_id ?? null });
      this.event('device.activated', accountId);
      return { deviceId, groupId: group.id, keyThumbprint: payload.thumbprint, generation, freeAt, cost };
    });
  }
  private loadChallenge(id: string, kind: string): Challenge {
    const row = this.store.get<Challenge>('SELECT * FROM challenges WHERE id=?', id);
    requireThat(row && row.kind === kind && row.used_at === null && row.expires_at > this.now(), 'INVALID_CHALLENGE', 401); return row;
  }
  licenseChallenge(deviceId: string, editionId: string) {
    const binding = this.store.get<Binding>('SELECT * FROM bindings WHERE device_id=? AND enabled=1', deviceId);
    requireThat(binding && this.owns(binding.account_id, editionId), 'LICENSE_UNAVAILABLE', 403);
    requireThat(this.groupForEdition(editionId).groupId === binding.group_id, 'LICENSE_UNAVAILABLE', 403);
    return this.challenge(binding.account_id, 'license', { deviceId, editionId, generation: binding.generation });
  }
  issueLicense(challengeId: string, signature: string) {
    return this.store.transaction(() => {
      const challenge = this.loadChallenge(challengeId, 'license');
      const payload = JSON.parse(challenge.payload) as { deviceId: string; editionId: string; generation: number };
      const binding = this.store.get<Binding>('SELECT * FROM bindings WHERE device_id=? AND enabled=1', payload.deviceId);
      requireThat(binding && binding.account_id === challenge.account_id && binding.generation === payload.generation &&
        this.owns(binding.account_id, payload.editionId) && this.groupForEdition(payload.editionId).groupId === binding.group_id, 'LICENSE_UNAVAILABLE', 403);
      requireThat(verifyProof(binding.public_key, challenge.message, signature), 'INVALID_DEVICE_PROOF', 401);
      const seconds = Math.floor(this.now() / 1000);
      const claims: LicenseClaims = { iss: this.issuer, aud: this.groupForEdition(payload.editionId).productId,
        sub: binding.account_id, edition: payload.editionId, device: binding.device_id, keyThumbprint: binding.key_thumbprint,
        generation: binding.generation, ownership: 'perpetual', iat: seconds, nbf: seconds, exp: seconds + this.licenseSeconds };
      const token = this.signer.sign(claims, 'plk-license');
      this.store.run('UPDATE challenges SET used_at=? WHERE id=?', this.now(), challengeId);
      return { token, expiresAt: claims.exp * 1000 };
    });
  }
  reserveDistribution(accountId: string, editionId: string, releaseId: string, key: string) {
    return this.command(accountId, 'distribution.reserve', key, { editionId, releaseId }, () => {
      const account = this.account(accountId); requireThat(this.owns(accountId, editionId), 'EDITION_NOT_OWNED', 403);
      const id = randomUUID();
      this.store.run('INSERT INTO distributions VALUES (?,?,?,?,?,NULL,NULL,?,NULL)', id, accountId, editionId,
        releaseId, JSON.stringify({ provider: account.provider, subject: account.subject }), this.now());
      this.audit('admin', 'distribution.reserved', id, { accountId, editionId, releaseId });
      return { distributionId: id, marker: `PLK-DISTRIBUTION:${id}` };
    });
  }
  finalizeDistribution(id: string, artifactSha256: string) {
    requireThat(/^[a-f0-9]{64}$/.test(artifactSha256), 'INVALID_ARTIFACT_HASH');
    return this.store.transaction(() => {
      const row = this.store.get<Distribution>('SELECT * FROM distributions WHERE id=?', id);
      requireThat(row, 'DISTRIBUTION_NOT_FOUND', 404);
      requireThat(this.owns(row.account_id, row.edition_id), 'EDITION_NOT_OWNED', 403);
      if (row.manifest) {
        requireThat(row.artifact_sha256 === artifactSha256, 'DISTRIBUTION_IMMUTABLE', 409);
        return { manifest: row.manifest };
      }
      const manifest = this.signer.sign({ distributionId: row.id, editionId: row.edition_id,
        releaseId: row.release_id, sha256: artifactSha256, issuedAt: this.now() }, 'plk-distribution');
      this.store.run('UPDATE distributions SET artifact_sha256=?,manifest=?,finalized_at=? WHERE id=?', artifactSha256, manifest, this.now(), id);
      this.audit('admin', 'distribution.finalized', id, { artifactSha256 }); this.event('distribution.ready', row.account_id);
      return { manifest };
    });
  }
  distributions(accountId: string) {
    return this.store.all<Distribution>('SELECT * FROM distributions WHERE account_id=? AND finalized_at IS NOT NULL ORDER BY created_at DESC LIMIT 100', accountId)
      .filter(row => this.owns(accountId, row.edition_id))
      .map(row => ({ id: row.id, editionId: row.edition_id, releaseId: row.release_id, manifest: row.manifest, sha256: row.artifact_sha256 }));
  }
  traceDistribution(id: string) {
    const row = this.store.get<Distribution>('SELECT * FROM distributions WHERE id=?', id);
    requireThat(row, 'DISTRIBUTION_NOT_FOUND', 404); return row;
  }
  /** Single-worker, at-least-once outbox. Sinks should deduplicate by event.id where supported. */
  async dispatchNotifications(sink: NotificationSink, limit = 20): Promise<{ delivered: number; failed: number }> {
    const rows = this.store.all<{ id: string; topic: string; account_id: string; created_at: number }>(
      'SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY created_at,id LIMIT ?', limit);
    let delivered = 0; let failed = 0;
    for (const row of rows) {
      const account = this.account(row.account_id);
      this.store.run('UPDATE outbox SET attempts=attempts+1 WHERE id=?', row.id);
      try {
        await sink.send({ id: row.id, topic: row.topic, accountId: account.id, createdAt: row.created_at },
          { provider: account.provider, subject: account.subject });
        this.store.run('UPDATE outbox SET delivered_at=? WHERE id=?', this.now(), row.id); delivered++;
      } catch { failed++; }
    }
    return { delivered, failed };
  }
  auditLog() { return this.store.all('SELECT * FROM audit ORDER BY created_at DESC,id DESC LIMIT 100'); }
  cleanupExpired(): void {
    this.store.transaction(() => {
      this.store.run('DELETE FROM sessions WHERE expires_at<=?', this.now());
      this.store.run('DELETE FROM challenges WHERE expires_at<=?', this.now());
      this.store.run('DELETE FROM invitations WHERE expires_at<=?', this.now());
    });
  }
}
