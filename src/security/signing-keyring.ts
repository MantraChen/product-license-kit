import type { AsyncStore } from '../core/async-store.js';
import { EnvelopeSigner } from '../core/crypto.js';
import { requireThat } from '../core/model.js';

/** Immutable process-local private material; the PostgreSQL policy chooses the active member. */
export class SigningKeyRing {
  private readonly keys: ReadonlyMap<string, EnvelopeSigner>;
  constructor(
    readonly primary: EnvelopeSigner,
    additional: readonly EnvelopeSigner[] = [],
  ) {
    const values = [primary, ...additional];
    requireThat(
      values.length <= 32 &&
        new Set(values.map((key) => key.kid)).size === values.length,
      'DUPLICATE_SIGNING_KEY',
    );
    this.keys = new Map(values.map((key) => [key.kid, key]));
  }
  get(kid: string) {
    return this.keys.get(kid);
  }
  additional() {
    return [...this.keys.values()].filter((key) => key !== this.primary);
  }
  async active(unit: AsyncStore, namespace: string, contextHash?: string) {
    requireThat(unit.transactionUnit === true, 'TRANSACTION_UNIT_REQUIRED');
    // A share lock makes activation wait for in-flight issuance. SERIALIZABLE
    // transactions whose snapshot predates activation retry instead of signing stale.
    const policy = await unit.get<{ active_kid: string; context_hash: string }>(
      'SELECT active_kid,context_hash FROM signing_policies WHERE namespace=$1 FOR SHARE',
      namespace,
    );
    if (!policy) {
      requireThat(!contextHash, 'SIGNING_POLICY_NOT_CONFIGURED', 503);
      return this.primary;
    }
    requireThat(
      contextHash && contextHash === policy.context_hash,
      'SIGNING_CONTEXT_CHANGED',
      503,
    );
    const signer = this.get(policy.active_kid);
    requireThat(signer, 'SIGNING_KEY_UNAVAILABLE', 503);
    const registered = await unit.get<{ public_key: string }>(
      'SELECT public_key FROM signing_keys WHERE namespace=$1 AND kid=$2',
      namespace,
      policy.active_kid,
    );
    requireThat(
      registered?.public_key === signer.publicKey,
      'SIGNING_POLICY_INVALID',
      503,
    );
    return signer;
  }
}
