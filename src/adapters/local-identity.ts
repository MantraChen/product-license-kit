import { requireThat, type IdentityProvider, type VerifiedIdentity } from '../core/model.js';
import { secretEqual } from '../core/crypto.js';

/** Development only: proves possession of a randomly generated local credential. */
export class LocalIdentityProvider implements IdentityProvider {
  readonly name = 'local';
  constructor(private readonly identities: ReadonlyArray<{ subject: string; proof: string }>) {
    requireThat(process.env.NODE_ENV !== 'production', 'LOCAL_IDENTITY_FORBIDDEN_IN_PRODUCTION');
    requireThat(identities.every(i => i.proof.length >= 32), 'WEAK_LOCAL_CREDENTIAL');
  }
  async verify(proof: string): Promise<VerifiedIdentity> {
    const match = this.identities.find(i => secretEqual(i.proof, proof));
    requireThat(match, 'INVALID_IDENTITY_PROOF', 401);
    return { provider: this.name, subject: match.subject };
  }
}
