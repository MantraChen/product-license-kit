import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto';
import { requireThat } from './model.js';

export const randomToken = () => randomBytes(32).toString('base64url');
export const sha256 = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
export function secretEqual(a: string, b: string): boolean {
  return timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
}
export function normalizePublicKey(pem: string): { pem: string; thumbprint: string } {
  try {
    const key = createPublicKey(pem);
    requireThat(key.asymmetricKeyType === 'ed25519', 'ED25519_REQUIRED');
    return { pem: key.export({ type: 'spki', format: 'pem' }).toString(),
      thumbprint: sha256(key.export({ type: 'spki', format: 'der' })) };
  } catch { throw new Error('INVALID_DEVICE_KEY'); }
}
export function verifyProof(pem: string, message: string, signature: string): boolean {
  try {
    if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
    return verify(null, Buffer.from(message), createPublicKey(pem), Buffer.from(signature, 'base64url'));
  } catch { return false; }
}

export interface LicenseClaims {
  iss: string; aud: string; sub: string; edition: string; device: string;
  channel: 'stable' | 'beta'; fingerprint: { schema: string; digest: string };
  keyThumbprint: string; generation: number; ownership: 'perpetual';
  iat: number; nbf: number; exp: number;
}
export class EnvelopeSigner {
  readonly publicKey: string;
  readonly kid: string;
  private readonly privateKey;
  constructor(pem: string) {
    this.privateKey = createPrivateKey(pem);
    requireThat(this.privateKey.asymmetricKeyType === 'ed25519', 'ED25519_REQUIRED');
    this.publicKey = createPublicKey(this.privateKey).export({ type: 'spki', format: 'pem' }).toString();
    this.kid = normalizePublicKey(this.publicKey).thumbprint.slice(0, 24);
  }
  sign(payload: object, type: 'plk-license' | 'plk-distribution'): string {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: type, kid: this.kid })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const message = `${header}.${body}`;
    return `${message}.${sign(null, Buffer.from(message), this.privateKey).toString('base64url')}`;
  }
}

export function verifyEnvelope(token: string, publicKey: string, expectedType: string): unknown {
  requireThat(token.length < 16384, 'INVALID_ENVELOPE');
  const parts = token.split('.');
  requireThat(parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]+$/.test(p)), 'INVALID_ENVELOPE');
  const [header, body, signature] = parts as [string, string, string];
  const parsed = JSON.parse(Buffer.from(header, 'base64url').toString()) as Record<string, unknown>;
  requireThat(parsed.alg === 'EdDSA' && parsed.typ === expectedType &&
    parsed.kid === normalizePublicKey(publicKey).thumbprint.slice(0, 24), 'INVALID_ENVELOPE_HEADER');
  requireThat(verifyProof(publicKey, `${header}.${body}`, signature), 'INVALID_SIGNATURE');
  return JSON.parse(Buffer.from(body, 'base64url').toString()) as unknown;
}
