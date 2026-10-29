import { createPrivateKey, sign } from 'node:crypto';
import { z } from 'zod';
import { normalizePublicKey, sha256, verifyEnvelope } from '../core/crypto.js';
import { requireThat } from '../core/model.js';

const claimsSchema = z.object({
  iss: z.string(), aud: z.string(), sub: z.string(), edition: z.string(), device: z.string(),
  keyThumbprint: z.string(), generation: z.number().int().positive(), ownership: z.literal('perpetual'),
  iat: z.number().int(), nbf: z.number().int(), exp: z.number().int(),
}).strict();

/** publicKey must come from trusted product configuration, never from the same untrusted response as token. */
export function verifyLicense(token: string, publicKey: string, expected: {
  issuer: string; productId: string; editionId: string; accountId: string;
  deviceId: string; devicePublicKey: string; now?: number;
}) {
  const claims = claimsSchema.parse(verifyEnvelope(token, publicKey, 'plk-license'));
  const now = Math.floor((expected.now ?? Date.now()) / 1000);
  requireThat(claims.iss === expected.issuer && claims.aud === expected.productId && claims.edition === expected.editionId &&
    claims.sub === expected.accountId && claims.device === expected.deviceId &&
    claims.keyThumbprint === normalizePublicKey(expected.devicePublicKey).thumbprint, 'LICENSE_SCOPE_MISMATCH');
  requireThat(claims.nbf <= now && claims.iat <= now && claims.exp > now && claims.exp > claims.iat, 'LICENSE_EXPIRED_OR_NOT_YET_VALID');
  return claims;
}

export function signChallenge(message: string, devicePrivateKey: string): string {
  requireThat(message.startsWith('["product-license-kit",1,'), 'UNKNOWN_CHALLENGE_PROTOCOL');
  const key = createPrivateKey(devicePrivateKey);
  requireThat(key.asymmetricKeyType === 'ed25519', 'ED25519_REQUIRED');
  return sign(null, Buffer.from(message), key).toString('base64url');
}

export function verifyDistribution(token: string, publicKey: string, artifact: Uint8Array,
  expected: { distributionId: string; editionId: string; releaseId: string }) {
  const manifest = z.object({ distributionId: z.string(), editionId: z.string(), releaseId: z.string(),
    sha256: z.string(), issuedAt: z.number().int() }).strict().parse(verifyEnvelope(token, publicKey, 'plk-distribution'));
  requireThat(manifest.distributionId === expected.distributionId && manifest.editionId === expected.editionId &&
    manifest.releaseId === expected.releaseId && manifest.sha256 === sha256(artifact), 'DISTRIBUTION_MISMATCH');
  return manifest;
}

export class LicenseClient {
  constructor(private readonly baseUrl: string, private readonly http: typeof fetch = fetch) {
    const url = new URL(baseUrl);
    requireThat(url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)), 'HTTPS_REQUIRED');
    requireThat(!url.username && !url.password && !url.search && !url.hash, 'INVALID_SERVER_URL');
  }
  async request<T>(path: string, options: { body?: unknown; accessToken?: string; idempotencyKey?: string } = {}): Promise<T> {
    requireThat(path.startsWith('/v1/') && !path.includes('://'), 'INVALID_API_PATH');
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (options.accessToken) headers.Authorization = `Bearer ${options.accessToken}`;
    if (options.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey;
    const response = await this.http(new URL(path, this.baseUrl), {
      method: options.body === undefined ? 'GET' : 'POST', headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      signal: AbortSignal.timeout(10_000), redirect: 'error',
    });
    if (!response.ok) throw new Error(`API_REQUEST_FAILED:${response.status}`);
    return await response.json() as T;
  }
}
