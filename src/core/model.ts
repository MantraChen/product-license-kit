import { z } from 'zod';

export class DomainError extends Error {
  constructor(public readonly code: string, public readonly status = 400) { super(code); }
}
export function requireThat(condition: unknown, code: string, status = 400): asserts condition {
  if (!condition) throw new DomainError(code, status);
}

const id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/);
export const catalogSchema = z.object({
  groups: z.array(z.object({
    id, cooldownMonths: z.number().int().min(1).max(60),
    utcOffsetMinutes: z.number().int().min(-840).max(840),
  }).strict()).min(1),
  products: z.array(z.object({ id, name: z.string().min(1).max(100), groupId: id }).strict()).min(1),
  editions: z.array(z.object({ id, productId: id, name: z.string().min(1).max(100) }).strict()).min(1),
  offers: z.array(z.object({
    id, kind: z.enum(['edition', 'upgrade', 'rebind']),
    editionId: id.optional(), requiresEditionId: id.optional(), groupId: id.optional(),
    credits: z.number().int().min(1).max(100).optional(),
    amount: z.number().int().min(1).max(100_000_000), currency: z.string().regex(/^[A-Z]{3}$/),
  }).strict()),
}).strict();
export type Catalog = z.infer<typeof catalogSchema>;
export type Offer = Catalog['offers'][number];
export function parseCatalog(input: unknown): Catalog {
  const catalog = catalogSchema.parse(input);
  for (const list of [catalog.groups, catalog.products, catalog.editions, catalog.offers]) {
    requireThat(new Set(list.map(item => item.id)).size === list.length, 'DUPLICATE_CATALOG_ID');
  }
  for (const product of catalog.products) requireThat(catalog.groups.some(g => g.id === product.groupId), 'UNKNOWN_GROUP');
  for (const edition of catalog.editions) requireThat(catalog.products.some(p => p.id === edition.productId), 'UNKNOWN_PRODUCT');
  for (const offer of catalog.offers) {
    if (offer.kind === 'rebind') {
      requireThat(offer.credits && catalog.groups.some(g => g.id === offer.groupId), 'INVALID_CREDIT_OFFER');
      requireThat(!offer.editionId && !offer.requiresEditionId, 'INVALID_CREDIT_OFFER');
    } else {
      const target = catalog.editions.find(e => e.id === offer.editionId);
      requireThat(target && !offer.credits && !offer.groupId, 'INVALID_EDITION_OFFER');
      if (offer.kind === 'upgrade') {
        const source = catalog.editions.find(e => e.id === offer.requiresEditionId);
        requireThat(source && source.id !== target.id && source.productId === target.productId, 'INVALID_UPGRADE_OFFER');
      } else requireThat(!offer.requiresEditionId, 'INVALID_EDITION_OFFER');
    }
  }
  return catalog;
}

export interface VerifiedIdentity { provider: string; subject: string }
/** Implementations must verify a provider credential, never just echo a submitted ID. */
export interface IdentityProvider {
  readonly name: string;
  verify(proof: string): Promise<VerifiedIdentity>;
}
export interface Notification {
  id: string; topic: string; accountId: string; createdAt: number;
}
export interface NotificationSink { send(event: Notification, identity: VerifiedIdentity): Promise<void> }

/** UTC offset is explicit: no dependency on the host's timezone; month ends clamp. */
export function addCalendarMonths(epochMs: number, months: number, utcOffsetMinutes: number): number {
  requireThat(Number.isSafeInteger(epochMs) && Number.isInteger(months) && months > 0, 'INVALID_CALENDAR_INPUT');
  const shifted = new Date(epochMs + utcOffsetMinutes * 60_000);
  const day = shifted.getUTCDate();
  shifted.setUTCDate(1);
  shifted.setUTCMonth(shifted.getUTCMonth() + months);
  const end = new Date(Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth() + 1, 0)).getUTCDate();
  shifted.setUTCDate(Math.min(day, end));
  return shifted.getTime() - utcOffsetMinutes * 60_000;
}

export function rebindCost(freeAt: number, now: number, credits: number): 'free' | 'credit' {
  if (now >= freeAt) return 'free';
  requireThat(credits > 0, 'REBIND_COOLDOWN', 409);
  return 'credit';
}
