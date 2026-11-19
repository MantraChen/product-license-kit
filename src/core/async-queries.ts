import type { AsyncStore, SqlValue } from './async-store.js';
import { requireThat } from './model.js';

/** Private compatibility boundary for the framework's fixed domain statements, never user-supplied SQL. */
function compile(sql: string) {
  const ignore = /^INSERT OR IGNORE\b/i.test(sql);
  let source = sql.replace(/^INSERT OR IGNORE\b/i, 'INSERT');
  source = source
    .replace(/json_extract\(payload,'\$\.(groupId|deviceId)'\)/g, "(payload::jsonb ->> '$1')")
    .replace('balance=balance+excluded.balance', 'balance=credits.balance+excluded.balance');
  let result = '',
    quote = '',
    count = 0;
  for (let index = 0; index < source.length; index++) {
    const char = source[index]!;
    if (quote) {
      result += char;
      if (char === quote) {
        if (source[index + 1] === quote) result += source[++index];
        else quote = '';
      }
    } else if (char === "'" || char === '"') {
      quote = char;
      result += char;
    } else result += char === '?' ? `$${++count}` : char;
  }
  requireThat(!quote, 'INVALID_DOMAIN_SQL');
  return { text: result + (ignore ? ' ON CONFLICT DO NOTHING' : ''), count };
}
function row<T>(value: T): T {
  // The wire format historically exposes SQLite EXISTS as 0/1.
  if (
    value &&
    typeof value === 'object' &&
    'reset_pending' in value &&
    typeof value.reset_pending === 'boolean'
  )
    return { ...value, reset_pending: Number(value.reset_pending) };
  return value;
}
export class AsyncQueries {
  constructor(private readonly store: AsyncStore) {}
  private statement(sql: string, values: SqlValue[]) {
    const statement = compile(sql);
    requireThat(statement.count === values.length, 'INVALID_DOMAIN_SQL');
    return statement.text;
  }
  async get<T>(sql: string, ...values: SqlValue[]): Promise<T | undefined> {
    return row(await this.store.get<T>(this.statement(sql, values), ...values));
  }
  async all<T>(sql: string, ...values: SqlValue[]): Promise<T[]> {
    return (await this.store.all<T>(this.statement(sql, values), ...values)).map(row);
  }
  run(sql: string, ...values: SqlValue[]) {
    return this.store.run(this.statement(sql, values), ...values);
  }
}
export async function mapAsync<T, U>(
  items: readonly T[],
  project: (value: T, index: number) => U | Promise<U>,
): Promise<U[]> {
  const output: U[] = [];
  for (let index = 0; index < items.length; index++) output.push(await project(items[index]!, index));
  return output;
}
export async function filterAsync<T>(
  items: readonly T[],
  predicate: (value: T, index: number) => unknown | Promise<unknown>,
): Promise<T[]> {
  const output: T[] = [];
  for (let index = 0; index < items.length; index++)
    if (await predicate(items[index]!, index)) output.push(items[index]!);
  return output;
}
export async function someAsync<T>(
  items: readonly T[],
  predicate: (value: T, index: number) => unknown | Promise<unknown>,
): Promise<boolean> {
  for (let index = 0; index < items.length; index++) if (await predicate(items[index]!, index)) return true;
  return false;
}
