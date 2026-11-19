/** Native asynchronous storage. SQL uses PostgreSQL $1 parameters, never request-supplied SQL. */
export type SqlValue = string | number | bigint | Uint8Array | null;
export interface AsyncStore {
  readonly transactionUnit?: true;
  get<T>(sql: string, ...values: SqlValue[]): Promise<T | undefined>;
  all<T>(sql: string, ...values: SqlValue[]): Promise<T[]>;
  run(sql: string, ...values: SqlValue[]): Promise<{ changes: number }>;
  /** Use the supplied unit for every query and nested transaction. It expires with this callback. */
  transaction<T>(work: (unit: AsyncStore) => T | Promise<T>): Promise<T>;
}

export class StorageError extends Error {
  readonly retryable: boolean;
  constructor(readonly code: string, readonly postgresCode?: string) {
    super(code); this.name = 'StorageError';
    this.retryable = code === 'TRANSACTION_RETRY_REQUIRED';
  }
}
