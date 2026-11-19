import { createHash } from 'node:crypto';

// PostgreSQL has an independent migration history. This baseline corresponds to the SQLite v7 domain layout.
const baseline = `
CREATE TABLE accounts(id TEXT PRIMARY KEY,provider TEXT NOT NULL,subject TEXT NOT NULL,
  created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991),UNIQUE(provider,subject));
CREATE TABLE account_states(account_id TEXT PRIMARY KEY REFERENCES accounts(id),active SMALLINT NOT NULL CHECK(active IN (0,1)),
  reason TEXT NOT NULL,updated_at BIGINT NOT NULL CHECK(updated_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE invitations(hash TEXT PRIMARY KEY,provider TEXT NOT NULL,subject TEXT NOT NULL,
  expires_at BIGINT NOT NULL CHECK(expires_at BETWEEN 0 AND 9007199254740991),used_at BIGINT CHECK(used_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE sessions(hash TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),
  expires_at BIGINT NOT NULL CHECK(expires_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE orders(id TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),offer_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','paid','cancelled')),created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991),
  paid_at BIGINT CHECK(paid_at BETWEEN 0 AND 9007199254740991),payment_method TEXT,payment_reference TEXT,UNIQUE(payment_method,payment_reference));
CREATE TABLE entitlements(account_id TEXT NOT NULL REFERENCES accounts(id),edition_id TEXT NOT NULL,
  order_id TEXT REFERENCES orders(id),active SMALLINT NOT NULL CHECK(active IN (0,1)),PRIMARY KEY(account_id,edition_id));
CREATE TABLE credits(account_id TEXT NOT NULL REFERENCES accounts(id),group_id TEXT NOT NULL,
  balance BIGINT NOT NULL CHECK(balance BETWEEN 0 AND 9007199254740991),PRIMARY KEY(account_id,group_id));
CREATE TABLE bindings(account_id TEXT NOT NULL REFERENCES accounts(id),group_id TEXT NOT NULL,device_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,key_thumbprint TEXT NOT NULL,fingerprint_json TEXT NOT NULL,
  bound_at BIGINT NOT NULL CHECK(bound_at BETWEEN 0 AND 9007199254740991),free_at BIGINT NOT NULL CHECK(free_at BETWEEN 0 AND 9007199254740991),
  generation BIGINT NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),enabled SMALLINT NOT NULL CHECK(enabled IN (0,1)),
  PRIMARY KEY(account_id,group_id),UNIQUE(group_id,key_thumbprint));
CREATE TABLE challenges(id TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),kind TEXT NOT NULL,payload TEXT NOT NULL,message TEXT NOT NULL,
  expires_at BIGINT NOT NULL CHECK(expires_at BETWEEN 0 AND 9007199254740991),used_at BIGINT CHECK(used_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE commands(account_id TEXT NOT NULL REFERENCES accounts(id),operation TEXT NOT NULL,command_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,result_json TEXT NOT NULL,PRIMARY KEY(account_id,operation,command_key));
CREATE TABLE audit(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL,
  created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE outbox(id TEXT PRIMARY KEY,topic TEXT NOT NULL,account_id TEXT NOT NULL REFERENCES accounts(id),
  created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991),delivered_at BIGINT CHECK(delivered_at BETWEEN 0 AND 9007199254740991),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0));
CREATE TABLE outbox_resources(event_id TEXT PRIMARY KEY REFERENCES outbox(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('account','order','entitlement','device','distribution')),resource_id TEXT NOT NULL CHECK(length(resource_id) BETWEEN 1 AND 128));
CREATE TABLE distributions(id TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),edition_id TEXT NOT NULL,release_id TEXT NOT NULL,
  identity_snapshot TEXT NOT NULL,artifact_sha256 TEXT,manifest TEXT,created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991),
  finalized_at BIGINT CHECK(finalized_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE entitlement_imports(source TEXT NOT NULL,reference TEXT NOT NULL,edition_id TEXT NOT NULL,
  account_id TEXT NOT NULL REFERENCES accounts(id),reason TEXT NOT NULL,created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991),
  PRIMARY KEY(source,reference,edition_id));
CREATE TABLE entitlement_channels(account_id TEXT NOT NULL,edition_id TEXT NOT NULL,channel TEXT NOT NULL CHECK(channel='beta'),
  PRIMARY KEY(account_id,edition_id,channel),FOREIGN KEY(account_id,edition_id) REFERENCES entitlements(account_id,edition_id));
CREATE TABLE binding_resets(account_id TEXT NOT NULL,group_id TEXT NOT NULL,generation BIGINT NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
  reset_at BIGINT NOT NULL CHECK(reset_at BETWEEN 0 AND 9007199254740991),PRIMARY KEY(account_id,group_id),
  FOREIGN KEY(account_id,group_id) REFERENCES bindings(account_id,group_id) ON DELETE CASCADE);
CREATE TABLE order_deadlines(order_id TEXT PRIMARY KEY REFERENCES orders(id),expires_at BIGINT NOT NULL CHECK(expires_at BETWEEN 0 AND 9007199254740991),
  expired_at BIGINT CHECK(expired_at BETWEEN 0 AND 9007199254740991));
CREATE TABLE payment_exceptions(id TEXT PRIMARY KEY,original_order_id TEXT NOT NULL REFERENCES orders(id),account_id TEXT NOT NULL REFERENCES accounts(id),
  method TEXT NOT NULL,reference TEXT NOT NULL,amount BIGINT NOT NULL CHECK(amount BETWEEN 1 AND 9007199254740991),currency TEXT NOT NULL,reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','applied','refunded')),created_at BIGINT NOT NULL CHECK(created_at BETWEEN 0 AND 9007199254740991),
  resolved_at BIGINT CHECK(resolved_at BETWEEN 0 AND 9007199254740991),resolution TEXT,UNIQUE(method,reference));
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE INDEX orders_account_cursor ON orders(account_id,created_at DESC,id DESC);
CREATE INDEX audit_cursor ON audit(created_at DESC,id DESC);
CREATE INDEX distributions_account_cursor ON distributions(account_id,created_at DESC,id DESC) WHERE finalized_at IS NOT NULL;
CREATE INDEX challenges_expiry ON challenges(expires_at);
CREATE INDEX outbox_pending ON outbox(created_at,id) WHERE delivered_at IS NULL;
CREATE INDEX order_deadline_due ON order_deadlines(expires_at) WHERE expired_at IS NULL;
`;
const coordination = `
CREATE TABLE task_jobs(
  id TEXT PRIMARY KEY,namespace TEXT NOT NULL,task_key TEXT NOT NULL,payload TEXT NOT NULL,input_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','leased','sending','succeeded','uncertain','dead','expired','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
  generation BIGINT NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 9007199254740991),
  lease_token TEXT,lease_until BIGINT,next_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,last_error TEXT,result TEXT,resolution TEXT,
  UNIQUE(namespace,task_key),
  CHECK((state IN ('leased','sending'))=(lease_token IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE INDEX task_jobs_due ON task_jobs(namespace,next_at,created_at,id) WHERE state IN ('pending','leased');
CREATE INDEX task_jobs_review ON task_jobs(namespace,created_at DESC,id DESC);
CREATE TABLE task_job_reviews(
  task_id TEXT NOT NULL REFERENCES task_jobs(id),generation BIGINT NOT NULL,actor TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','retry','cancelled')),reason TEXT NOT NULL,result_hash TEXT NOT NULL,created_at BIGINT NOT NULL,
  PRIMARY KEY(task_id,generation)
);
CREATE TABLE rate_limit_buckets(
  bucket_key TEXT PRIMARY KEY,window_ms INTEGER NOT NULL,max_requests INTEGER NOT NULL,
  current INTEGER NOT NULL CHECK(current BETWEEN 0 AND 1000001),expires_at BIGINT NOT NULL
);
CREATE INDEX rate_limit_expiry ON rate_limit_buckets(expires_at);
`;
const signing = `
CREATE TABLE signing_keys(namespace TEXT NOT NULL,kid TEXT NOT NULL,public_key TEXT NOT NULL,created_at BIGINT NOT NULL,
  PRIMARY KEY(namespace,kid));
CREATE TABLE signing_policies(namespace TEXT PRIMARY KEY,active_kid TEXT NOT NULL,epoch BIGINT NOT NULL CHECK(epoch BETWEEN 1 AND 9007199254740991),
  context_hash TEXT NOT NULL,required_nodes TEXT NOT NULL,updated_at BIGINT NOT NULL,
  FOREIGN KEY(namespace,active_kid) REFERENCES signing_keys(namespace,kid));
CREATE TABLE signing_rotations(id TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES signing_policies(namespace),
  previous_kid TEXT NOT NULL,kid TEXT NOT NULL,epoch BIGINT NOT NULL,context_hash TEXT NOT NULL,required_nodes TEXT NOT NULL,nonce TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('scheduled','running','completed','paused','expired','cancelled')),
  not_before BIGINT NOT NULL,expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 0,owner_token TEXT,lease_until BIGINT,actor TEXT NOT NULL,reason TEXT NOT NULL,
  backup_receipt TEXT,last_error TEXT,
  FOREIGN KEY(namespace,kid) REFERENCES signing_keys(namespace,kid),
  CHECK((status='running')=(owner_token IS NOT NULL AND lease_until IS NOT NULL)));
CREATE UNIQUE INDEX signing_one_active ON signing_rotations(namespace) WHERE status IN ('scheduled','running');
CREATE INDEX signing_rotation_history ON signing_rotations(namespace,created_at DESC,id DESC);
CREATE TABLE signing_readiness(plan_id TEXT NOT NULL REFERENCES signing_rotations(id),node_id TEXT NOT NULL,proof TEXT NOT NULL,
  expires_at BIGINT NOT NULL,PRIMARY KEY(plan_id,node_id));
`;
const compatibility = `
CREATE TABLE compatibility_imports(id TEXT PRIMARY KEY,source_digest TEXT NOT NULL,plan_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','completed')),backup_sha256 TEXT NOT NULL,
  actor TEXT NOT NULL,reason TEXT NOT NULL,created_at BIGINT NOT NULL,completed_at BIGINT);
`;
const portal = `
CREATE TABLE portal_settings(namespace TEXT PRIMARY KEY,context_hash TEXT NOT NULL,key_hash TEXT NOT NULL);
CREATE TABLE portal_mfa(namespace TEXT NOT NULL REFERENCES portal_settings(namespace),account_id TEXT NOT NULL REFERENCES accounts(id),
  secret TEXT NOT NULL,last_counter BIGINT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(namespace,account_id));
CREATE TABLE portal_recovery(namespace TEXT NOT NULL,account_id TEXT NOT NULL,hash TEXT NOT NULL,
  PRIMARY KEY(namespace,account_id,hash),FOREIGN KEY(namespace,account_id) REFERENCES portal_mfa(namespace,account_id) ON DELETE CASCADE);
CREATE TABLE portal_operators(namespace TEXT NOT NULL REFERENCES portal_settings(namespace),account_id TEXT NOT NULL REFERENCES accounts(id),
  permissions TEXT NOT NULL,enabled SMALLINT NOT NULL CHECK(enabled IN (0,1)),revision BIGINT NOT NULL,updated_at BIGINT NOT NULL,
  PRIMARY KEY(namespace,account_id));
CREATE TABLE portal_oauth_states(hash TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES portal_settings(namespace),
  browser_hash TEXT NOT NULL,remember SMALLINT NOT NULL CHECK(remember IN (0,1)),expires_at BIGINT NOT NULL);
CREATE TABLE portal_sessions(hash TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES portal_settings(namespace),account_id TEXT NOT NULL REFERENCES accounts(id),
  provider TEXT NOT NULL,subject TEXT NOT NULL,csrf TEXT NOT NULL,stage TEXT NOT NULL CHECK(stage IN ('setup','mfa','active')),
  core_hash TEXT NOT NULL REFERENCES sessions(hash) ON DELETE CASCADE,core_token TEXT NOT NULL,setup_secret TEXT,
  remember SMALLINT NOT NULL CHECK(remember IN (0,1)),created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,
  mfa_at BIGINT,last_seen BIGINT NOT NULL,CHECK((stage='setup')=(setup_secret IS NOT NULL)),CHECK(stage<>'active' OR mfa_at IS NOT NULL));
CREATE INDEX portal_sessions_expiry ON portal_sessions(expires_at);
CREATE INDEX portal_oauth_expiry ON portal_oauth_states(expires_at);
CREATE TABLE portal_reset_intents(hash TEXT PRIMARY KEY,namespace TEXT NOT NULL,session_hash TEXT NOT NULL REFERENCES portal_sessions(hash) ON DELETE CASCADE,
  group_id TEXT NOT NULL,snapshot TEXT NOT NULL,command_key TEXT NOT NULL,expires_at BIGINT NOT NULL,consumed_at BIGINT,result TEXT);
`;
const bot = `
CREATE TABLE bot_settings(namespace TEXT PRIMARY KEY,portal_namespace TEXT NOT NULL REFERENCES portal_settings(namespace),
  context_hash TEXT NOT NULL,epoch BIGINT NOT NULL CHECK(epoch BETWEEN 1 AND 9007199254740991),paused SMALLINT NOT NULL CHECK(paused IN (0,1)));
CREATE TABLE bot_messages(id TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES bot_settings(namespace),epoch BIGINT NOT NULL,
  user_id TEXT NOT NULL,content TEXT NOT NULL,content_hash TEXT NOT NULL,message_id TEXT,chat_code TEXT,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,
  CHECK((message_id IS NULL)=(chat_code IS NULL)),UNIQUE(namespace,message_id));
CREATE TABLE bot_actions(hash TEXT PRIMARY KEY,message_key TEXT NOT NULL REFERENCES bot_messages(id),action TEXT NOT NULL,
  expires_at BIGINT NOT NULL,used_at BIGINT,result TEXT);
CREATE TABLE bot_handoffs(hash TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES bot_settings(namespace),epoch BIGINT NOT NULL,
  portal_namespace TEXT NOT NULL REFERENCES portal_settings(namespace),provider TEXT NOT NULL,subject TEXT NOT NULL,
  expires_at BIGINT NOT NULL,used_at BIGINT,revoked_at BIGINT,account_id TEXT REFERENCES accounts(id));
CREATE INDEX bot_handoffs_expiry ON bot_handoffs(expires_at);
CREATE TABLE portal_registration_states(state_hash TEXT PRIMARY KEY REFERENCES portal_oauth_states(hash) ON DELETE CASCADE,
  handoff_hash TEXT NOT NULL REFERENCES bot_handoffs(hash));
CREATE TABLE bot_notification_owners(issuer TEXT PRIMARY KEY,namespace TEXT NOT NULL UNIQUE REFERENCES bot_settings(namespace));
`;
export const postgresMigrations = [
  {
    version: 1,
    sql: baseline,
    checksum: createHash('sha256').update(baseline).digest('hex'),
  },
  {
    version: 2,
    sql: coordination,
    checksum: createHash('sha256').update(coordination).digest('hex'),
  },
  {
    version: 3,
    sql: signing,
    checksum: createHash('sha256').update(signing).digest('hex'),
  },
  {
    version: 4,
    sql: compatibility,
    checksum: createHash('sha256').update(compatibility).digest('hex'),
  },
  {
    version: 5,
    sql: portal,
    checksum: createHash('sha256').update(portal).digest('hex'),
  },
  {
    version: 6,
    sql: bot,
    checksum: createHash('sha256').update(bot).digest('hex'),
  },
] as const;
