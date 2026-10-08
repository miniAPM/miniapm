-- journal_mode/busy_timeout/synchronous/foreign_keys are set per-connection via
-- SqliteConnectOptions in db.rs, not here, so every pooled connection gets them
-- (not just whichever connection happens to run this migration once).

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    controller TEXT,
    action TEXT,
    status INTEGER NOT NULL,
    total_ms REAL NOT NULL,
    db_ms REAL DEFAULT 0,
    db_count INTEGER DEFAULT 0,
    view_ms REAL DEFAULT 0,
    host TEXT,
    env TEXT,
    git_sha TEXT,
    happened_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_project_id ON requests(project_id);
CREATE INDEX IF NOT EXISTS idx_requests_happened_at ON requests(happened_at);
CREATE INDEX IF NOT EXISTS idx_requests_path_method ON requests(path, method);
CREATE INDEX IF NOT EXISTS idx_requests_total_ms ON requests(total_ms DESC);

CREATE TABLE IF NOT EXISTS errors (
    id INTEGER PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    exception_class TEXT NOT NULL,
    message TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    occurrence_count INTEGER DEFAULT 1,
    status TEXT DEFAULT 'open',
    UNIQUE(project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_errors_project_id ON errors(project_id);
CREATE INDEX IF NOT EXISTS idx_errors_status ON errors(status);
CREATE INDEX IF NOT EXISTS idx_errors_last_seen ON errors(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS error_occurrences (
    id INTEGER PRIMARY KEY,
    error_id INTEGER NOT NULL REFERENCES errors(id) ON DELETE CASCADE,
    request_id TEXT,
    user_id TEXT,
    backtrace TEXT NOT NULL,
    params TEXT,
    happened_at TEXT NOT NULL,
    source_context TEXT
);

CREATE INDEX IF NOT EXISTS idx_error_occurrences_error_id ON error_occurrences(error_id);
CREATE INDEX IF NOT EXISTS idx_error_occurrences_happened_at ON error_occurrences(happened_at);

CREATE TABLE IF NOT EXISTS rollups_hourly (
    id INTEGER PRIMARY KEY,
    hour TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    error_count INTEGER DEFAULT 0,
    total_ms_sum REAL NOT NULL,
    total_ms_p50 REAL,
    total_ms_p95 REAL,
    total_ms_p99 REAL,
    db_ms_sum REAL DEFAULT 0,
    db_count_sum INTEGER DEFAULT 0,
    UNIQUE(hour, path, method)
);

CREATE INDEX IF NOT EXISTS idx_rollups_hourly_hour ON rollups_hourly(hour);

CREATE TABLE IF NOT EXISTS rollups_daily (
    id INTEGER PRIMARY KEY,
    date TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    error_count INTEGER DEFAULT 0,
    total_ms_p50 REAL,
    total_ms_p95 REAL,
    total_ms_p99 REAL,
    avg_db_ms REAL,
    avg_db_count REAL,
    UNIQUE(date, path, method)
);

CREATE INDEX IF NOT EXISTS idx_rollups_daily_date ON rollups_daily(date);

CREATE TABLE IF NOT EXISTS deploys (
    id INTEGER PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    git_sha TEXT NOT NULL,
    version TEXT,
    env TEXT,
    deployed_at TEXT NOT NULL,
    description TEXT,
    deployer TEXT
);

CREATE INDEX IF NOT EXISTS idx_deploys_project_id ON deploys(project_id);
CREATE INDEX IF NOT EXISTS idx_deploys_deployed_at ON deploys(deployed_at);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,
    api_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_slug ON projects(slug);
CREATE INDEX IF NOT EXISTS idx_projects_api_key ON projects(api_key);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    invite_token TEXT UNIQUE,
    invite_expires_at TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS spans (
    id INTEGER PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    parent_span_id TEXT,
    start_time_unix_nano INTEGER NOT NULL,
    end_time_unix_nano INTEGER NOT NULL,
    duration_ms REAL,
    name TEXT NOT NULL,
    kind INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER DEFAULT 0,
    status_message TEXT,
    span_category TEXT NOT NULL,
    root_span_type TEXT,
    service_name TEXT,
    http_method TEXT,
    http_url TEXT,
    http_status_code INTEGER,
    db_system TEXT,
    db_statement TEXT,
    db_operation TEXT,
    messaging_system TEXT,
    messaging_operation TEXT,
    request_id TEXT,
    attributes_json TEXT,
    events_json TEXT,
    resource_attributes_json TEXT,
    happened_at TEXT NOT NULL,
    UNIQUE(trace_id, span_id)
);

CREATE INDEX IF NOT EXISTS idx_spans_project_id ON spans(project_id);
CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id);
CREATE INDEX IF NOT EXISTS idx_spans_happened_at ON spans(happened_at);
CREATE INDEX IF NOT EXISTS idx_spans_root_type ON spans(root_span_type) WHERE root_span_type IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_spans_category ON spans(span_category);
