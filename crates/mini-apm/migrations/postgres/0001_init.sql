CREATE TABLE projects (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,
    api_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    invite_token TEXT UNIQUE,
    invite_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);

CREATE TABLE sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE errors (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT REFERENCES projects (id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    exception_class TEXT NOT NULL,
    message TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    occurrence_count BIGINT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    UNIQUE NULLS NOT DISTINCT (project_id, fingerprint)
);

CREATE INDEX errors_last_seen_at ON errors (last_seen_at DESC);
CREATE INDEX errors_status ON errors (status);

CREATE TABLE error_occurrences (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    error_id BIGINT NOT NULL REFERENCES errors (id) ON DELETE CASCADE,
    request_id TEXT,
    user_id TEXT,
    backtrace TEXT NOT NULL,
    params TEXT,
    happened_at TIMESTAMPTZ NOT NULL,
    source_context TEXT
);

CREATE INDEX error_occurrences_error_id ON error_occurrences (error_id, happened_at DESC);
CREATE INDEX error_occurrences_happened_at ON error_occurrences USING brin (happened_at);

CREATE TABLE deploys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT REFERENCES projects (id) ON DELETE CASCADE,
    git_sha TEXT NOT NULL,
    version TEXT,
    env TEXT,
    deployed_at TIMESTAMPTZ NOT NULL,
    description TEXT,
    deployer TEXT
);

CREATE INDEX deploys_project_id ON deploys (project_id, deployed_at DESC);
CREATE INDEX deploys_deployed_at ON deploys (deployed_at);

CREATE TABLE spans (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT REFERENCES projects (id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    parent_span_id TEXT,
    start_time_unix_nano BIGINT NOT NULL,
    end_time_unix_nano BIGINT NOT NULL,
    duration_ms DOUBLE PRECISION,
    name TEXT NOT NULL,
    kind INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL DEFAULT 0,
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
    happened_at TIMESTAMPTZ NOT NULL,
    UNIQUE (trace_id, span_id)
);

CREATE INDEX spans_project_id ON spans (project_id, happened_at);
CREATE INDEX spans_happened_at ON spans USING brin (happened_at);
CREATE INDEX spans_roots ON spans (happened_at) WHERE parent_span_id IS NULL;
CREATE INDEX spans_root_type ON spans (root_span_type) WHERE root_span_type IS NOT NULL;
CREATE INDEX spans_category ON spans (span_category);
