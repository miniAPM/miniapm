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

-- spans and error_occurrences are partitioned by day on happened_at, so
-- retention drops whole days; see create_day_partition and
-- drop_partitions_before. A key must include the partition column.
CREATE TABLE error_occurrences (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    error_id BIGINT NOT NULL REFERENCES errors (id) ON DELETE CASCADE,
    request_id TEXT,
    user_id TEXT,
    backtrace JSONB NOT NULL,
    params JSONB,
    happened_at TIMESTAMPTZ NOT NULL,
    source_context JSONB,
    PRIMARY KEY (id, happened_at)
) PARTITION BY RANGE (happened_at);

CREATE TABLE error_occurrences_default PARTITION OF error_occurrences DEFAULT;

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
    id BIGINT GENERATED ALWAYS AS IDENTITY,
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
    attributes_json JSONB,
    events_json JSONB,
    resource_attributes_json JSONB,
    happened_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (id, happened_at),
    UNIQUE (trace_id, span_id, happened_at)
) PARTITION BY RANGE (happened_at);

CREATE TABLE spans_default PARTITION OF spans DEFAULT;

CREATE INDEX spans_project_id ON spans (project_id, happened_at);
CREATE INDEX spans_happened_at ON spans USING brin (happened_at);
CREATE INDEX spans_roots ON spans (happened_at) WHERE parent_span_id IS NULL;
CREATE INDEX spans_root_type ON spans (root_span_type) WHERE root_span_type IS NOT NULL;
CREATE INDEX spans_category ON spans (span_category);

-- The start of each of the `hours` hours up to and including the one `until` falls in
CREATE FUNCTION hour_buckets(until timestamptz, hours integer)
RETURNS SETOF timestamptz
LANGUAGE sql STABLE
RETURN generate_series(
    date_trunc('hour', until) - make_interval(hours => hours - 1),
    date_trunc('hour', until),
    interval '1 hour'
);

-- Store one error occurrence and bump the group it belongs to: `p_group_id`
-- when the caller matched one, else the group at `p_fingerprint`. A recurring
-- group moves from each status in `p_recur_from` to the one at the same
-- position in `p_recur_to`.
CREATE FUNCTION record_error(
    p_group_id bigint,
    p_project_id bigint,
    p_fingerprint text,
    p_exception_class text,
    p_message text,
    p_happened_at timestamptz,
    p_recur_from text[],
    p_recur_to text[],
    p_request_id text,
    p_user_id text,
    p_backtrace text,
    p_params text,
    p_source_context text
)
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    recorded bigint;
BEGIN
    IF p_group_id IS NOT NULL THEN
        UPDATE errors
           SET last_seen_at = p_happened_at,
               occurrence_count = occurrence_count + 1,
               status = COALESCE(p_recur_to[array_position(p_recur_from, status)], status)
         WHERE id = p_group_id
        RETURNING id INTO recorded;
    END IF;

    IF recorded IS NULL THEN
        INSERT INTO errors AS e
            (project_id, fingerprint, exception_class, message, first_seen_at, last_seen_at)
        VALUES
            (p_project_id, p_fingerprint, p_exception_class, p_message, p_happened_at, p_happened_at)
        ON CONFLICT (project_id, fingerprint) DO UPDATE
           SET last_seen_at = excluded.last_seen_at,
               occurrence_count = e.occurrence_count + 1,
               status = COALESCE(p_recur_to[array_position(p_recur_from, e.status)], e.status)
        RETURNING id INTO recorded;
    END IF;

    INSERT INTO error_occurrences
        (error_id, request_id, user_id, backtrace, params, happened_at, source_context)
    VALUES
        (recorded, p_request_id, p_user_id, p_backtrace::jsonb, p_params::jsonb, p_happened_at,
         p_source_context::jsonb);

    RETURN recorded;
END
$$;

-- Create the partition of `parent` holding UTC day `day`, named
-- <parent>_pYYYYMMDD. Rows of that day already in the default partition move
-- into it, as Postgres refuses a partition whose rows sit in the default one.
CREATE FUNCTION create_day_partition(parent regclass, day date)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    schema_name text;
    table_name text;
    part text;
    lo timestamptz := day::timestamp AT TIME ZONE 'UTC';
    hi timestamptz := (day + 1)::timestamp AT TIME ZONE 'UTC';
BEGIN
    SELECT n.nspname, c.relname INTO schema_name, table_name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.oid = parent;
    part := format('%I.%I', schema_name, table_name || '_p' || to_char(day, 'YYYYMMDD'));
    IF to_regclass(part) IS NOT NULL THEN
        RETURN;
    END IF;

    EXECUTE format('CREATE TEMP TABLE moved_rows (LIKE %s)', parent);
    EXECUTE format(
        'WITH moved AS (DELETE FROM %I.%I WHERE happened_at >= %L AND happened_at < %L RETURNING *)
         INSERT INTO moved_rows SELECT * FROM moved',
        schema_name, table_name || '_default', lo, hi);
    EXECUTE format('CREATE TABLE %s PARTITION OF %s FOR VALUES FROM (%L) TO (%L)', part, parent, lo, hi);
    EXECUTE format('INSERT INTO %s OVERRIDING SYSTEM VALUE SELECT * FROM moved_rows', parent);
    DROP TABLE moved_rows;
END
$$;

-- Create the day partitions of `parent` from yesterday to `days_ahead` days ahead
CREATE FUNCTION create_day_partitions(parent regclass, days_ahead integer)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    today date := (now() AT TIME ZONE 'UTC')::date;
BEGIN
    FOR offset_days IN -1 .. days_ahead LOOP
        PERFORM create_day_partition(parent, today + offset_days);
    END LOOP;
END
$$;

-- Drop the day partitions of `parent` that end by `cutoff` and delete older
-- rows from its default partition. The partition straddling `cutoff` stays
-- until its whole day has expired.
CREATE FUNCTION drop_partitions_before(parent regclass, cutoff timestamptz)
RETURNS TABLE (dropped integer, deleted bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    part regclass;
BEGIN
    dropped := 0;
    FOR part IN
        SELECT c.oid::regclass
          FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = parent
           AND c.relname ~ '_p[0-9]{8}$'
           AND (to_date(right(c.relname, 8), 'YYYYMMDD') + 1)::timestamp AT TIME ZONE 'UTC' <= cutoff
    LOOP
        EXECUTE format('DROP TABLE %s', part);
        dropped := dropped + 1;
    END LOOP;

    EXECUTE format(
        'DELETE FROM %s WHERE happened_at < $1',
        (SELECT format('%I.%I', n.nspname, c.relname || '_default')
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.oid = parent))
    USING cutoff;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN NEXT;
END
$$;
