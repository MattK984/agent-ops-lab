-- Context memory for the CVE triage agent (schema `cve`).
-- Runs automatically only on an EMPTY data volume (docker-entrypoint-initdb.d).
-- On an existing volume apply it once by hand:
--   docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" < db/init/001_cve_memory.sql
-- Requires the pgvector image (pgvector/pgvector:pg17). Idempotent.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS cve;

-- One row per agent run (scheduled or manual).
CREATE TABLE IF NOT EXISTS cve.runs (
    id              bigserial PRIMARY KEY,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    window_start    timestamptz NOT NULL,
    window_end      timestamptz NOT NULL,
    status          text NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'ok', 'failed')),
    cves_fetched    integer,
    matches_found   integer,
    cost_usd        numeric(10, 4),
    langsmith_trace text,
    error           text
);

-- Normalised CVE records from NVD (latest version wins; raw JSON kept).
CREATE TABLE IF NOT EXISTS cve.cves (
    cve_id          text PRIMARY KEY,
    published       timestamptz,
    last_modified   timestamptz,
    cvss_score      numeric(3, 1),
    cvss_vector     text,
    cvss_version    text,
    severity        text,
    cwe             text[],
    kev_added       date,
    description     text,
    raw             jsonb NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Output of the deterministic matcher: CVE x host.
CREATE TABLE IF NOT EXISTS cve.matches (
    id              bigserial PRIMARY KEY,
    run_id          bigint NOT NULL REFERENCES cve.runs(id),
    cve_id          text NOT NULL REFERENCES cve.cves(cve_id),
    host_id         text NOT NULL,
    cpe             text NOT NULL,
    result          text NOT NULL
                    CHECK (result IN ('affected', 'not_affected', 'needs_review')),
    match_detail    jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, cve_id, host_id, cpe)
);

-- Every assessment, append-only. A re-assessment is a new row.
CREATE TABLE IF NOT EXISTS cve.analyses (
    id              bigserial PRIMARY KEY,
    run_id          bigint NOT NULL REFERENCES cve.runs(id),
    cve_id          text NOT NULL REFERENCES cve.cves(cve_id),
    host_id         text NOT NULL,
    rule_priority   text NOT NULL CHECK (rule_priority IN ('P1', 'P2', 'P3', 'P4')),
    final_priority  text NOT NULL CHECK (final_priority IN ('P1', 'P2', 'P3', 'P4')),
    rationale       text NOT NULL,
    recommended_action text,
    evidence        jsonb NOT NULL DEFAULT '{}'::jsonb,
    guard_result    text NOT NULL
                    CHECK (guard_result IN ('passed', 'corrected', 'rejected')),
    needs_review    boolean NOT NULL DEFAULT false,
    model           text,
    prompt_version  text,
    langsmith_run_id text,
    embedding       vector(384),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS analyses_cve_host_idx ON cve.analyses (cve_id, host_id);
CREATE INDEX IF NOT EXISTS analyses_embedding_idx
    ON cve.analyses USING hnsw (embedding vector_cosine_ops);

-- Audit trail: analyses cannot be changed or removed.
CREATE OR REPLACE FUNCTION cve.block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'cve.analyses is append-only (% blocked)', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS analyses_append_only ON cve.analyses;
CREATE TRIGGER analyses_append_only
    BEFORE UPDATE OR DELETE ON cve.analyses
    FOR EACH ROW EXECUTE FUNCTION cve.block_mutation();

-- One markdown digest per run (checkpoint B); delivery reads from here (Q-2.1-05).
CREATE TABLE IF NOT EXISTS cve.digests (
    id              bigserial PRIMARY KEY,
    run_id          bigint NOT NULL REFERENCES cve.runs(id),
    markdown        text NOT NULL,
    delivered_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS digests_run_idx ON cve.digests (run_id);
