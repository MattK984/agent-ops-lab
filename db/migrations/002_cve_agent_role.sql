-- Least privilege for the CVE triage agent (Q-2.1-04 checkpoint B).
-- The agent stops connecting as the database owner. Its role may read and append,
-- update only run bookkeeping and the CVE cache, and never DELETE, TRUNCATE or change DDL.
-- cve.analyses stays append-only twice over: no UPDATE/DELETE grant AND the trigger.
--
-- Not in db/init on purpose: it needs psql variables agent_user / agent_pw.
-- Apply by hand (idempotent); the exact command is in docs/cve-triage/checkpoint-b.md, step 2.

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'agent_user', :'agent_pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'agent_user') \gexec

-- Re-running rotates the password to the current value
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE', :'agent_user', :'agent_pw') \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'agent_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA cve TO %I', :'agent_user') \gexec
SELECT format('REVOKE ALL ON ALL TABLES IN SCHEMA cve FROM %I', :'agent_user') \gexec

SELECT format('GRANT SELECT, INSERT, UPDATE ON cve.runs, cve.cves TO %I', :'agent_user') \gexec
SELECT format('GRANT SELECT, INSERT ON cve.matches, cve.analyses TO %I', :'agent_user') \gexec
-- UPDATE on digests only for delivered_at (Q-2.1-05)
SELECT format('GRANT SELECT, INSERT, UPDATE (delivered_at) ON cve.digests TO %I', :'agent_user') \gexec
SELECT format('GRANT USAGE ON ALL SEQUENCES IN SCHEMA cve TO %I', :'agent_user') \gexec
