# agent-ops-lab

**AI automations for settings where mistakes are expensive.**

A working lab for running LangGraph agents in production on a small, shared server: human approval before actions, an audit trail, evals and tracing in LangSmith, and a known cost per completed task. Built in the open, on synthetic or public data only.

> Status: **v0, infrastructure + first agent scoped.** Automation #1 is a CVE triage agent ([product brief](docs/cve-triage/product-brief.md)). Agents land here cycle by cycle (see [Roadmap](#roadmap)).

## Why this matters for a bank

Most AI automations in regulated firms don't fail at the demo. They fail at the risk review, because nobody can answer four questions:

1. **Who approved this action?** Every write, send or payment needs a named human step, or a documented reason why it doesn't.
2. **What exactly happened?** Inputs, model calls, tool calls and outputs must be reconstructable after the fact.
3. **How do we know it still works?** A fixed eval set, re-run on every change, beats "it looked fine last week".
4. **What does it cost per case?** Not per token: per completed task, so it can be compared with the manual process.

This repo is where I build the patterns that answer those questions, on infrastructure I run myself.

## What's here

| Path | What it is |
|---|---|
| `compose.yaml` | The `agent-ops` Compose project: Postgres 17 with pgvector for state, checkpoints, audit log and agent memory; own network and volume; hard memory/CPU limits; no published ports |
| `.env.example` | Every setting the stack reads. Copy to `.env`, which is never committed |
| `db/init/001_cve_memory.sql` | Schema `cve`: runs, CVE records, deterministic matches, append-only analyses with embeddings |
| `agents/cve_triage/` | The agent: Python package (uv), Dockerfile, offline tests. Today: `hello_graph.py` (NVD last 24 h → count, traced) |
| `agents/cve_triage/inventory/bank-estate.yaml` | Synthetic IT estate of a fictional bank (8 hosts with CPEs, zones, criticality, compensating controls) |
| `docs/cve-triage/product-brief.md` | User, problem, graph design, priority rules, guardrails, metrics, out of scope |
| `docs/cve-triage/setup.md` | Runbook: keys, pgvector switch, schema, first traced run on the VPS |

Coming next: the full triage graph in `agents/cve_triage/`, `evals/`.

## Automation #1: CVE triage agent

Pulls new and modified CVEs from the NVD API, matches them **deterministically** against a synthetic bank inventory (CPE + version ranges), lets an LLM assess the priority per affected host in context, checks that assessment with hard rules, and stores every analysis with its evidence in Postgres/pgvector so later decisions stay consistent and auditable. Output: a digest grouped by priority and host.

The split matters: code decides *whether* a machine is affected; the model only helps decide *how urgent* it is, and a guard stops it from inventing findings or lowering a priority without a documented compensating control. Details in the [product brief](docs/cve-triage/product-brief.md).

## Guardrails (the rules this stack keeps)

- **Isolation.** Own Compose project, network, volumes and secrets. It shares a host with other workloads and must never touch them.
- **No public surface.** No published ports. Admin access via SSH/Tailscale only.
- **Resource limits on every container.** A looping agent hits its own ceiling, not the host's.
- **Least privilege for secrets.** `.env` is `chmod 600`. No exchange, brokerage or payment keys in this stack, ever.
- **Human approval before side effects.** Agents draft; a person approves anything that leaves the system (from cycle 2.4 on, enforced in the graph).
- **Everything traced.** LangSmith tracing on from the first hello-world graph.
- **Synthetic or public data only** in this repo. Personal config and real data stay private.

## Run it

Requires Docker with the Compose plugin.

```bash
git clone https://github.com/MattK984/agent-ops-lab.git
cd agent-ops-lab
cp .env.example .env && chmod 600 .env   # then set POSTGRES_PASSWORD
docker compose up -d
docker compose ps                        # postgres should show (healthy)
docker compose exec postgres psql -U agent_ops -d agent_ops -c 'select version();'
```

On a fresh volume the `cve` schema is created automatically. On an existing volume, apply it once:

```bash
docker compose exec -T postgres psql -U agent_ops -d agent_ops < db/init/001_cve_memory.sql
```

## Roadmap

| Cycle | Dates | Ships |
|---|---|---|
| 2.1 | Nov 23 – Dec 6, 2026 | Stack + repo · LangSmith tracing · **CVE triage agent** (NVD → inventory match → assessment → pgvector memory) delivering a digest |
| 2.2 | Dec 7 – Dec 20 | Automation #2: research/news digest |
| 2.3 | Dec 21 – Jan 3 | Eval set (≥15 cases) for the CVE triage agent |
| 2.4 | Jan 4 – Jan 17 | Automation #3: inbox/document triage with a human approval gate |
| 2.5 | Jan 18 – Jan 31 | Spec + architecture for a regulated document-intake template |
| 2.6 | Feb 1 – Feb 14, 2027 | Template v0.1 end to end: intake → extraction → approval → audit log |

## Stack

LangGraph (Python) · LangSmith · Postgres 17 + pgvector · Docker Compose · a single small VPS behind Tailscale.

## About

Built by [Matthias Knauth](https://www.linkedin.com/in/pm-matthias-knauth): 20+ years in banking, trading and digital assets; now building on-prem LLM and agent systems for regulated operators. Personal work from public sources, no employer or client material.

Licence: [MIT](LICENSE).
