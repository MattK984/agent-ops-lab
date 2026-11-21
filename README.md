# agent-ops-lab

**AI automations for settings where mistakes are expensive.**

A working lab for running LangGraph agents in production on a small, shared server: human approval before actions, an audit trail, evals and tracing in LangSmith, and a known cost per completed task. Built in the open, on synthetic or public data only.

> Status: **v0, infrastructure only.** Agents land here cycle by cycle (see [Roadmap](#roadmap)).

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
| `compose.yaml` | The `agent-ops` Compose project: Postgres 17 for state, checkpoints and audit log; own network and volume; hard memory/CPU limits; no published ports |
| `.env.example` | Every setting the stack reads. Copy to `.env`, which is never committed |

Coming next: `agents/job_scan/` (first LangGraph agent), `evals/`, `docs/`.

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

## Roadmap

| Cycle | Dates | Ships |
|---|---|---|
| 2.1 | Nov 23 – Dec 6, 2026 | Stack + repo · LangSmith tracing · **job-scan agent** delivering a weekly digest |
| 2.2 | Dec 7 – Dec 20 | Automation #2: research/news digest |
| 2.3 | Dec 21 – Jan 3 | Eval set (≥15 cases) for the job-scan agent |
| 2.4 | Jan 4 – Jan 17 | Automation #3: inbox/document triage with a human approval gate |
| 2.5 | Jan 18 – Jan 31 | Spec + architecture for a regulated document-intake template |
| 2.6 | Feb 1 – Feb 14, 2027 | Template v0.1 end to end: intake → extraction → approval → audit log |

## Stack

LangGraph (Python) · LangSmith · Postgres 17 · Docker Compose · a single small VPS behind Tailscale.

## About

Built by [Matthias Knauth](https://www.linkedin.com/in/pm-matthias-knauth): 20+ years in banking, trading and digital assets; now building on-prem LLM and agent systems for regulated operators. Personal work from public sources, no employer or client material.

Licence: [MIT](LICENSE).
