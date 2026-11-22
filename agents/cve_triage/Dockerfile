# CVE triage agent image. Built and run by compose.yaml (service `cve-triage`).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app
# Dependencies first (cached layer), then the code
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev
# Default inventory baked in; compose.yaml mounts the repo copy over it read-only
COPY inventory ./inventory

RUN useradd --system --uid 10001 agent
USER agent

# Checkpoint A of the triage graph. Hello world: `python -m cve_triage.hello_graph`
CMD ["python", "-m", "cve_triage.triage"]
