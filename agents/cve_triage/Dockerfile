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
# Bake the local embedding model into the image: the container runs read-only and offline for it
ENV FASTEMBED_CACHE_PATH=/app/models
RUN python -m cve_triage.memory && chmod -R a+rX /app/models
ENV HF_HUB_OFFLINE=1 \
    HF_HOME=/tmp/hf
# Default inventory baked in; compose.yaml mounts the repo copy over it read-only
COPY inventory ./inventory

RUN useradd --system --uid 10001 agent
USER agent

# Triage graph, checkpoints A + B. Hello world: `python -m cve_triage.hello_graph`
CMD ["python", "-m", "cve_triage.triage"]
