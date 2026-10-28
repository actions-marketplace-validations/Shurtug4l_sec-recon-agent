# syntax=docker/dockerfile:1.7

# ============================================================================
# uv, as a named stage instead of an inline `COPY --from=<image>:<tag>`.
# The inline form sat on the floating `uv:0.5` tag through every monthly
# Dependabot docker batch without a single bump proposed, while CI ran 0.11.x
# and the lock was written by 0.11.28: three uv versions across one resolution
# contract. A FROM line is the form Dependabot demonstrably updates in this
# repo (the python and node base images). The pin is exact and matches the uv
# that writes uv.lock.
# ============================================================================
FROM ghcr.io/astral-sh/uv:0.12.21 AS uv

# ============================================================================
# Builder stage: install dependencies into a virtualenv using uv.
# Kept separate from runtime so the final image does not carry uv or its cache.
# ============================================================================
FROM python:3.14-slim AS builder

# The uv binary from the official distroless image (small, signed).
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Install runtime dependencies first (cached unless uv.lock changes), then
# copy source. This ordering maximizes Docker layer cache reuse during dev.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# `--reinstall-package` forces the first-party package to be rebuilt from the
# current source on every image build. Without it, uv's build cache keys the
# non-editable wheel by version, so a source change that does not bump the
# version (the norm during development on 0.1.0) is silently served stale from
# the cache mount and the image ships old code. Third-party deps stay cached.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --reinstall-package sec-recon-agent

# ============================================================================
# Runtime stage: minimal Python image, non-root user, only the venv and src.
# ============================================================================
FROM python:3.14-slim AS runtime

# Pull latest Debian security patches in the runtime stage. Without this,
# the image inherits every CVE in whatever snapshot `python:3.14-slim` was
# built from, even when fixes are already in the Debian archive. Picks up
# glibc / systemd / libcap2 / sed patches that `docker scout` flags.
# curl is needed for the healthcheck; everything else lives in the venv.
RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y --no-install-recommends curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# No package manager in the runtime image. The venv is built by uv in the
# builder stage and copied in, so pip is never invoked here. What the base
# image's pip does ship is vendored copies of other projects
# (pip/_vendor/vendor.txt: msgpack 1.1.2, setuptools 70.3.0), which Trivy
# flags (GHSA-6v7p-g79w-8964, CVE-2025-47273, CVE-2026-59890) and which no
# lockfile bump can reach, because they are not in any lockfile. Removing pip
# closes them at the root and takes an install primitive away from anyone who
# lands code execution in the container. Same structural fix as the frontend
# image, where npm/corepack/yarn left the runtime stage. The model bake
# further down imports chromadb and runs an inference with pip already gone,
# so a venv that secretly needed it fails the build, not the deployment.
RUN python -m pip uninstall -y pip \
    && rm -rf /usr/local/bin/pip* /usr/local/lib/python3*/ensurepip/_bundled

# Run as a non-root user. UID 1000 is the convention; matches typical host
# users so bind-mounted data/ stays owned by the same uid outside the container.
RUN groupadd --system --gid 1000 secrecon \
    && useradd --system --uid 1000 --gid secrecon --create-home --shell /sbin/nologin secrecon

WORKDIR /app

# Copy the venv from the builder.
COPY --from=builder --chown=secrecon:secrecon /app/.venv /app/.venv

# Copy source (read-only in container; runtime never writes to /app/src).
COPY --chown=secrecon:secrecon src/ /app/src/
COPY --chown=secrecon:secrecon pyproject.toml /app/

# Writable mount points. Both dirs are pre-created owned by secrecon so the
# named volumes mounted over them (sec-recon-data, sec-recon-audit) inherit
# that ownership; a volume over a missing or root-owned dir is unwritable by
# the non-root runtime user, which silently breaks the audit trail on the
# read-only rootfs.
RUN mkdir -p /app/data /app/audit && chown secrecon:secrecon /app/data /app/audit

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/home/secrecon \
    CHROMA_PERSIST_DIR=/app/data/cve_index

USER secrecon

# Bake the ONNX embedding model into the image at build time.
# ChromaDB's DefaultEmbeddingFunction (ONNX MiniLM-L6) lazily downloads its
# model into ~/.cache on first use. At runtime the container has a read-only
# rootfs (see docker-compose: read_only: true), so a first-query download
# fails with `OSError: [Errno 30] Read-only file system: '/home/secrecon/.cache'`
# and cve_semantic_search raises — taking the agent down on any query that
# hits semantic search. Warming the model here, as the secrecon user, writes
# it into /home/secrecon/.cache during the build (writable) so it is baked
# into the image and present at runtime: no network, no writable cache needed,
# read-only rootfs preserved. Must run after `USER secrecon` so the model
# lands in the runtime user's home, the exact path resolved at query time.
RUN python -c "from chromadb.utils.embedding_functions import DefaultEmbeddingFunction; DefaultEmbeddingFunction()(['warmup'])"

# Default to API; the compose file overrides this for the MCP service.
# Healthcheck applies to whatever process is running; both API and MCP
# bind a TCP port on 127.0.0.1:8000 / :8001 respectively (overridden via
# env in compose to 0.0.0.0 so the other container can reach it).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/v1/health || exit 1

CMD ["sec-recon-api"]
