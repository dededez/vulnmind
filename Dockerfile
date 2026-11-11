# syntax=docker/dockerfile:1

# Runtime image for the VulnMind CLI. The WSL sandbox is deliberately NOT part of
# this image: sandboxed scanners and the sandboxed shell require a WSL/VM boundary
# and cannot be provided by a normal container on Windows. Run those on a host
# with the VulnMindSandbox distribution, or add a dedicated runner later.

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VULNMIND_REPORT_ROOT=/data/reports \
    VULNMIND_EVIDENCE_ROOT=/data/evidence

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY migrations ./migrations

RUN pip install --no-cache-dir . \
 && useradd --create-home --uid 10001 vulnmind \
 && mkdir -p /data/reports /data/evidence \
 && chown -R vulnmind:vulnmind /data /app

USER vulnmind

VOLUME ["/data"]

ENTRYPOINT ["vulnmind"]
CMD ["--help"]
