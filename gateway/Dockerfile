# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
# POPOPX Service Suite — gateway image.
#
# Multi-architecture: python:3.11-slim carries linux/amd64 and linux/arm64
# manifests, and every dependency in requirements.txt resolves to a pure-wheel
# or an abi3 wheel on both, so the image builds unmodified on an Apple Silicon
# laptop and on an x86_64 Ubuntu server. Build both in one go with:
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t popopx/gateway:1 ./gateway
#
# Deliberately NO `HEALTHCHECK` instruction (the same choice the upstream
# `apps/popopx-support-bot-light/Dockerfile` records): the gateway's readiness
# depends on a WebSocket it does not own — the `popopx-chat` node on
# 127.0.0.1:5225 — and a container whose only fault is "the node is still
# catching up" being restarted by the orchestrator turns a 20-second reconnect
# into a crash loop that also drops in-flight message correlation ids.
# Liveness is therefore asserted by /healthz to the orchestrator's own probe
# (see docker-compose.yml, which is where the policy belongs) and never by an
# instruction baked into the image.

FROM python:3.11-slim AS runtime

# `pyc` files and interactive prompts buy nothing in a container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl is for the deployment smoke test in install_ubuntu22.sh; ca-certificates
# is for the outbound TLS of the AI plugin and the chain-RPC poller.
RUN apt-get update \
 && apt-get install --no-install-recommends -y curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged uid/gid, matching the USER_UID/USER_GID convention (1000) the
# sibling repos use, so a bind-mounted /var/lib/popopx-service-suite created by
# the install script needs no chown dance at first start.
RUN groupadd --gid 1001 popopx \
 && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin popopx

WORKDIR /srv/gateway

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# The SQLite file, the Ed25519 key material and the voucher store all live
# here; compose mounts a volume on it. 0750 on purpose: other users of a shared
# host must not read a merchant's channel keys.
RUN mkdir -p /var/lib/popopx-service-suite \
 && chown -R popopx:popopx /var/lib/popopx-service-suite /srv/gateway

USER popopx

ENV POPOPX_DB_PATH=/var/lib/popopx-service-suite/gateway.db \
    POPOPX_GATEWAY_HOST=0.0.0.0 \
    POPOPX_GATEWAY_PORT=8080

EXPOSE 8080

# One process, always: the WebSocket link to the node and its pending-correlation
# table are per-process state, so a second worker would be a second, conflicting
# link. `python -m app.main` is the only entrypoint, and it takes the bind address,
# the port and the log level from POPOPX_GATEWAY_HOST / POPOPX_GATEWAY_PORT /
# POPOPX_LOG_LEVEL above — flag arguments here would be a second source of truth
# about one socket, and the flag would silently win over the environment.
# `access_log` is off in `main()` for the same reason as `--no-access-log` was:
# request bodies carry pairwise uids and signatures.
CMD ["python", "-m", "app.main"]
