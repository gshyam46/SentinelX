# ─── Stage 1: Nuclei builder ─────────────────────────────────────────────────
# Isolated so Go download never invalidates the Python + app layers.
FROM ubuntu:22.04 AS nuclei-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz \
    | tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}" \
    GOPATH=/root/go

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/app

# System packages — cached until this layer changes
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-dev \
    python3-pip \
    nmap \
    curl \
    wget \
    ca-certificates \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Nuclei binary from Stage 1 — avoids re-downloading Go on every build
COPY --from=nuclei-builder /root/go/bin/nuclei /usr/local/bin/nuclei

# OWASP ZAP — cached in its own layer (rarely changes)
RUN ZAP_VERSION=2.15.0 && \
    wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" && \
    tar -xzf "ZAP_${ZAP_VERSION}_Linux.tar.gz" -C /opt/ && \
    rm "ZAP_${ZAP_VERSION}_Linux.tar.gz" && \
    ln -sf "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zaproxy

# Python dependencies — cached until requirements.txt changes
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Application code — last layer so code changes don't invalidate earlier layers
COPY backend/ /app/backend/
COPY agents/ /app/agents/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
