FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH=/app
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-dev \
    python3-pip \
    nmap \
    curl \
    wget \
    git \
    ca-certificates \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# ── Go → Nuclei ───────────────────────────────────────────────────────────────
RUN curl -OL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz \
    && rm go1.23.4.linux-amd64.tar.gz
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── OWASP ZAP ────────────────────────────────────────────────────────────────
RUN ZAP_VERSION=2.15.0 \
    && wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    && tar -xzf "ZAP_${ZAP_VERSION}_Linux.tar.gz" -C /opt/ \
    && rm "ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    && ln -s "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zaproxy

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Application code ──────────────────────────────────────────────────────────
COPY backend/ /app/backend/
COPY agents/ /app/agents/

# ── Runtime ───────────────────────────────────────────────────────────────────
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
