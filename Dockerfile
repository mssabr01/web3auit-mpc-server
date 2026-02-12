FROM python:3.12.8-slim-bookworm

# Metadata
LABEL org.opencontainers.image.description="Web3 Security Audit Tools - Offline-Ready"
LABEL org.opencontainers.image.source="https://github.com/mssabr01/web3auit-mpc-server"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential libffi-dev nodejs npm && \
    rm -rf /var/lib/apt/lists/*

# ---- Foundry (forge, cast, anvil) -----------------------------------------
ENV FOUNDRY_VERSION=nightly-de33b6af53005037b463318d2628b5cfcaf39916
RUN curl -L https://foundry.paradigm.xyz | bash && \
    bash -c "source /root/.bashrc && foundryup --version ${FOUNDRY_VERSION}" || \
    /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# ---- uv (fast Python package manager) -------------------------------------
RUN pip install --no-cache-dir uv

# ---- solc-select -----------------------------------------------------------
RUN uv pip install --system solc-select && \
# Pre-install common Solidity compiler versions for offline use
    solc-select install 0.8.24 && \
    solc-select install 0.8.23 && \
    solc-select install 0.8.22 && \
    solc-select install 0.8.21 && \
    solc-select install 0.8.20 && \
    solc-select install 0.8.19 && \
    solc-select install 0.8.18 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.16 && \
    solc-select install 0.8.15 && \
    solc-select install 0.8.13 && \
    solc-select install 0.8.12 && \
    solc-select install 0.8.11 && \
    solc-select install 0.8.10 && \
    solc-select install 0.8.9 && \
    solc-select install 0.8.8 && \
    solc-select install 0.8.7 && \
    solc-select install 0.8.4 && \
    solc-select install 0.7.6 && \
    solc-select install 0.6.12 && \
    solc-select use 0.8.24

# ---- Slither (standalone — used by our wrapper, not slither-mcp) -----------
RUN uv pip install --system slither-analyzer

# ---- Aderyn (Cyfrin's Rust-based static analyser) --------------------------
# Official npm package — no Rust toolchain or shell reload required
RUN npm install -g @cyfrin/aderyn

# ---- web3audit-mcp (this project) -----------------------------------------
COPY pyproject.toml README.md /app/
COPY src/ /app/src/
RUN uv pip install --system /app

WORKDIR /contracts

ENTRYPOINT ["web3audit-mcp"]
