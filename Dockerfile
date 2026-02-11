FROM python:3.12.8-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# Install uv
RUN pip install --no-cache-dir uv

# Install solc-select
RUN uv pip install --system solc-select && \
    solc-select install 0.8.24 && \
    solc-select use 0.8.24

# Install slither-mcp
RUN uv pip install --system \
    "slither-mcp @ git+https://github.com/trailofbits/slither-mcp.git"

WORKDIR /contracts

ENTRYPOINT ["slither-mcp"]