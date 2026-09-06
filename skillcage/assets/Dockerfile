# skillcage sandbox image: an untrusted skill runs headless in here.
# It holds NO real credential (the proxy injects it) and runs as non-root.
FROM docker.io/library/python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates ripgrep jq procps \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 sandbox
USER sandbox
WORKDIR /home/sandbox

# default driver: Claude Code (swap via --agent-cmd for another CLI)
RUN curl -fsSL https://claude.ai/install.sh | bash \
 && /home/sandbox/.local/bin/claude --version

ENV PATH="/home/sandbox/.local/bin:${PATH}" \
    HOME=/home/sandbox \
    DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 \
    DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
WORKDIR /work
