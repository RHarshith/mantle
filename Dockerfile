FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bpftrace \
    ca-certificates \
    curl \
    git \
    iproute2 \
    iptables \
    iputils-ping \
    lsof \
    npm \
    openssh-client \
    python3 \
    python3-pip \
    python3-venv \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/mantle

COPY requirements.runtime.txt /tmp/requirements.runtime.txt
RUN python3 -m venv /opt/mantle-venv && \
    /opt/mantle-venv/bin/pip install --upgrade pip && \
    /opt/mantle-venv/bin/pip install -r /tmp/requirements.runtime.txt

# Install Codex CLI globally so the advisor does not need separate setup.
RUN npm install -g @openai/codex

COPY . /workspace/mantle

RUN chmod +x \
    /workspace/mantle/bin/mantle \
    /workspace/mantle/bin/rtrace_test \
    /workspace/mantle/scripts/agent_setup/run_setup_scripts.sh \
    /workspace/mantle/scripts/agent_setup/codex_setup.sh \
    /workspace/mantle/scripts/install_mantle.sh \
    /workspace/mantle/scripts/install_rtrace.sh \
    /workspace/mantle/docker/entrypoint.sh \
    /workspace/mantle/run_intercepted_codex.sh

RUN ln -sf /workspace/mantle/bin/mantle /usr/local/bin/mantle

ENV PATH="/opt/mantle-venv/bin:/usr/local/bin:${PATH}" \
    MANTLE_VENV="/opt/mantle-venv" \
    MANTLE_REPO_ROOT="/workspace/mantle" \
    RTRACE_VENV="/opt/mantle-venv" \
    RTRACE_REPO_ROOT="/workspace/mantle" \
    AGENT_OBS_ROOT="/workspace/mantle/obs"

ENTRYPOINT ["/workspace/mantle/docker/entrypoint.sh"]
CMD ["bash"]
