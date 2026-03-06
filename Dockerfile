FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
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
    strace \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/simple_agent

COPY requirements.runtime.txt /tmp/requirements.runtime.txt
RUN python3 -m venv /opt/rtrace-venv && \
    /opt/rtrace-venv/bin/pip install --upgrade pip && \
    /opt/rtrace-venv/bin/pip install -r /tmp/requirements.runtime.txt

# Install Codex CLI globally so the advisor does not need separate setup.
RUN npm install -g @openai/codex

COPY . /workspace/simple_agent

RUN chmod +x \
    /workspace/simple_agent/bin/rtrace \
    /workspace/simple_agent/bin/rtrace_monitor \
    /workspace/simple_agent/scripts/agent_setup/run_setup_scripts.sh \
    /workspace/simple_agent/scripts/agent_setup/codex_setup.sh \
    /workspace/simple_agent/scripts/install_rtrace.sh \
    /workspace/simple_agent/docker/entrypoint.sh \
    /workspace/simple_agent/run_intercepted_codex.sh \
    /workspace/simple_agent/run_intercepted_agent.sh \
    /workspace/simple_agent/run_interactive_intercepted.sh

RUN ln -sf /workspace/simple_agent/bin/rtrace /usr/local/bin/rtrace && \
    ln -sf /workspace/simple_agent/bin/rtrace_monitor /usr/local/bin/rtrace_monitor

ENV PATH="/opt/rtrace-venv/bin:/usr/local/bin:${PATH}" \
    RTRACE_VENV="/opt/rtrace-venv" \
    RTRACE_REPO_ROOT="/workspace/simple_agent" \
    AGENT_OBS_ROOT="/workspace/simple_agent/obs"

ENTRYPOINT ["/workspace/simple_agent/docker/entrypoint.sh"]
CMD ["bash"]
