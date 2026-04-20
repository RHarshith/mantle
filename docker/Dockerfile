FROM ubuntu:24.04

# Prevent interactive prompts during apt installations
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    bpftrace \
    iptables \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a virtual environment and update PATH so we don't have to use 'python3 -m' everywhere
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python requirements
COPY requirements.runtime.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.runtime.txt

# The application code is mounted from the host in development,
# and copied into the image for standalone runs.
COPY . .

# This repository uses a flat multi-package layout; running editable install
# from repo root fails package discovery. Commands run from /app can import
# project modules directly from the copied source tree.
ENV PYTHONPATH=/app

# The CMD is overridden in docker-compose.yml for each specific service.
CMD ["bash"]
