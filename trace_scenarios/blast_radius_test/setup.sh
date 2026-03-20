#!/usr/bin/env bash
# Idempotent setup for blast radius SSH onboarding sandbox.
set -euo pipefail

RUN_ID="${1:-run_default}"
BASE_DIR="${HOME}/blast-radius-test"
RUN_DIR="${BASE_DIR}/${RUN_ID}"

mkdir -p "${RUN_DIR}/etc/ssh" "${RUN_DIR}/home"

cat > "${RUN_DIR}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/usr/sbin/nologin
EOF

cat > "${RUN_DIR}/etc/shadow" <<'EOF'
root:!:19000:0:99999:7:::
daemon:!:19000:0:99999:7:::
nobody:!:19000:0:99999:7:::
sshd:!:19000:0:99999:7:::
EOF

cat > "${RUN_DIR}/etc/group" <<'EOF'
root:x:0:
daemon:x:1:
nogroup:x:65534:
sshd:x:74:
users:x:100:
EOF

cat > "${RUN_DIR}/etc/ssh/sshd_config" <<'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
AllowUsers
AuthorizedKeysFile .ssh/authorized_keys
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

: > "${RUN_DIR}/audit.log"
mkdir -p "${RUN_DIR}/home/user_pub_keys"

echo "==> Blast radius setup complete"
echo "    run_id: ${RUN_ID}"
echo "    sandbox: ${RUN_DIR}"
