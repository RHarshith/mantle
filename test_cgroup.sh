#!/usr/bin/env bash
cg="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
mkdir -p "$cg/agent"
echo "Parent cg: $cg"
echo "Agent cg: $cg/agent"
(
    echo $BASHPID > "$cg/agent/cgroup.procs"
    cat /proc/self/cgroup
)
cat /proc/self/cgroup
