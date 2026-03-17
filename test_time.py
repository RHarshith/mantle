import time
import subprocess

offset = time.time() - time.clock_gettime(time.CLOCK_MONOTONIC)
print("Offset:", offset)

cmd = ["sudo", "bpftrace", "-e", "BEGIN { printf(\"%llu\\n\", nsecs); exit(); }"]
proc = subprocess.run(cmd, capture_output=True, text=True)
nsecs = 0
for line in proc.stdout.splitlines():
    if line.isdigit():
        nsecs = int(line)
        break
print("bpftrace nsecs:", nsecs)
print("bpftrace epoch:", (nsecs / 1e9) + offset)
print("python time:", time.time())
