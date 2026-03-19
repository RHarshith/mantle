#!/usr/bin/env bash
# Precondition verification for the taint analysis test scenario.
set -euo pipefail

PASS=true

echo "==> Verifying taint analysis test prerequisites..."

# Check vulnerable app.
if curl -sf http://localhost:19090/health > /dev/null 2>&1; then
    echo "    ✅ Vulnerable app reachable on port 19090"
else
    echo "    ❌ Vulnerable app NOT reachable on port 19090" >&2
    PASS=false
fi

# Check mock MCP server.
if curl -sf http://localhost:19091/health > /dev/null 2>&1; then
    echo "    ✅ Mock MCP server reachable on port 19091"
else
    echo "    ❌ Mock MCP server NOT reachable on port 19091" >&2
    PASS=false
fi

# Check that the vulnerable app serves data.
if curl -sf http://localhost:19090/api/data | grep -q "external_input" 2>/dev/null; then
    echo "    ✅ Vulnerable app /api/data returns expected data"
else
    echo "    ❌ Vulnerable app /api/data not returning expected data" >&2
    PASS=false
fi

if [ "$PASS" = true ]; then
    echo "==> All prerequisites met."
    exit 0
else
    echo "==> Some prerequisites are missing. Run setup.sh first." >&2
    exit 1
fi
