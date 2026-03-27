#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "Tearing down legacy_log_processor scenario..."

if [ -f "api_server.pid" ]; then
    PID=$(cat api_server.pid)
    if ps -p $PID > /dev/null; then
        echo "Killing API server (PID $PID)..."
        kill $PID
    fi
    rm api_server.pid
fi

# Clean up generated files
rm -rf ~/legacy_log_processor_test_env
rm -f api_server.log
rm -f report_generator.py # Agent's output

echo "Teardown complete."
