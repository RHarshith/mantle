#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "Setting up legacy_log_processor scenario..."

# Cleanup previous state
if [ -f "teardown.sh" ]; then
    ./teardown.sh 2>/dev/null || true
fi

# Generate the database
echo "Generating logs.db..."
python3 create_db.py

# Start the mock API server
echo "Starting mock API server..."
python3 api_server.py > api_server.log 2>&1 &
echo $! > api_server.pid

# Wait for server to start
sleep 1

if ps -p $(cat api_server.pid) > /dev/null; then
   echo "Setup complete! API running on port 8080."
else
   echo "Failed to start API server. Check api_server.log"
   exit 1
fi
