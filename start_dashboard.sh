#!/bin/bash
cd "$(dirname "$0")"
export PATH="/Users/adampetz/Documents/Summer_2025/maestro_repos/cvm/_build/default/theories:$PATH"
PIDS=$(lsof -ti :5050)
if [ -n "$PIDS" ]; then
    echo "$PIDS" | xargs kill -9
    echo "Stopped existing dashboard."
fi
/usr/local/bin/python3 dashboard.py
