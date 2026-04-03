#!/bin/bash
cd "$(dirname "$0")"
PIDS=$(lsof -ti :5050)
if [ -n "$PIDS" ]; then
    echo "$PIDS" | xargs kill -9
    echo "Stopped existing dashboard."
fi
python3 dashboard.py
