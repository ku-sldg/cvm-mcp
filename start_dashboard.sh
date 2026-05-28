#!/bin/bash
cd "$(dirname "$0")"
export PATH="/Users/adampetz/Claude_workspace/bin:/Users/adampetz/Claude_workspace/verus-arm64-macos:/Users/adampetz/Documents/Summer_2025/maestro_repos/cvm/_build/default/theories:$PATH"
LOG_FILE="$(pwd)/dashboard.log"
PIDS=$(lsof -ti :5050)
if [ -n "$PIDS" ]; then
    echo "$PIDS" | xargs kill -9
    echo "Stopped existing dashboard (pid $PIDS)."
fi
# Detach so this script exits in <1s. Useful both for interactive use
# (the parent terminal returns immediately) and for harness invocations
# (no long-lived background task object).
nohup /usr/local/bin/python3 dashboard.py >> "$LOG_FILE" 2>&1 &
NEW_PID=$!
disown $NEW_PID 2>/dev/null || true
echo "Dashboard started (pid $NEW_PID). Logs: $LOG_FILE"
echo "Tail with:  tail -f $LOG_FILE"
