#!/bin/bash
PIDS=$(lsof -ti :5050)
if [ -n "$PIDS" ]; then
    echo "$PIDS" | xargs kill -9
    echo "Dashboard killed."
else
    echo "Dashboard not running."
fi
