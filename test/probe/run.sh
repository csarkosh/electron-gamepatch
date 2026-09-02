#!/bin/sh
# run.sh <path/to/Electron.app> [rounds]  — exit 0 iff every round relocked first try and saw Esc while locked.
set -eu
APP="$1"; ROUNDS="${2:-3}"
cd "$(dirname "$0")"
ROUNDS="$ROUNDS" exec "$APP/Contents/MacOS/Electron" . 2>/dev/null
