#!/bin/sh
# run.sh <path/to/Electron.app> [rounds]  — exit 0 iff every round relocked first try and saw Esc while locked.
set -eu
APP=$(cd "$1" 2>/dev/null && pwd) || { echo "run.sh: no such directory: $1" >&2; exit 2; }
ROUNDS="${2:-3}"
[ -x "$APP/Contents/MacOS/Electron" ] || { echo "run.sh: not an Electron.app (no Contents/MacOS/Electron): $APP" >&2; exit 2; }
cd "$(dirname "$0")"
ROUNDS="$ROUNDS" exec "$APP/Contents/MacOS/Electron" . 2>/dev/null
