#!/bin/bash
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
  python3 -m bft app "$@"
else
  echo "Python 3.9 or newer is needed: https://www.python.org/downloads/"
  read -r -p "Press Return to close this window. " _
fi
