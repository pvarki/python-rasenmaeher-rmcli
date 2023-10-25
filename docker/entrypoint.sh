#!/bin/bash -l
set -e
if [ "$#" -eq 0 ]; then
  rmcli --help
else
  exec "$@"
fi
