#!/usr/bin/env bash
set -euo pipefail

# Simple wrapper for nicer ergonomics and defaults
# Examples:
#   podman run --rm -v $PWD/out:/work scanner:latest --formula zstd
#   podman run --rm -v $PWD/out:/work scanner:latest --formula-file /app/example.list --os x86_64_linux

uv run /app/scan.py "$@"

