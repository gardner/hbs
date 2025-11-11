#!/usr/bin/env bash
set -euo pipefail

# Update AV signatures; don't fail the container if mirrors are flaky
if command -v freshclam >/dev/null 2>&1; then
  echo "[entrypoint] Updating ClamAV signatures..."
  freshclam || echo "[entrypoint] freshclam failed or partially updated; continuing."
fi

# codeql pack download codeql/cpp-queries & \
#   codeql pack download codeql/python-queries & \
#   codeql pack download codeql/javascript-queries & \
#   codeql pack download codeql/java-queries & \
#   codeql pack download codeql/csharp-queries & \
#   codeql pack download codeql/go-queries & \
#   codeql pack download codeql/ruby-queries & \
#   wait -n


# Hand off to the runner (accepting args for CLI pass-through)
gosu scanner /app/run_scans.sh "$@"
