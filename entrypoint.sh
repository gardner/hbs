#!/usr/bin/env bash
set -euo pipefail

# Update AV signatures; don't fail the container if mirrors are flaky
if command -v freshclam >/dev/null 2>&1; then
  echo "[entrypoint] Updating ClamAV signatures..."
  freshclam || echo "[entrypoint] freshclam failed or partially updated; continuing."
fi

# Setup CodeQL environment variables based on configuration
echo "[entrypoint] Setting up CodeQL environment..."

# Load CodeQL configuration
if [ -f "/app/config/codeql_config.json" ]; then
  echo "[entrypoint] Loading CodeQL configuration..."

  # Extract resource limits from config
  MAX_MEMORY_GB=$(uv run python3 -c "
import json
with open('/app/config/codeql_config.json') as f:
    config = json.load(f)
print(config['resource_limits']['max_memory_gb'])
")

  MAX_THREADS=$(uv run python3 -c "
import json
with open('/app/config/codeql_config.json') as f:
    config = json.load(f)
print(config['resource_limits']['max_cpu_threads'])
")

  TIMEOUT=$(uv run python3 -c "
import json
with open('/app/config/codeql_config.json') as f:
    config = json.load(f)
print(config['resource_limits']['default_timeout_seconds'])
")

  MAX_DB_SIZE=$(uv run python3 -c "
import json
with open('/app/config/codeql_config.json') as f:
    config = json.load(f)
print(config['resource_limits']['database_size_limit_mb'])
")
else
  # Fallback to defaults if config not found
  echo "[entrypoint] WARNING: CodeQL config not found, using defaults"
  MAX_MEMORY_GB=6
  MAX_THREADS=2
  TIMEOUT=1800
  MAX_DB_SIZE=1000
fi

# Calculate dynamic memory allocation (80% of available memory)
AVAILABLE_MEMORY_GB=$(uv run python3 -c "
try:
    import psutil
    memory_gb = psutil.virtual_memory().total // (1024**3)
    print(int(memory_gb * 0.8))
except ImportError:
    print(4)  # Safe fallback
except Exception:
    print(4)  # Safe fallback
")

# Use the minimum of configured max and available memory
CODEQL_MEMORY_GB=$(uv run python3 -c "print(min($AVAILABLE_MEMORY_GB, $MAX_MEMORY_GB))")

# Detect CPU cores for thread allocation
AVAILABLE_THREADS=$(uv run python3 -c "
try:
    import psutil
    print(psutil.cpu_count())
except ImportError:
    print(2)  # Safe fallback
except Exception:
    print(2)  # Safe fallback
")

# Use the minimum of configured max and available threads
CODEQL_THREADS=$(uv run python3 -c "print(min($AVAILABLE_THREADS, $MAX_THREADS))")

# Set environment variables
export CODEQL_RAM="${CODEQL_MEMORY_GB}"
export CODEQL_THREADS="${CODEQL_THREADS}"
export CODEQL_TIMEOUT="${TIMEOUT}"
export CODEQL_MAX_DB_SIZE="${MAX_DB_SIZE}"
export CODEQL_WORK_DIR="/tmp/codeql_work"

# Verify CodeQL work directory exists and is writable
if [ ! -d "$CODEQL_WORK_DIR" ]; then
  echo "[entrypoint] ERROR: CodeQL work directory $CODEQL_WORK_DIR does not exist"
  exit 1
fi

# Display configuration
echo "[entrypoint] CodeQL Configuration:"
echo "[entrypoint]   Memory: ${CODEQL_RAM}GB"
echo "[entrypoint]   Threads: ${CODEQL_THREADS}"
echo "[entrypoint]   Timeout: ${CODEQL_TIMEOUT}s"
echo "[entrypoint]   Max DB Size: ${CODEQL_MAX_DB_SIZE}MB"
echo "[entrypoint]   Work Directory: ${CODEQL_WORK_DIR}"

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
