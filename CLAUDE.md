# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HBS (Homebrew Scanner) is a single-node Podman container that performs security scans on Homebrew formulae. It downloads formula source code and binary bottles, then runs multiple security scanning tools in parallel.

**Key Architecture Components:**

- **scan.py**: Core Python script (404 lines) that orchestrates the entire scanning workflow
- **Dockerfile**: Multi-stage container build with security tools pre-installed
- **Security tools**: Semgrep (OWASP Top 10), Gitleaks, Bandit, ClamAV, YARA, rabin2
- **Output structure**: `/work/<formula>/reports/` with organized subdirectories

## Development Commands

### Building and Running
```bash
# Build container
podman build -t hbs:latest .

# Run single formula scan
podman run --rm -v "$PWD/out:/work" hbs:latest --formula zstd

# Run multiple formulae from file
podman run --rm -v "$PWD/out:/work" hbs:latest --formula-file /app/example.list --os x86_64_linux
```

### Local Development
```bash
# Install dependencies with uv
uv sync

# Run scan locally (for testing)
uv run scan.py --formula zstd --workdir ./test-output

# Update dependencies
uv add <package_name>
```

## Code Architecture

**Core Workflow (scan.py):**
1. **Metadata fetching**: Uses Homebrew API at `https://formulae.brew.sh/api/formula/{name}.json`
2. **Download phase**: Fetches source tarballs and binary bottles from GHCR with SHA256 verification
3. **Extraction**: Safely extracts tarballs using `filter="data"` for security
4. **Scanning phase**: Runs parallel security scans on source and binaries
5. **Reporting**: Generates structured JSON reports in organized directories

**Key Functions:**
- `fetch_formula_meta()`: API integration with Homebrew formulae service
- `download_ghcr_blob()`: Handles OCI authentication for GitHub Container Registry
- `run_*_scan()` functions: Individual tool wrappers with error handling
- `list_binaries()`: Smart binary detection using file permissions and `file` command

**Security Considerations:**
- All downloads use SHA256 verification
- Container runs as unprivileged `scanner` user
- Archive extraction uses safe filtering
- No execution of downloaded binaries (only static analysis)

## Important Implementation Details

- **Error handling**: Individual scanner failures don't stop the entire workflow
- **Network**: Requires egress for Homebrew API, GHCR, and tool downloads
- **Storage**: Uses mounted volume at `/work` for persistent reports
- **Authentication**: Implements OAuth Bearer token flow for GHCR access
- **Python detection**: Automatically skips Bandit scan if no Python files found

## YARA Rules

Custom malware detection rules are stored in `rules/malware_index.yar`. These are used by the YARA scanner for binary analysis.

## Testing Environment

The project is designed to run exclusively in Docker. Local testing requires:
- All security tools installed (ClamAV, YARA, etc.)
- Proper directory permissions
- Network access for downloads