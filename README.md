# HBS Single-Node Scanner (Homebrew)

A single Podman container that iteratively scans Homebrew formulae with:
- **Static code**: Semgrep, Gitleaks, Bandit (skips bandit if no Python files)
- **Binary/bottle**: ClamAV, YARA (simple rules included), radare2/rabin2 inventory

No P2P, no coordination—just fetch → scan → write reports.

## Build

```bash
docker build --platform=linux/amd64 -t hbs:latest .
````

## Run

Mount a local output dir to collect reports (recommended):

```bash
mkdir -p out
docker run --platform=linux/amd64 --rm -v "$PWD/out:/work" hbs:latest --formula zstd
```

Multiple formulae via a file:

```bash
docker run --platform=linux/amd64 --rm -v "$PWD/out:/work" hbs:latest \
  --formula-file /app/example.list \
  --os x86_64_linux
```

*OS key* picks the bottle; common values:

* `x86_64_linux` (default preference)
* `arm64_ventura`, `ventura`, `arm64_monterey`, `monterey`

## Outputs

For each formula under `/work/<formula>/reports/`:

* `static/semgrep.json` – Semgrep results (OWASP Top 10 ruleset)
* `static/gitleaks.json` – Secrets findings
* `static/bandit.json` – Python security findings (or a `skipped` note)
* `binary/clamscan.log` – ClamAV infected file log lines (if any)
* `binary/yara_matches.txt` – YARA matches
* `binary/rabin2_inventory.jsonl` – Per-binary metadata + strings head

A `manifest.json` summarizes what was scanned.

## Notes & Tips

* **AV signatures**: the entrypoint runs `freshclam` on start. If mirrors are flaky, it won’t crash the job.
* **Semgrep config**: uses `p/owasp-top-ten`. You can change it in `scan.py`.
* **Network**: the container needs egress to fetch formula metadata, sources, bottles, and semgrep rules.
* **Safety**: we don’t execute downloaded binaries—only static scans and metadata extraction.

## Example: scan three formulae

```bash
printf "zstd\nwget\njq\n" > example.list
docker run --platform=linux/amd64 --rm -v "$PWD/out:/work" hbs:latest --formula-file /app/example.list
```

Reports end up in `./out/<formula>/reports`.

