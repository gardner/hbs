#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Optional, Tuple


import requests
from tqdm import tqdm

# Import CodeQL SARIF parsing
try:
    from src.codeql_manager import parse_sarif_findings
except ImportError:
    # Fallback for when src is not in path
    sys.path.append(str(Path(__file__).parent / "src"))
    try:
        from codeql_manager import parse_sarif_findings
    except ImportError:
        # If still not available, define a stub function
        def parse_sarif_findings(sarif_file):
            return {"findings_count": 0, "error": "SARIF parsing not available"}


API_FORMULA = "https://formulae.brew.sh/api/formula/{name}.json"


# --------------------------
# Shell helpers
# --------------------------

def sh(cmd, cwd=None, capture=False, check=False):
    if capture:
        return subprocess.run(cmd, cwd=cwd, shell=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)
    else:
        return subprocess.run(cmd, cwd=cwd, shell=True, check=check)


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------
# HTTP download helpers
# --------------------------

def _stream_to_file(r: requests.Response, dest: Path, desc: str):
    total = int(r.headers.get("Content-Length", 0))
    with open(dest, "wb") as f, tqdm(total=total, unit="B", unit_scale=True, desc=desc) as pbar:
        for chunk in r.iter_content(chunk_size=1 << 20):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))


def _parse_www_authenticate(h: str) -> dict:
    # Example: Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:homebrew/core/zstd:pull"
    out = {}
    if not h:
        return out
    # Only support Bearer style here
    parts = h.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        for kv in parts[1].split(","):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k] = v.strip('"')
    return out


def download_ghcr_blob(url: str, dest: Path, expected_sha256: Optional[str], desc: str):
    # 1) probe to get WWW-Authenticate challenge
    probe = requests.get(url, timeout=30, allow_redirects=False)
    if probe.status_code == 200:
        # Rare, but just stream it
        _stream_to_file(probe, dest, desc)
    elif probe.status_code in (401, 403):
        wa = probe.headers.get("WWW-Authenticate") or probe.headers.get("Www-Authenticate")
        params = _parse_www_authenticate(wa)
        realm = params.get("realm")
        service = params.get("service")
        scope = params.get("scope")
        if not (realm and service and scope):
            raise RuntimeError(f"GHCR auth challenge missing fields: {wa}")

        # 2) fetch bearer token
        tok_resp = requests.get(realm, params={"service": service, "scope": scope}, timeout=30)
        tok_resp.raise_for_status()
        token = tok_resp.json().get("token") or tok_resp.json().get("access_token")
        if not token:
            raise RuntimeError("Failed to obtain GHCR bearer token")

        # 3) fetch blob with Authorization
        headers = {
            "Authorization": f"Bearer {token}",
            # Accept common layer types
            "Accept": ",".join([
                "application/vnd.oci.image.layer.v1.tar+gzip",
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "application/octet-stream",
            ]),
        }
        with requests.get(url, headers=headers, timeout=300, stream=True) as r:
            r.raise_for_status()
            _stream_to_file(r, dest, desc)
    else:
        probe.raise_for_status()

    # verify sha if provided
    if expected_sha256:
        got = sha256_file(dest)
        if got.lower() != expected_sha256.lower():
            raise RuntimeError(f"SHA256 mismatch for {dest.name}: got {got}, expected {expected_sha256}")
    return dest


def download(url: str, dest: Path, expected_sha256: Optional[str] = None, desc: str = "download"):
    dest.parent.mkdir(parents=True, exist_ok=True)

    # GHCR blob? Use OCI flow
    if url.startswith("https://ghcr.io/v2/"):
        return download_ghcr_blob(url, dest, expected_sha256, desc)

    # Plain HTTP(S)
    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        _stream_to_file(r, dest, desc)
    if expected_sha256:
        got = sha256_file(dest)
        if got.lower() != expected_sha256.lower():
            raise RuntimeError(f"SHA256 mismatch for {dest.name}: got {got}, expected {expected_sha256}")
    return dest


# --------------------------
# Archive helpers
# --------------------------

def untar(archive: Path, dst_dir: Path):
    ensure_dir(dst_dir)
    with tarfile.open(archive, "r:*") as tar:
        # future-proof: filter="data" avoids writing special files
        try:
            tar.extractall(path=dst_dir, filter="data")
        except TypeError:
            # Python <3.12 compatibility
            tar.extractall(path=dst_dir)
    return dst_dir


# --------------------------
# Homebrew formula helpers
# --------------------------

def fetch_formula_meta(name: str) -> dict:
    url = API_FORMULA.format(name=name)
    r = requests.get(url, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to fetch formula metadata for {name}: HTTP {r.status_code}")
    return r.json()


def choose_bottle(meta: dict, os_key: Optional[str]) -> Optional[Tuple[str, str]]:
    try:
        files = meta["bottle"]["stable"]["files"]
    except KeyError:
        return None
    if not files:
        return None
    if os_key and os_key in files:
        info = files[os_key]
        return info["url"], info["sha256"]
    for k in ["x86_64_linux", "arm64_ventura", "ventura", "arm64_monterey", "monterey"]:
        if k in files:
            info = files[k]
            return info["url"], info["sha256"]
    k, info = next(iter(files.items()))
    return info["url"], info["sha256"]


def gather_sources(meta: dict) -> Optional[Tuple[str, Optional[str]]]:
    try:
        st = meta["urls"]["stable"]
        return st["url"], st.get("sha256")
    except KeyError:
        return None


# --------------------------
# Scanners
# --------------------------

# Import CodeQL manager functions
try:
    from src.codeql_manager import run_fast_codeql_scan, run_codeql_scan
except ImportError:
    # Fallback if src module not available in current environment
    run_fast_codeql_scan = None
    run_codeql_scan = None


def detect_python(src_dir: Path) -> bool:
    for root, _, files in os.walk(src_dir):
        for fn in files:
            if fn.endswith(".py"):
                return True
    return False


def run_semgrep(src_dir: Path, out_dir: Path):
    out = ensure_dir(out_dir) / "semgrep.json"
    cmd = f"semgrep --quiet --config=p/owasp-top-ten --json --no-git-ignore --timeout=120 {shlex(src_dir)}"
    res = sh(cmd, capture=True)
    out.write_text(res.stdout, encoding="utf-8")


def run_gitleaks(src_dir: Path, out_dir: Path):
    out = ensure_dir(out_dir) / "gitleaks.json"
    cmd = f"gitleaks detect -s {shlex(src_dir)} -f json -r {shlex(out)} --no-banner --exit-code 0"
    sh(cmd, check=False)


def run_bandit(src_dir: Path, out_dir: Path):
    out = ensure_dir(out_dir) / "bandit.json"
    if not detect_python(src_dir):
        out.write_text(json.dumps({"skipped": "no_python_files_found"}), encoding="utf-8")
        return
    cmd = f"bandit -r {shlex(src_dir)} -f json -o {shlex(out)} || true"
    sh(cmd, check=False)


def run_clamav(bin_dir: Path, out_dir: Path):
    log = ensure_dir(out_dir) / "clamscan.log"
    dbdir = os.environ.get("CLAM_DB", "/var/lib/clamav")
    cmd = f"clamscan -r --infected --no-summary --database={shlex(dbdir)} {shlex(bin_dir)}"
    res = sh(cmd, capture=True, check=False)
    log.write_text(res.stdout, encoding="utf-8")


def run_yara(bin_dir: Path, out_dir: Path, rules_dir: Path):
    out = ensure_dir(out_dir) / "yara_matches.txt"
    cmd = f"yara -r {shlex(rules_dir)} {shlex(bin_dir)}"
    res = sh(cmd, capture=True, check=False)
    out.write_text(res.stdout, encoding="utf-8")


def run_codeql(src_dir: Path, out_dir: Path):
    """Run CodeQL security analysis"""
    out = ensure_dir(out_dir) / "codeql_results.json"

    try:
        if run_fast_codeql_scan is None:
            # CodeQL manager not available, skip scan
            error_results = {
                "scanner": "codeql",
                "success": False,
                "error": "CodeQL manager not available",
                "scan_type": "unknown"
            }
            out.write_text(json.dumps(error_results, indent=2), encoding="utf-8")
            print("[CodeQL] CodeQL manager not available, skipping scan")
            return

        print("[CodeQL] Running fast security scan...")
        result = run_fast_codeql_scan(src_dir, out_dir)

        if result["success"]:
            # Parse SARIF file to get actual findings count
            output_file = result.get("output_file")
            findings_data = {"findings_count": 0}

            if output_file:
                sarif_file = Path(output_file)
                findings_data = parse_sarif_findings(sarif_file)

            # Convert SARIF to our JSON format
            scan_results = {
                "scanner": "codeql",
                "scan_type": result["scan_type"],
                "success": True,
                "output_file": output_file,
                "execution_time": result.get("execution_time", 0),
                "database_path": result.get("database_path"),
                "findings_count": findings_data.get("findings_count", 0),
                "sarif_parsing_error": findings_data.get("error"),
                "severity_breakdown": findings_data.get("severity_breakdown"),
                "rule_breakdown": findings_data.get("rule_breakdown")
            }

            out.write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
            print("[CodeQL] Scan completed successfully")

        else:
            error_results = {
                "scanner": "codeql",
                "success": False,
                "error": result.get("error", "Unknown error"),
                "scan_type": result.get("scan_type", "unknown")
            }
            out.write_text(json.dumps(error_results, indent=2), encoding="utf-8")
            print(f"[CodeQL] Scan failed: {result.get('error')}")

    except Exception as e:
        error_results = {
            "scanner": "codeql",
            "success": False,
            "error": str(e),
            "scan_type": "unknown"
        }
        out.write_text(json.dumps(error_results, indent=2), encoding="utf-8")
        print(f"[CodeQL] Scan failed with exception: {e}")


def list_binaries(root: Path):
    candidates = []
    for p in root.rglob("*"):
        if p.is_file():
            try:
                st = p.stat()
                if (st.st_mode & 0o111):
                    candidates.append(p)
                    continue
            except Exception:
                pass
            try:
                r = sh(f"file -b {shlex(p)}", capture=True)
                if "ELF" in r.stdout or "Mach-O" in r.stdout:
                    candidates.append(p)
            except Exception:
                pass
    return candidates


def run_rabin2(bin_dir: Path, out_dir: Path):
    out_json = ensure_dir(out_dir) / "rabin2_inventory.jsonl"
    with out_json.open("w", encoding="utf-8") as w:
        for b in list_binaries(bin_dir):
            info = {"path": str(b)}
            r1 = sh(f"rabin2 -I {shlex(b)}", capture=True, check=False)
            info["meta"] = r1.stdout
            r2 = sh(f"rabin2 -zz {shlex(b)} | head -n 500", capture=True, check=False)
            info["strings_head"] = r2.stdout
            w.write(json.dumps(info) + "\n")


def shlex(p: Path | str) -> str:
    s = str(p)
    if re.search(r"[^\w@%+=:,./-]", s):
        return "'" + s.replace("'", "'\"'\"'") + "'"
    return s


# --------------------------
# Main
# --------------------------

def main():
    ap = argparse.ArgumentParser(description="HBS single-node Homebrew scanner")
    ap.add_argument("--formula", help="Single Homebrew formula name")
    ap.add_argument("--formula-file", help="File with one formula per line")
    ap.add_argument("--os", default=None, help="Bottle OS key (e.g., x86_64_linux, arm64_ventura)")
    ap.add_argument("--workdir", default="/work", help="Working directory (mounted volume)")
    args = ap.parse_args()

    formulas = []
    if args.formula:
        formulas.append(args.formula.strip())
    if args.formula_file:
        with open(args.formula_file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    formulas.append(s)
    if not formulas:
        print("Provide --formula or --formula-file", file=sys.stderr)
        sys.exit(2)

    work = Path(args.workdir)
    ensure_dir(work)
    rules_dir = Path("/app/rules")

    for name in formulas:
        print(f"\n=== {name} ===")
        meta = fetch_formula_meta(name)

        pkg_dir = ensure_dir(work / name)
        src_dir = ensure_dir(pkg_dir / "src")
        bin_dir = ensure_dir(pkg_dir / "bottle")
        rep_dir = ensure_dir(pkg_dir / "reports")

        # Source tarball
        src_info = gather_sources(meta)
        if src_info:
            src_url, src_sha = src_info
            src_archive = pkg_dir / "source.tar"
            print(f"[{name}] Downloading source: {src_url}")
            download(src_url, src_archive, expected_sha256=src_sha or None, desc=f"{name}:source")
            print(f"[{name}] Extracting source...")
            try:
                untar(src_archive, src_dir)
            except tarfile.ReadError:
                print(f"[{name}] Source extraction failed; leaving as archive.")
        else:
            print(f"[{name}] No stable source URL in metadata.")

        # Bottle (OCI blob on GHCR)
        bsel = choose_bottle(meta, args.os)
        if bsel:
            bottle_url, bottle_sha = bsel
            bottle_archive = pkg_dir / "bottle.tar.gz"
            print(f"[{name}] Downloading bottle: {bottle_url}")
            download(bottle_url, bottle_archive, expected_sha256=bottle_sha, desc=f"{name}:bottle")
            print(f"[{name}] Extracting bottle...")
            try:
                untar(bottle_archive, bin_dir)
            except tarfile.ReadError:
                print(f"[{name}] Bottle extraction failed; leaving as archive.")
        else:
            print(f"[{name}] No bottle found for requested OS; binary scans may be limited.")

        # Static scans
        if any(src_dir.iterdir()):
            print(f"[{name}] Running Semgrep...")
            try:
                run_semgrep(src_dir, rep_dir / "static")
            except Exception as e:
                print(f"[{name}] Semgrep failed: {e}")
            print(f"[{name}] Running Gitleaks...")
            try:
                run_gitleaks(src_dir, rep_dir / "static")
            except Exception as e:
                print(f"[{name}] Gitleaks failed: {e}")
            print(f"[{name}] Running Bandit...")
            try:
                run_bandit(src_dir, rep_dir / "static")
            except Exception as e:
                print(f"[{name}] Bandit failed: {e}")
            print(f"[{name}] Running CodeQL...")
            try:
                run_codeql(src_dir, rep_dir / "static")
            except Exception as e:
                print(f"[{name}] CodeQL failed: {e}")
        else:
            print(f"[{name}] Skipping static scans (no extracted source).")

        # Binary scans
        if any(bin_dir.iterdir()):
            print(f"[{name}] Running ClamAV on bottle...")
            try:
                run_clamav(bin_dir, rep_dir / "binary")
            except Exception as e:
                print(f"[{name}] ClamAV failed: {e}")
            print(f"[{name}] Running YARA on bottle...")
            try:
                run_yara(bin_dir, rep_dir / "binary", rules_dir)
            except Exception as e:
                print(f"[{name}] YARA failed: {e}")
            print(f"[{name}] Running rabin2 inventory...")
            try:
                run_rabin2(bin_dir, rep_dir / "binary")
            except Exception as e:
                print(f"[{name}] rabin2 failed: {e}")
        else:
            print(f"[{name}] Skipping binary scans (no extracted bottle).")

        manifest = {
            "formula": name,
            "workdir": str(pkg_dir),
            "reports": str(rep_dir),
            "source_present": any(src_dir.iterdir()),
            "bottle_present": any(bin_dir.iterdir()),
        }
        (pkg_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("\nDone. Reports under /work/<formula>/reports/")


if __name__ == "__main__":
    main()
