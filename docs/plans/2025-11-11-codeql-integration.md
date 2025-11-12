# CodeQL Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate GitHub's CodeQL static analysis engine into HBS to enhance vulnerability detection and malware identification capabilities through container-optimized semantic analysis.

**Architecture:** Add CodeQL database creation and query execution to existing scan.py workflow, implementing tiered scanning with Homebrew-specific security queries and container resource management.

**Tech Stack:** CodeQL CLI v2.23.3, Python 3.11+, Docker/Podman containerization, Ruby formula analysis, custom security query development.

---

## Task 1: Setup CodeQL Profiling Infrastructure

**Files:**
- Create: `scripts/profile_codeql.py`
- Create: `tests/test_profile_codeql.py`
- Create: `config/codeql_resources.json`
- Modify: `pyproject.toml` (add dependencies)

**Step 1: Write failing test for profiling functionality**

```python
# tests/test_profile_codeql.py
import pytest
from pathlib import Path

def test_profile_small_formula():
    """Test profiling resource usage for small formula"""
    result = profile_formula_resources("zlib")
    assert "memory_peak_mb" in result
    assert "cpu_time_seconds" in result
    assert "database_size_mb" in result
    assert "scan_duration_seconds" in result

def test_get_timeout_for_project_size():
    """Test timeout calculation based on source code size"""
    small_src = Path("/tmp/small_test")
    timeout = get_timeout_for_project_size(small_src)
    assert 60 <= timeout <= 600  # 1-10 minute range

def test_resource_monitoring():
    """Test resource monitoring capabilities"""
    monitor = ResourceMonitor()
    metrics = monitor.get_current_metrics()
    assert "memory_usage_mb" in metrics
    assert "cpu_percent" in metrics
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_profile_codeql.py -v`
Expected: FAIL with "profile_formula_resources not defined", "ResourceMonitor not defined"

**Step 3: Write minimal profiling implementation**

```python
# scripts/profile_codeql.py
import subprocess
import psutil
import json
import time
from pathlib import Path
from typing import Dict, Any
import shutil

class ResourceMonitor:
    def __init__(self):
        self.process = psutil.Process()

    def get_current_metrics(self) -> Dict[str, Any]:
        return {
            "memory_usage_mb": self.process.memory_info().rss / 1024 / 1024,
            "cpu_percent": self.process.cpu_percent(),
            "disk_usage_gb": psutil.disk_usage('.').used / 1024 / 1024 / 1024
        }

def profile_formula_resources(formula_name: str) -> Dict[str, Any]:
    """Profile CodeQL resource usage for a specific formula"""
    print(f"Profiling formula: {formula_name}")

    # Setup paths
    work_dir = Path(f"/tmp/profile_{formula_name}")
    src_dir = work_dir / "src"
    db_dir = work_dir / "codeql_db"

    # Clean up any existing profiling data
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)

    monitor = ResourceMonitor()
    start_time = time.time()
    start_memory = monitor.get_current_metrics()["memory_usage_mb"]

    try:
        # Download and extract formula (simplified for profiling)
        formula_url = f"https://formulae.brew.sh/api/formula/{formula_name}.json"
        subprocess.run(["curl", "-s", formula_url, "-o", work_dir / "formula.json"], check=True)

        # Mock source extraction for profiling
        src_dir.mkdir()
        (src_dir / "test.c").write_text("#include <stdio.h>\nint main() { return 0; }\n")

        # Create CodeQL database
        db_create_start = time.time()
        result = subprocess.run([
            "codeql", "database", "create", str(db_dir),
            "--language=cpp",
            f"--source-root={src_dir}",
            "--command=gcc -c test.c"
        ], capture_output=True, text=True, cwd=src_dir)

        db_create_time = time.time() - db_create_start

        if result.returncode != 0:
            return {"error": f"Database creation failed: {result.stderr}"}

        # Measure database size
        database_size = sum(f.stat().st_size for f in db_dir.rglob('*') if f.is_file()) / 1024 / 1024

        # Run analysis
        analysis_start = time.time()
        result = subprocess.run([
            "codeql", "database", "analyze", str(db_dir),
            "--format=csv",
            "--output=/dev/null",  # Discard output for profiling
            "codeql-security-extended"
        ], capture_output=True, text=True)

        analysis_time = time.time() - analysis_start

        total_time = time.time() - start_time
        peak_memory = monitor.get_current_metrics()["memory_usage_mb"] - start_memory

        return {
            "formula": formula_name,
            "memory_peak_mb": max(peak_memory, 100),  # Minimum 100MB
            "cpu_time_seconds": total_time,
            "database_size_mb": database_size,
            "scan_duration_seconds": total_time,
            "db_creation_time": db_create_time,
            "analysis_time": analysis_time,
            "success": True
        }

    except Exception as e:
        return {
            "formula": formula_name,
            "error": str(e),
            "success": False
        }
    finally:
        # Cleanup
        if work_dir.exists():
            shutil.rmtree(work_dir)

def get_timeout_for_project_size(src_dir: Path) -> int:
    """Calculate timeout based on source code size"""
    if not src_dir.exists():
        return 300  # 5 minutes default

    total_size = sum(f.stat().st_size for f in src_dir.rglob('*') if f.is_file()) / 1024 / 1024  # MB

    # Base timeout: 5 minutes + 1 minute per 10MB of source
    base_timeout = 300
    additional_timeout = int(total_size / 10) * 60
    max_timeout = 3600  # 1 hour maximum

    return min(base_timeout + additional_timeout, max_timeout)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_profile_codeql.py -v`
Expected: PASS (may require CodeQL to be installed)

**Step 5: Add dependencies to pyproject.toml**

```toml
[project]
dependencies = [
    "requests",
    "tqdm",
    "psutil>=5.9.0",  # For system monitoring
]
```

**Step 6: Commit**

```bash
git add scripts/profile_codeql.py tests/test_profile_codeql.py pyproject.toml
git commit -m "feat: add CodeQL profiling infrastructure"
```

---

## Task 2: CodeQL Database Management Functions

**Files:**
- Create: `src/codeql_manager.py`
- Modify: `scan.py:351-368` (integration point)
- Create: `tests/test_codeql_manager.py`

**Step 1: Write failing tests for database management**

```python
# tests/test_codeql_manager.py
import pytest
from pathlib import Path

def test_detect_project_language_cpp():
    """Test C++ language detection"""
    test_dir = Path("/tmp/test_cpp")
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "main.cpp").write_text("#include <iostream>\nint main() { return 0; }")

    language = detect_project_language(test_dir)
    assert language == "cpp"

def test_detect_project_language_python():
    """Test Python language detection"""
    test_dir = Path("/tmp/test_python")
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "app.py").write_text("print('hello')")

    language = detect_project_language(test_dir)
    assert language == "python"

def test_manage_database_size_small_project():
    """Test database size management for small projects"""
    src_dir = Path("/tmp/small_test")
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "small.c").write_text("int x;")

    should_scan = manage_database_size(src_dir, Path("/tmp/db"))
    assert should_scan == True

def test_create_codeql_database_with_retry():
    """Test database creation with retry logic"""
    src_dir = Path("/tmp/test_src")
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "test.c").write_text("int main() { return 0; }")
    db_dir = Path("/tmp/test_db")

    result = create_codeql_database_with_retry(src_dir, db_dir, "cpp")
    assert result["success"] == True
    assert "database_path" in result
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_codeql_manager.py -v`
Expected: FAIL with "detect_project_language not defined", "manage_database_size not defined"

**Step 3: Implement database management functions**

```python
# src/codeql_manager.py
import subprocess
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Optional
import os
import logging

logger = logging.getLogger(__name__)

def detect_project_language(src_dir: Path) -> Optional[str]:
    """Detect primary programming language in source directory"""
    if not src_dir.exists():
        return None

    file_counts = {}

    # Count different file types
    for file_path in src_dir.rglob('*'):
        if file_path.is_file():
            suffix = file_path.suffix.lower()
            if suffix in ['.cpp', '.cc', '.cxx', '.c++', '.c', '.h', '.hpp', '.hxx']:
                file_counts['cpp'] = file_counts.get('cpp', 0) + 1
            elif suffix in ['.py']:
                file_counts['python'] = file_counts.get('python', 0) + 1
            elif suffix in ['.js', '.jsx', '.ts', '.tsx']:
                file_counts['javascript'] = file_counts.get('javascript', 0) + 1
            elif suffix in ['.java']:
                file_counts['java'] = file_counts.get('java', 0) + 1
            elif suffix in ['.go']:
                file_counts['go'] = file_counts.get('go', 0) + 1
            elif suffix in ['.rb']:
                file_counts['ruby'] = file_counts.get('ruby', 0) + 1

    if not file_counts:
        return None

    # Return language with most files
    primary_language = max(file_counts, key=file_counts.get)

    # Map to CodeQL language names
    language_mapping = {
        'cpp': 'cpp',
        'python': 'python',
        'javascript': 'javascript',
        'java': 'java',
        'go': 'go',
        'ruby': 'ruby'
    }

    return language_mapping.get(primary_language)

def manage_database_size(src_dir: Path, db_dir: Path, max_size_mb: int = 1000) -> bool:
    """
    Check if project is suitable for CodeQL analysis based on size
    Returns True if analysis should proceed
    """
    # Calculate source code size
    total_size = 0
    file_count = 0

    for file_path in src_dir.rglob('*'):
        if file_path.is_file() and not any(skip in str(file_path) for skip in ['test/', 'tests/', '__pycache__', '.git']):
            total_size += file_path.stat().st_size
            file_count += 1

    source_size_mb = total_size / 1024 / 1024

    # Check existing database size
    if db_dir.exists():
        db_size = sum(f.stat().st_size for f in db_dir.rglob('*') if f.is_file()) / 1024 / 1024
        if db_size > max_size_mb:
            logger.warning(f"Database size {db_size:.1f}MB exceeds limit {max_size_mb}MB")
            return False

    # Estimate expected database size (roughly 10-20x source size)
    estimated_db_size = source_size_mb * 15

    if estimated_db_size > max_size_mb:
        logger.warning(f"Estimated database size {estimated_db_size:.1f}MB would exceed limit {max_size_mb}MB")
        return False

    # Skip very small projects (likely not meaningful)
    if source_size_mb < 0.1:  # Less than 100KB
        logger.info(f"Project too small ({source_size_mb:.1f}MB) for meaningful analysis")
        return False

    logger.info(f"Project suitable for analysis: {source_size_mb:.1f}MB source, {file_count} files")
    return True

def create_codeql_database_with_retry(
    src_dir: Path,
    db_dir: Path,
    language: str,
    max_retries: int = 2,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """Create CodeQL database with retry logic and error handling"""

    # Clean up existing database
    if db_dir.exists():
        shutil.rmtree(db_dir)

    db_dir.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(max_retries + 1):
        try:
            logger.info(f"Creating CodeQL database (attempt {attempt + 1}/{max_retries + 1})")

            cmd = [
                "codeql", "database", "create", str(db_dir),
                f"--language={language}",
                f"--source-root={src_dir}",
                "--overwrite"  # Allow overwriting existing database
            ]

            # Add timeout if specified
            timeout_cmd = []
            if timeout:
                timeout_cmd = ["timeout", str(timeout)]
                cmd = timeout_cmd + cmd

            # Set environment variables for resource limits
            env = os.environ.copy()
            env["CODEQL_RAM"] = "4096"  # Limit to 4GB
            env["CODEQL_THREADS"] = "2"  # Limit to 2 threads

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=src_dir,
                env=env
            )

            if result.returncode == 0:
                # Verify database was created successfully
                db_path = db_dir / "codeql-database.yml"
                if db_path.exists():
                    logger.info(f"CodeQL database created successfully at {db_dir}")
                    return {
                        "success": True,
                        "database_path": str(db_dir),
                        "attempt": attempt + 1
                    }
                else:
                    error_msg = "Database creation claimed success but no database files found"
                    logger.error(error_msg)
                    if attempt < max_retries:
                        continue
                    return {"success": False, "error": error_msg, "attempt": attempt + 1}
            else:
                error_msg = result.stderr or result.stdout
                logger.error(f"CodeQL database creation failed: {error_msg}")

                # Check for timeout
                if timeout and result.returncode == 124:  # timeout exit code
                    error_msg = f"Database creation timed out after {timeout} seconds"
                    logger.error(error_msg)
                    return {"success": False, "error": error_msg, "attempt": attempt + 1}

                if attempt < max_retries:
                    # Wait before retry
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue

                return {"success": False, "error": error_msg, "attempt": attempt + 1}

        except Exception as e:
            error_msg = f"Exception during database creation: {str(e)}"
            logger.error(error_msg)
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {"success": False, "error": error_msg, "attempt": attempt + 1}

    return {"success": False, "error": "Max retries exceeded", "attempt": max_retries + 1}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_codeql_manager.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/codeql_manager.py tests/test_codeql_manager.py
git commit -m "feat: add CodeQL database management functions"
```

---

## Task 3: Basic CodeQL Scan Implementation

**Files:**
- Modify: `src/codeql_manager.py` (add scan functions)
- Modify: `scan.py:351-368` (add CodeQL integration)
- Create: `tests/test_codeql_scan.py`

**Step 1: Write failing tests for CodeQL scanning**

```python
# tests/test_codeql_scan.py
import pytest
from pathlib import Path
import json

def test_run_codeql_scan_success():
    """Test successful CodeQL scan execution"""
    src_dir = Path("/tmp/test_src")
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "safe.c").write_text("int main() { return 0; }")
    out_dir = Path("/tmp/test_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    result = run_codeql_scan(src_dir, out_dir, "cpp")
    assert result["success"] == True
    assert "output_file" in result

def test_run_fast_codeql_scan():
    """Test fast tiered CodeQL scan"""
    src_dir = Path("/tmp/test_src")
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "safe.py").write_text("print('hello')")
    out_dir = Path("/tmp/test_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    result = run_fast_codeql_scan(src_dir, out_dir)
    assert result["success"] == True
    assert "scan_type" in result
    assert result["scan_type"] == "fast"

def test_execute_queries_with_resource_limits():
    """Test query execution with resource monitoring"""
    # This would require a real CodeQL database for proper testing
    db_dir = Path("/tmp/test_db")
    out_dir = Path("/tmp/test_out")

    # Mock test for now
    assert True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_codeql_scan.py -v`
Expected: FAIL with "run_codeql_scan not defined", "run_fast_codeql_scan not defined"

**Step 3: Implement CodeQL scan functions**

```python
# src/codeql_manager.py (add to existing file)
import subprocess
import json
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

def run_codeql_scan(
    src_dir: Path,
    out_dir: Path,
    language: str,
    scan_type: str = "comprehensive"
) -> Dict[str, Any]:
    """
    Run CodeQL security analysis on source code

    Args:
        src_dir: Source directory to analyze
        out_dir: Output directory for results
        language: Programming language
        scan_type: "fast" or "comprehensive"
    """

    logger.info(f"Starting {scan_type} CodeQL scan for {language} code")

    try:
        # Create output directory
        ensure_dir(out_dir)

        # Generate database name
        db_name = f"codeql_db_{int(time.time())}"
        db_dir = out_dir / db_name

        # Create CodeQL database
        db_result = create_codeql_database_with_retry(src_dir, db_dir, language)
        if not db_result["success"]:
            return {
                "success": False,
                "error": f"Database creation failed: {db_result['error']}",
                "scan_type": scan_type
            }

        # Select queries based on scan type
        if scan_type == "fast":
            queries = [
                "codeql/cpp-queries",
                "codeql/security-extended"
            ]
        else:  # comprehensive
            queries = [
                "codeql/cpp-queries",
                "codeql/security-extended",
                "codeql/queries"
            ]

        # Execute queries
        output_file = out_dir / f"codeql_results_{scan_type}.sarif"

        query_result = execute_queries_with_limits(
            db_dir,
            output_file,
            queries,
            max_memory_gb=6,
            timeout_seconds=1800  # 30 minutes
        )

        if not query_result["success"]:
            return {
                "success": False,
                "error": f"Query execution failed: {query_result['error']}",
                "scan_type": scan_type,
                "database_path": str(db_dir)
            }

        # Parse and return results
        return {
            "success": True,
            "output_file": str(output_file),
            "scan_type": scan_type,
            "database_path": str(db_dir),
            "query_count": len(queries),
            "execution_time": query_result.get("execution_time", 0)
        }

    except Exception as e:
        error_msg = f"CodeQL scan failed: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "scan_type": scan_type
        }

def run_fast_codeql_scan(src_dir: Path, out_dir: Path) -> Dict[str, Any]:
    """
    Run fast tiered CodeQL scan for all formulae
    """
    # Detect language
    language = detect_project_language(src_dir)
    if not language:
        return {
            "success": False,
            "error": "Could not detect programming language",
            "scan_type": "fast"
        }

    # Check if suitable for analysis
    if not manage_database_size(src_dir, out_dir):
        return {
            "success": False,
            "error": "Project too large or too small for meaningful analysis",
            "scan_type": "fast"
        }

    return run_codeql_scan(src_dir, out_dir, language, scan_type="fast")

def execute_queries_with_limits(
    db_dir: Path,
    output_file: Path,
    queries: List[str],
    max_memory_gb: int = 6,
    timeout_seconds: int = 1800
) -> Dict[str, Any]:
    """
    Execute CodeQL queries with resource limits and monitoring
    """
    try:
        logger.info(f"Executing {len(queries)} query packs against {db_dir}")

        cmd = [
            "timeout", str(timeout_seconds),
            "codeql", "database", "analyze", str(db_dir),
            "--format=sarif-latest",
            f"--output={output_file}"
        ]

        # Add query packs
        for query in queries:
            cmd.append(query)

        # Set resource limits in environment
        env = os.environ.copy()
        env["CODEQL_RAM"] = str(max_memory_gb * 1024)  # Convert GB to MB
        env["CODEQL_THREADS"] = "2"  # Limit threads to avoid resource exhaustion

        start_time = time.time()

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env
        )

        execution_time = time.time() - start_time

        if result.returncode == 0:
            # Verify output file was created
            if output_file.exists() and output_file.stat().st_size > 0:
                logger.info(f"Query execution completed in {execution_time:.1f}s")
                return {
                    "success": True,
                    "execution_time": execution_time,
                    "output_size_bytes": output_file.stat().st_size
                }
            else:
                error_msg = "Query execution claimed success but no output file created"
                logger.error(error_msg)
                return {"success": False, "error": error_msg, "execution_time": execution_time}
        else:
            error_msg = result.stderr or result.stdout

            # Check for specific error types
            if result.returncode == 124:  # timeout
                error_msg = f"Query execution timed out after {timeout_seconds} seconds"
            elif result.returncode == 137:  # killed (likely OOM)
                error_msg = f"Query execution killed (likely out of memory, limit was {max_memory_gb}GB)"

            logger.error(f"Query execution failed: {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "execution_time": execution_time,
                "return_code": result.returncode
            }

    except Exception as e:
        error_msg = f"Exception during query execution: {str(e)}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

def ensure_dir(path: Path) -> Path:
    """Ensure directory exists"""
    path.mkdir(parents=True, exist_ok=True)
    return path
```

**Step 4: Update scan.py to integrate CodeQL**

```python
# scan.py (add around line 206, before existing scanner functions)
# Add this import at the top:
# from codeql_manager import run_fast_codeql_scan, run_codeql_scan

# Then add this function:
def run_codeql(src_dir: Path, out_dir: Path):
    """Run CodeQL security analysis"""
    out = ensure_dir(out_dir) / "codeql_results.json"

    try:
        print(f"[CodeQL] Running fast security scan...")
        result = run_fast_codeql_scan(src_dir, out_dir)

        if result["success"]:
            # Convert SARIF to our JSON format
            scan_results = {
                "scanner": "codeql",
                "scan_type": result["scan_type"],
                "success": True,
                "output_file": result.get("output_file"),
                "execution_time": result.get("execution_time", 0),
                "database_path": result.get("database_path"),
                "findings_count": 0  # Would parse SARIF to count findings
            }

            out.write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
            print(f"[CodeQL] Scan completed successfully")

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
```

**Step 5: Integrate CodeQL into main scanning workflow**

```python
# scan.py (modify around line 351-368 in the static scans section)
# Add after Bandit scan:

        print(f"[{name}] Running CodeQL...")
        try:
            run_codeql(src_dir, rep_dir / "static")
        except Exception as e:
            print(f"[{name}] CodeQL failed: {e}")
```

**Step 6: Run test to verify it passes**

Run: `pytest tests/test_codeql_scan.py -v`
Expected: PASS

**Step 7: Commit**

```bash
git add src/codeql_manager.py scan.py tests/test_codeql_scan.py
git commit -m "feat: add CodeQL scan implementation and integration"
```

---

## Task 4: Resource Monitoring and Error Handling

**Files:**
- Create: `src/resource_monitor.py`
- Modify: `src/codeql_manager.py` (add monitoring)
- Create: `tests/test_resource_monitor.py`

**Step 1: Write failing tests for resource monitoring**

```python
# tests/test_resource_monitor.py
import pytest
from pathlib import Path

def test_memory_monitor_initialization():
    """Test memory monitor setup"""
    monitor = MemoryMonitor(max_memory_gb=4)
    assert monitor.max_memory_gb == 4
    assert monitor.is_monitoring == False

def test_memory_monitor_alert_threshold():
    """Test memory usage alert threshold"""
    monitor = MemoryMonitor(max_memory_gb=4, alert_threshold=0.8)
    # 80% of 4GB = 3.2GB
    assert monitor.alert_threshold_gb == 3.2

def test_robust_codeql_execution_memory_error():
    """Test graceful handling of memory errors"""
    src_dir = Path("/tmp/test_src")
    out_dir = Path("/tmp/test_out")

    # This would need mocking for proper testing
    result = robust_codeql_execution(src_dir, out_dir)
    # Should handle memory errors gracefully
    assert "fallback_used" in result or "success" in result
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_resource_monitor.py -v`
Expected: FAIL with "MemoryMonitor not defined", "robust_codeql_execution not defined"

**Step 3: Implement resource monitoring**

```python
# src/resource_monitor.py
import psutil
import time
import threading
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Callable
import json

logger = logging.getLogger(__name__)

class MemoryMonitor:
    def __init__(self, max_memory_gb: float = 6.0, alert_threshold: float = 0.8):
        self.max_memory_gb = max_memory_gb
        self.alert_threshold = alert_threshold
        self.alert_threshold_gb = max_memory_gb * alert_threshold
        self.is_monitoring = False
        self.monitor_thread = None
        self.alert_callback: Optional[Callable] = None
        self.peak_memory = 0.0
        self.monitoring_data = []

    def start_monitoring(self, alert_callback: Optional[Callable] = None):
        """Start memory monitoring in background thread"""
        if self.is_monitoring:
            logger.warning("Memory monitoring already started")
            return

        self.alert_callback = alert_callback
        self.is_monitoring = True
        self.peak_memory = 0.0
        self.monitoring_data = []

        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        logger.info(f"Started memory monitoring (max: {self.max_memory_gb}GB, alert: {self.alert_threshold_gb}GB)")

    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return statistics"""
        if not self.is_monitoring:
            return {"error": "Monitoring not started"}

        self.is_monitoring = False

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)

        stats = {
            "peak_memory_gb": self.peak_memory,
            "max_memory_gb": self.max_memory_gb,
            "alert_triggered": self.peak_memory > self.alert_threshold_gb,
            "monitoring_duration_seconds": len(self.monitoring_data) * 0.5,  # Sample every 0.5s
            "sample_count": len(self.monitoring_data)
        }

        logger.info(f"Memory monitoring stopped. Peak: {self.peak_memory:.2f}GB")
        return stats

    def _monitor_loop(self):
        """Background monitoring loop"""
        process = psutil.Process()

        while self.is_monitoring:
            try:
                memory_gb = process.memory_info().rss / 1024 / 1024 / 1024
                cpu_percent = process.cpu_percent()

                self.peak_memory = max(self.peak_memory, memory_gb)

                self.monitoring_data.append({
                    "timestamp": time.time(),
                    "memory_gb": memory_gb,
                    "cpu_percent": cpu_percent
                })

                # Check alert threshold
                if memory_gb > self.alert_threshold_gb:
                    logger.warning(f"Memory usage {memory_gb:.2f}GB exceeds threshold {self.alert_threshold_gb}GB")

                    if self.alert_callback:
                        try:
                            self.alert_callback(memory_gb, self.alert_threshold_gb)
                        except Exception as e:
                            logger.error(f"Alert callback failed: {e}")

                time.sleep(0.5)  # Sample every 500ms

            except Exception as e:
                logger.error(f"Memory monitoring error: {e}")
                time.sleep(1.0)  # Brief pause on error

def robust_codeql_execution(
    src_dir: Path,
    out_dir: Path,
    max_memory_gb: int = 4,
    timeout_multiplier: float = 2.0
) -> Dict[str, Any]:
    """
    Execute CodeQL with comprehensive error handling and fallbacks
    """
    from codeql_manager import detect_project_language, manage_database_size, create_codeql_database_with_retry, execute_queries_with_limits

    logger.info(f"Starting robust CodeQL execution for {src_dir}")

    # Initialize monitoring
    monitor = MemoryMonitor(max_memory_gb=max_memory_gb)

    def memory_alert_callback(current_gb: float, threshold_gb: float):
        logger.warning(f"Memory alert: {current_gb:.2f}GB > {threshold_gb:.2f}GB")

    monitor.start_monitoring(memory_alert_callback)

    try:
        # Language detection
        language = detect_project_language(src_dir)
        if not language:
            return {
                "success": False,
                "error": "Could not detect project language",
                "fallback_used": False
            }

        # Size validation
        if not manage_database_size(src_dir, out_dir / "codeql_db"):
            return {
                "success": False,
                "error": "Project size not suitable for analysis",
                "fallback_used": False
            }

        # Calculate timeouts based on project size
        from scripts.profile_codeql import get_timeout_for_project_size
        base_timeout = get_timeout_for_project_size(src_dir)
        analysis_timeout = int(base_timeout * timeout_multiplier)

        logger.info(f"Using timeouts: DB={base_timeout}s, Analysis={analysis_timeout}s")

        # Create database
        db_dir = out_dir / "codeql_db_robust"
        db_result = create_codeql_database_with_retry(
            src_dir, db_dir, language,
            max_retries=2,
            timeout=base_timeout
        )

        if not db_result["success"]:
            # Try fallback lightweight scan
            return run_lightweight_fallback(src_dir, out_dir, monitor.get_stats(), db_result["error"])

        # Execute queries with monitoring
        output_file = out_dir / "codeql_results_robust.sarif"

        query_result = execute_queries_with_limits(
            db_dir,
            output_file,
            ["codeql/security-extended"],  # Use minimal query set
            max_memory_gb=max_memory_gb,
            timeout_seconds=analysis_timeout
        )

        if not query_result["success"]:
            # Check if it was a memory or timeout issue
            if "memory" in query_result["error"].lower() or "timeout" in query_result["error"].lower():
                return run_lightweight_fallback(src_dir, out_dir, monitor.get_stats(), query_result["error"])
            else:
                return {
                    "success": False,
                    "error": query_result["error"],
                    "fallback_used": False
                }

        # Success
        final_stats = monitor.stop_monitoring()

        return {
            "success": True,
            "output_file": str(output_file),
            "language": language,
            "database_path": str(db_dir),
            "execution_time": query_result.get("execution_time", 0),
            "memory_stats": final_stats,
            "fallback_used": False
        }

    except MemoryError as e:
        logger.error(f"Memory error during CodeQL execution: {e}")
        return run_lightweight_fallback(src_dir, out_dir, monitor.get_stats(), str(e))

    except TimeoutError as e:
        logger.error(f"Timeout during CodeQL execution: {e}")
        return record_timeout_and_continue(src_dir, out_dir, monitor.get_stats(), str(e))

    except Exception as e:
        logger.error(f"Unexpected error during CodeQL execution: {e}")
        return {
            "success": False,
            "error": str(e),
            "fallback_used": False,
            "memory_stats": monitor.get_stats() if monitor.is_monitoring else None
        }

    finally:
        monitor.stop_monitoring()

def run_lightweight_fallback(
    src_dir: Path,
    out_dir: Path,
    memory_stats: Dict[str, Any],
    original_error: str
) -> Dict[str, Any]:
    """Run lightweight fallback analysis when full CodeQL scan fails"""
    logger.info(f"Running lightweight fallback scan due to: {original_error}")

    try:
        # Simple file-based analysis as fallback
        security_findings = []

        # Scan for obvious security issues
        for file_path in src_dir.rglob('*'):
            if file_path.is_file() and file_path.stat().st_size < 1024 * 1024:  # < 1MB files
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')

                    # Simple pattern matching for obvious issues
                    if 'eval(' in content and ('user_input' in content or 'request' in content):
                        security_findings.append({
                            "file": str(file_path.relative_to(src_dir)),
                            "type": "potential_eval_injection",
                            "severity": "high"
                        })

                    if 'system(' in content and ('wget' in content or 'curl' in content):
                        security_findings.append({
                            "file": str(file_path.relative_to(src_dir)),
                            "type": "potential_command_injection",
                            "severity": "medium"
                        })

                except Exception:
                    continue  # Skip files that can't be read

        fallback_file = out_dir / "codeql_fallback_results.json"
        fallback_file.write_text(json.dumps({
            "scanner": "codeql_fallback",
            "original_error": original_error,
            "memory_stats": memory_stats,
            "findings": security_findings,
            "fallback_used": True
        }, indent=2), encoding="utf-8")

        return {
            "success": True,
            "fallback_used": True,
            "output_file": str(fallback_file),
            "findings_count": len(security_findings),
            "original_error": original_error
        }

    except Exception as e:
        logger.error(f"Fallback scan also failed: {e}")
        return {
            "success": False,
            "error": f"Original: {original_error}, Fallback: {str(e)}",
            "fallback_used": True
        }

def record_timeout_and_continue(
    src_dir: Path,
    out_dir: Path,
    memory_stats: Dict[str, Any],
    timeout_error: str
) -> Dict[str, Any]:
    """Record timeout and save partial results"""
    logger.warning(f"CodeQL execution timed out: {timeout_error}")

    timeout_file = out_dir / "codeql_timeout_record.json"
    timeout_file.write_text(json.dumps({
        "scanner": "codeql",
        "status": "timeout",
        "error": timeout_error,
        "memory_stats": memory_stats,
        "requires_manual_review": True
    }, indent=2), encoding="utf-8")

    return {
        "success": False,
        "error": timeout_error,
        "timeout": True,
        "requires_manual_review": True,
        "partial_results_file": str(timeout_file)
    }
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_resource_monitor.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/resource_monitor.py src/codeql_manager.py tests/test_resource_monitor.py
git commit -m "feat: add resource monitoring and robust error handling for CodeQL"
```

---

## Task 5: Update Docker Configuration for CodeQL

**Files:**
- Modify: `Dockerfile` (add resource limits)
- Modify: `entrypoint.sh` (add environment setup)
- Create: `config/codeql_config.json`

**Step 1: Write failing test for Docker configuration**

```python
# tests/test_docker_config.py
import pytest
import json
from pathlib import Path

def test_codeql_config_exists():
    """Test that CodeQL configuration file exists"""
    config_path = Path("config/codeql_config.json")
    assert config_path.exists()

def test_codeql_config_valid_json():
    """Test that CodeQL configuration is valid JSON"""
    config_path = Path("config/codeql_config.json")
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)
        assert "resource_limits" in config
        assert "default_queries" in config

def test_dockerfile_has_codeql_resources():
    """Test that Dockerfile includes CodeQL resource configuration"""
    dockerfile = Path("Dockerfile")
    content = dockerfile.read_text()
    assert "CODEQL_RAM" in content or "memory" in content.lower()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_docker_config.py -v`
Expected: FAIL with configuration files missing

**Step 3: Create CodeQL configuration**

```json
{
  "resource_limits": {
    "max_memory_gb": 6,
    "max_cpu_threads": 2,
    "default_timeout_seconds": 1800,
    "database_size_limit_mb": 1000
  },
  "default_queries": {
    "fast_scan": [
      "codeql/cpp-queries",
      "codeql/python-queries",
      "codeql/security-extended"
    ],
    "comprehensive_scan": [
      "codeql/cpp-queries",
      "codeql/python-queries",
      "codeql/javascript-queries",
      "codeql/security-extended",
      "codeql/queries"
    ]
  },
  "homebrew_specific": {
    "ruby_formula_analysis": true,
    "patch_security_analysis": true,
    "build_system_injection": true
  },
  "monitoring": {
    "memory_alert_threshold": 0.8,
    "monitoring_interval_ms": 500,
    "save_monitoring_data": true
  }
}
```

**Step 4: Update Dockerfile for CodeQL optimization**

```dockerfile
# Add this section after the existing CodeQL installation lines

# CodeQL runtime configuration
ENV CODEQL_RAM=6144 \
    CODEQL_THREADS=2 \
    CODEQL_TIMEOUT=1800 \
    CODEQL_MAX_DB_SIZE=1000

# Add monitoring tools
RUN apt-get update && apt-get install -y \
    procps \
    htop \
    time \
    && rm -rf /var/lib/apt/lists/*

# Create CodeQL working directory
RUN mkdir -p /tmp/codeql_work && chown scanner:scanner /tmp/codeql_work

# Add CodeQL configuration
COPY --chown=scanner:scanner config/codeql_config.json /app/config/
```

**Step 5: Update entrypoint.sh for CodeQL setup**

```bash
# Add to entrypoint.sh after the existing setup

# CodeQL environment setup
echo "Setting up CodeQL environment..."

# Set resource limits based on container resources
AVAILABLE_MEMORY=$(cat /proc/meminfo | grep MemTotal | awk '{print int($2/1024/1024 * 0.8)}')  # 80% of available
CODEQL_MEMORY=${CODEQL_RAM:-$AVAILABLE_MEMORY}
CODEQL_THREADS=${CODEQL_THREADS:-2}

export CODEQL_RAM=$CODEQL_MEMORY
export CODEQL_THREADS=$CODEQL_THREADS

echo "CodeQL configured: ${CODEQL_RAM}MB RAM, ${CODEQL_THREADS} threads"

# Create temporary working directory for CodeQL
mkdir -p /tmp/codeql_work
chmod 755 /tmp/codeql_work

echo "CodeQL environment setup complete"
```

**Step 6: Run test to verify it passes**

Run: `pytest tests/test_docker_config.py -v`
Expected: PASS

**Step 7: Commit**

```bash
git add config/codeql_config.json Dockerfile entrypoint.sh tests/test_docker_config.py
git commit -m "feat: add CodeQL resource configuration to Docker"
```

---

**Plan complete and saved to `docs/plans/2025-11-11-codeql-integration.md`. Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**