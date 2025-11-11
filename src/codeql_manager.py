import subprocess
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
import os
import logging
import json

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

        # Select queries based on scan type and language
        if scan_type == "fast":
            if language == "cpp":
                queries = ["codeql/cpp-queries"]
            elif language == "python":
                queries = ["codeql/python-queries"]
            elif language == "javascript":
                queries = ["codeql/javascript-queries"]
            else:
                queries = ["codeql/security-extended"]
        else:  # comprehensive
            if language == "cpp":
                queries = ["codeql/cpp-queries", "codeql/security-extended"]
            elif language == "python":
                queries = ["codeql/python-queries", "codeql/security-extended"]
            elif language == "javascript":
                queries = ["codeql/javascript-queries", "codeql/security-extended"]
            else:
                queries = ["codeql/security-extended", "codeql/queries"]

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