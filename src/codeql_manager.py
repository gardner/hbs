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