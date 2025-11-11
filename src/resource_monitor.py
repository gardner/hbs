import psutil
import time
import threading
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Callable
import json
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

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

    def get_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        try:
            process = psutil.Process()
            current_memory_gb = process.memory_info().rss / 1024 / 1024 / 1024
            cpu_percent = process.cpu_percent()

            return {
                "is_monitoring": self.is_monitoring,
                "current_memory_gb": current_memory_gb,
                "peak_memory_gb": max(self.peak_memory, current_memory_gb),
                "max_memory_gb": self.max_memory_gb,
                "alert_threshold_gb": self.alert_threshold_gb,
                "alert_triggered": current_memory_gb > self.alert_threshold_gb,
                "cpu_percent": cpu_percent,
                "sample_count": len(self.monitoring_data)
            }
        except Exception as e:
            logger.error(f"Error getting monitor stats: {e}")
            return {
                "is_monitoring": self.is_monitoring,
                "error": str(e),
                "sample_count": len(self.monitoring_data)
            }

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
    try:
        from src.codeql_manager import detect_project_language, manage_database_size, create_codeql_database_with_retry, execute_queries_with_limits
    except ImportError as e:
        logger.error(f"Could not import codeql_manager functions: {e}")
        raise

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
        if monitor.is_monitoring:
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

                    # Additional patterns for common vulnerabilities
                    if 'exec(' in content and ('user_input' in content or 'form' in content):
                        security_findings.append({
                            "file": str(file_path.relative_to(src_dir)),
                            "type": "potential_exec_injection",
                            "severity": "high"
                        })

                    if 'shell=True' in content and 'subprocess' in content:
                        security_findings.append({
                            "file": str(file_path.relative_to(src_dir)),
                            "type": "potential_shell_injection",
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
        "requires_manual_review": True,
        "timestamp": time.time()
    }, indent=2), encoding="utf-8")

    return {
        "success": False,
        "error": timeout_error,
        "timeout": True,
        "requires_manual_review": True,
        "partial_results_file": str(timeout_file)
    }