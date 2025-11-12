from pathlib import Path
import sys
import os

# Add the scripts directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from profile_codeql import profile_formula_resources, get_timeout_for_project_size, ResourceMonitor

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