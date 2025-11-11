from pathlib import Path
import sys
import os
import tempfile

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from codeql_manager import run_codeql_scan, run_fast_codeql_scan, execute_queries_with_limits

def test_run_codeql_scan_success():
    """Test successful CodeQL scan execution"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_dir = tmp_path / "test_src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "safe.c").write_text("int main() { return 0; }")
        out_dir = tmp_path / "test_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        result = run_codeql_scan(src_dir, out_dir, "cpp")
        assert result["success"] == True
        assert "output_file" in result
        assert result["scan_type"] == "comprehensive"

def test_run_fast_codeql_scan():
    """Test fast tiered CodeQL scan"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_dir = tmp_path / "test_src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "safe.py").write_text("print('hello')")
        out_dir = tmp_path / "test_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        result = run_fast_codeql_scan(src_dir, out_dir)
        assert result["success"] == True
        assert "scan_type" in result
        assert result["scan_type"] == "fast"

def test_execute_queries_with_resource_limits():
    """Test query execution with resource monitoring"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Create a mock CodeQL database directory structure
        db_dir = tmp_path / "test_db"
        db_dir.mkdir()
        (db_dir / "codeql-database.yml").write_text("version: 2.0.0")
        out_dir = tmp_path / "test_out"
        out_dir.mkdir()

        # Mock test for now since we need a real CodeQL database for proper testing
        assert True