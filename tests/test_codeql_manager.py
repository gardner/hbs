from pathlib import Path
import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from codeql_manager import detect_project_language, manage_database_size, create_codeql_database_with_retry

def test_detect_project_language_cpp():
    """Test C++ language detection"""
    test_dir = Path("test_cpp_dir")
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "main.cpp").write_text("#include <iostream>\nint main() { return 0; }")

    language = detect_project_language(test_dir)
    assert language == "cpp"

def test_detect_project_language_python():
    """Test Python language detection"""
    test_dir = Path("test_python_dir")
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "app.py").write_text("print('hello')")

    language = detect_project_language(test_dir)
    assert language == "python"

def test_manage_database_size_small_project():
    """Test database size management for small projects"""
    src_dir = Path("test_small_dir")
    src_dir.mkdir(parents=True, exist_ok=True)
    # Create a larger file to pass the minimum size threshold (>0.1MB = 100KB)
    large_content = "int x;\n" * 20000  # About 120KB
    (src_dir / "small.c").write_text(large_content)

    should_scan = manage_database_size(src_dir, Path("test_db_dir"))
    assert should_scan == True

def test_create_codeql_database_with_retry():
    """Test database creation with retry logic"""
    # Check if CodeQL CLI is available
    import shutil
    codeql_available = shutil.which("codeql") is not None

    src_dir = Path("test_src_dir")
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "test.c").write_text("int main() { return 0; }")
    db_dir = Path("test_db_dir")

    result = create_codeql_database_with_retry(src_dir, db_dir, "cpp")

    if codeql_available:
        # If CodeQL is installed, it should succeed
        assert result["success"] == True
        assert "database_path" in result
    else:
        # If CodeQL is not installed, it should fail gracefully
        assert result["success"] == False
        assert "error" in result
        assert "codeql" in result["error"].lower() or "not found" in result["error"].lower()