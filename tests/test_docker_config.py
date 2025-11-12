"""Tests for Docker configuration and CodeQL runtime setup."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from hbs.codeql_manager import CodeQLManager


class TestDockerCodeQLConfig:
    """Test CodeQL configuration integration with Docker environment."""

    def test_codeql_config_file_exists_and_valid(self):
        """Test that CodeQL configuration file exists and has valid structure."""
        config_path = Path("/app/config/codeql_config.json")

        # This should fail initially since we haven't created the config yet
        assert config_path.exists(), f"CodeQL config file not found at {config_path}"

        with open(config_path, 'r') as f:
            config = json.load(f)

        # Validate required configuration sections
        required_sections = ["resource_limits", "default_queries", "monitoring"]
        for section in required_sections:
            assert section in config, f"Missing required section: {section}"

        # Validate resource limits
        limits = config["resource_limits"]
        assert limits["max_memory_gb"] == 6
        assert limits["max_cpu_threads"] == 2
        assert limits["default_timeout_seconds"] == 1800
        assert limits["database_size_limit_mb"] == 1000

    def test_environment_variables_are_set(self):
        """Test that required CodeQL environment variables are set."""
        required_vars = [
            "CODEQL_RAM",
            "CODEQL_THREADS",
            "CODEQL_TIMEOUT",
            "CODEQL_MAX_DB_SIZE"
        ]

        for var in required_vars:
            assert var in os.environ, f"Missing environment variable: {var}"
            assert os.environ[var] != "", f"Empty environment variable: {var}"

    @patch('os.cpu_count')
    @patch('psutil.virtual_memory')
    def test_dynamic_memory_calculation(self, mock_memory, mock_cpu):
        """Test dynamic memory calculation based on container resources."""
        # Mock system resources
        mock_cpu.return_value = 4
        mock_memory.return_value = MagicMock(total=8 * 1024 * 1024 * 1024)  # 8GB

        # This should fail initially since we haven't implemented the logic
        expected_memory_gb = int(8 * 0.8)  # 80% of 8GB
        assert os.environ.get("CODEQL_RAM") == str(expected_memory_gb)

    def test_monitoring_tools_available(self):
        """Test that required monitoring tools are installed."""
        monitoring_tools = ["htop", "time", "procinfo"]

        for tool in monitoring_tools:
            # Check if tool is available in PATH
            result = os.system(f"which {tool} > /dev/null 2>&1")
            assert result == 0, f"Monitoring tool {tool} not found in PATH"

    def test_codeql_work_directory_exists(self):
        """Test that CodeQL work directory exists and is writable."""
        work_dir = Path("/tmp/codeql_work")

        assert work_dir.exists(), f"CodeQL work directory not found at {work_dir}"
        assert work_dir.is_dir(), f"CodeQL work path is not a directory: {work_dir}"

        # Test writability by creating a test file
        test_file = work_dir / "test_writable"
        try:
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            pytest.fail(f"CodeQL work directory not writable: {work_dir}")

    def test_default_queries_configuration(self):
        """Test that default queries are properly configured."""
        config_path = Path("/app/config/codeql_config.json")

        with open(config_path, 'r') as f:
            config = json.load(f)

        queries = config["default_queries"]

        # Validate fast scan queries
        assert "fast_scan" in queries
        fast_queries = queries["fast_scan"]
        assert len(fast_queries) > 0
        assert all("-security" in query or "-extended" in query for query in fast_queries)

        # Validate comprehensive scan queries
        assert "comprehensive_scan" in queries
        comp_queries = queries["comprehensive_scan"]
        assert len(comp_queries) >= len(fast_queries)
        assert set(fast_queries).issubset(set(comp_queries))

    @patch('subprocess.run')
    def test_codeql_environment_integration(self, mock_run):
        """Test that CodeQL commands work with the configured environment."""
        # Mock successful CodeQL version check
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "CodeQL CLI 2.23.3\n"

        # Create manager with environment config
        manager = CodeQLManager()

        # Verify that environment variables are used
        assert manager.max_ram_gb == int(os.environ.get("CODEQL_RAM", 6))
        assert manager.max_threads == int(os.environ.get("CODEQL_THREADS", 2))
        assert manager.timeout_seconds == int(os.environ.get("CODEQL_TIMEOUT", 1800))

    def test_docker_resource_constraints_enforced(self):
        """Test that Docker resource constraints match configuration."""
        config_path = Path("/app/config/codeql_config.json")

        with open(config_path, 'r') as f:
            config = json.load(f)

        limits = config["resource_limits"]

        # These should match the Docker resource limits
        memory_limit_gb = limits["max_memory_gb"]
        cpu_limit = limits["max_cpu_threads"]

        # In Docker, we should have access to /sys/fs/cgroup for limits
        if Path("/sys/fs/cgroup/memory/memory.limit_in_bytes").exists():
            with open("/sys/fs/cgroup/memory/memory.limit_in_bytes") as f:
                docker_memory_bytes = int(f.read().strip())
                docker_memory_gb = docker_memory_bytes // (1024**3)

                # Allow some tolerance for system overhead
                assert docker_memory_gb >= memory_limit_gb - 1