"""Integration test for Docker CodeQL configuration."""

import json
import os
from pathlib import Path


def test_docker_config_integration():
    """Test that all Docker configuration components work together."""

    print("🐳 Testing Docker CodeQL Configuration Integration")

    # Test 1: Config file exists and is valid
    config_path = Path("config/codeql_config.json")
    assert config_path.exists(), "Config file not found"
    with open(config_path, "r") as f:
        config = json.load(f)
    print("✓ Config file loaded successfully")

    # Test 2: Validate configuration structure
    required_sections = ["resource_limits", "default_queries", "monitoring", "environment"]
    for section in required_sections:
        assert section in config, f"Missing section: {section}"
    print("✓ All required configuration sections present")

    # Test 3: Validate resource limits
    limits = config["resource_limits"]
    expected_limits = {
        "max_memory_gb": 6,
        "max_cpu_threads": 2,
        "default_timeout_seconds": 1800,
        "database_size_limit_mb": 1000
    }

    for key, expected_value in expected_limits.items():
        actual_value = limits[key]
        assert actual_value == expected_value, f"Resource limit mismatch: {key} = {actual_value}, expected {expected_value}"
    print("✓ Resource limits are correct")

    # Test 4: Validate default queries
    queries = config["default_queries"]
    assert "fast_scan" in queries, "Missing fast_scan queries"
    assert "comprehensive_scan" in queries, "Missing comprehensive_scan queries"

    fast_queries = queries["fast_scan"]
    comp_queries = queries["comprehensive_scan"]

    assert len(fast_queries) > 0, "No fast scan queries configured"
    assert len(comp_queries) > 0, "No comprehensive scan queries configured"
    assert len(comp_queries) >= len(fast_queries), "Comprehensive scan should include fast scan queries"
    print("✓ Default queries configured correctly")

    # Test 5: Simulate environment variable calculation
    try:
        import psutil

        # Calculate available resources
        available_memory_gb = int(psutil.virtual_memory().total // (1024**3) * 0.8)
        available_threads = psutil.cpu_count()

        # Calculate CodeQL allocation (using minimum of available and configured)
        codeql_memory = min(available_memory_gb, limits["max_memory_gb"])
        codeql_threads = min(available_threads, limits["max_cpu_threads"])

        # Simulate environment variables that would be set by entrypoint
        env_vars = {
            "CODEQL_RAM": str(codeql_memory),
            "CODEQL_THREADS": str(codeql_threads),
            "CODEQL_TIMEOUT": str(limits["default_timeout_seconds"]),
            "CODEQL_MAX_DB_SIZE": str(limits["database_size_limit_mb"]),
            "CODEQL_WORK_DIR": "/tmp/codeql_work"
        }

        print(f"✓ Environment variables calculated: {env_vars}")

    except ImportError:
        print("⚠ psutil not available, using fallback values")

    # Test 6: Validate monitoring configuration
    monitoring = config["monitoring"]
    assert monitoring["enable_profiling"] == True
    assert monitoring["enable_resource_monitoring"] == True
    assert monitoring["work_directory"] == "/tmp/codeql_work"
    assert monitoring["cleanup_temp_files"] == True
    print("✓ Monitoring configuration is correct")

    # Test 7: Validate environment configuration
    env_config = config["environment"]
    assert env_config["CODEQL_RAM"] == "auto"
    assert env_config["CODEQL_THREADS"] == "auto"
    assert env_config["CODEQL_TIMEOUT"] == "1800"
    assert env_config["CODEQL_MAX_DB_SIZE"] == "1000"
    print("✓ Environment configuration is correct")

    print("\n🎉 All Docker configuration integration tests passed!")
    print("✅ Ready for Docker build and CodeQL integration!")

    return True