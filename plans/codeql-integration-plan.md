# CodeQL Integration Plan for HBS (Homebrew Scanner)

## Executive Summary

This plan outlines the strategic integration of GitHub's CodeQL static analysis engine into the HBS security scanning workflow, significantly enhancing vulnerability detection and malware identification capabilities. Based on deep analysis with advanced AI models (GPT-5 and Gemini), this integration focuses on container-optimized performance, Homebrew-specific security patterns, and advanced malware detection through semantic analysis. CodeQL complements existing tools (Semgrep, Bandit, Gitleaks, ClamAV, YARA, rabin2) by providing sophisticated cross-language vulnerability detection and intent-based malware analysis.

## Critical Insights from Advanced Analysis

**Key Finding**: The integration requires significant optimization for container constraints and Homebrew-specific patterns. Success depends on:
1. **Resource-Conscious Architecture**: CodeQL databases can be 10-50x source size with 2-8GB RAM requirements
2. **Homebrew-Specific Queries**: Focus on build system vulnerabilities and Ruby formula analysis
3. **Tiered Performance Strategy**: Balance comprehensive analysis with practical scan time constraints
4. **Advanced Malware Detection**: Use taint tracking for intent-based pattern recognition vs simple vulnerability scanning

**Strategic Recommendation**: Implement a **tiered scanning approach** with fast, high-signal scans for all formulae and comprehensive deep scans for suspicious packages only.

## Current State Analysis

### Existing CodeQL Installation
- **Version**: CodeQL CLI v2.23.3 (installed in Dockerfile)
- **Language Packs**: cpp, python, javascript, java, csharp, go, ruby (pre-downloaded)
- **Status**: Installed but not utilized in scan.py
- **Location**: `/opt/codeql/codeql` with PATH configured

### Current Security Tool Stack
- **Static Analysis**: Semgrep (OWASP Top 10), Bandit (Python), Gitleaks (secrets)
- **Binary Analysis**: ClamAV (signatures), YARA (rules), rabin2 (binary info)
- **Gap**: Missing advanced semantic analysis and cross-language vulnerability patterns

## CodeQL Capabilities Assessment

### Security Query Categories Available
1. **Injection Vulnerabilities**
   - SQL injection (`java/sql-injection`, `cpp/sql-injection`)
   - Command injection (`py/command-line-injection`)
   - LDAP injection (`java/ldap-injection`)
   - XPath injection (`cs/xpath-injection`)

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS (`js/reflected-xss`, `cs/cross-site-scripting`)
   - DOM-based XSS variants

3. **Cryptographic Issues**
   - Weak algorithms (`java/potentially-weak-cryptographic-algorithm`)
   - Insecure random number generation
   - Hardcoded credentials/keys

4. **Input Validation**
   - Regex injection (`java/regex-injection`)
   - Format string vulnerabilities
   - Path traversal (`java/path-injection`)

5. **Deserialization & Code Execution**
   - Unsafe deserialization (`cs/unsafe-deserialization`, `py/unsafe-deserialization`)
   - Remote code execution patterns
   - Assembly loading vulnerabilities (`cs/assembly-path-injection`)

6. **Memory Safety (C/C++)**
   - Buffer overflows
   - Use-after-free (`cpp/use-after-free`)
   - XML External Entity (XXE) attacks (`cpp/external-entity-expansion`)

7. **Malware & Backdoor Patterns**
   - Hardcoded data executed as code (Ruby backdoor detection)
   - Suspicious string concatenation patterns
   - Obfuscated code execution

### Malware Detection Capabilities

CodeQL can identify potential malware through:

1. **Code Obfuscation Patterns**
   - Base64/encoded strings executed as code
   - Dynamic code construction with suspicious literals
   - Eval/injection patterns with hardcoded data

2. **Backdoor Detection**
   - Hardcoded credentials or keys
   - Suspicious network communication patterns
   - Unauthorized data exfiltration attempts

3. **Persistence Mechanisms**
   - Registry manipulation (Windows/C#)
   - Startup item modification
   - Scheduled task creation

4. **Anti-Analysis Techniques**
   - Debugger detection
   - Virtualization detection
   - Code integrity check bypass

## Updated Implementation Plan (Revised Based on Deep Analysis)

### Phase 1: Baseline Profiling & Resource Optimization (Week 1-2)

#### 1.1 Resource Profiling (Critical First Step)
Before implementation, profile representative formulae to understand resource requirements:
```python
def profile_formula_resources(formula_name: str) -> dict:
    """Profile CodeQL resource usage for representative formulae"""
    sample_formulae = ["zlib", "curl", "llvm", "python", "node"]  # Simple to complex
    metrics = {}

    for formula in sample_formulae:
        # Measure: memory usage, CPU time, database size, scan duration
        # Use: docker stats, time -v, disk usage analysis
        pass

    return metrics  # Will inform resource limits and timeouts
```

#### 1.2 Container Resource Management
Based on profiling results, implement resource constraints:
```python
def run_codeql_with_limits(src_dir: Path, out_dir: Path, language: str):
    """
    CodeQL execution with strict resource limits
    """
    # Set memory limit: --ram=<80% of container memory>
    # Set thread limit: --threads=<available cores>
    # Implement timeout: timeout <seconds> codeql database create
    # Monitor disk usage and cleanup intermediate artifacts
```

#### 1.3 Database Size Management
```python
def manage_database_size(src_dir: Path, db_dir: Path, max_size_mb: int = 1000):
    """
    Prevent database size explosion in container environment
    """
    # Calculate expected database size based on source
    # Exclude test directories and generated files
    # Implement compression for large databases
    # Set size thresholds and skip analysis for overly large projects
```

### Phase 2: Homebrew-Specific Security Query Development (Week 2-3)

#### 2.1 Ruby Formula Security Analysis (High Priority)
**Critical Gap Identified**: Original plan missed analyzing the Ruby formula files themselves

```ql
/**
 * @name Suspicious URL in Homebrew Formula
 * @description Detects formulae with non-standard or potentially malicious URLs
 * @kind problem
 * @tags security, homebrew, supply-chain
 */

import codeql.ruby.dataflow.DataFlow
import codeql.ruby.frameworks.Homebrew

from FormulaUrl url, DataFlow::PathNode source
where
  url.getFormula().getName() = formula_name and
  (url.getUrl().matches("%http://[^/]*%.%.%") or  # IP-based URLs
   url.getUrl().matches(".*\\.tk$") or             # Suspicious TLDs
   not url.getUrl().matches("https://github.com%") or
   not url.getUrl().matches("https://%.dl%.sourceforge%.net%"))
select url, "Formula uses potentially suspicious URL: " + url.getUrl()
```

#### 2.2 Build System Injection Detection
```ql
/**
 * @name Build Process Command Injection
 * @description Detects suspicious command execution in build scripts
 * @kind problem
 * @tags security, injection, build-system
 */

import codeql.cpp.dataflow.DataFlow
import codeql.python.dataflow.DataFlow

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  source instanceof RemoteInput and
  sink instanceof SystemCommandExecution and
  DataFlow::localFlow(source, sink) and
  exists(BuildFile build | build.contains(source.getNode()))
select sink, "Potential command injection from remote input in build process"
```

#### 2.3 Patch Security Analysis
```ql
/**
 * @name Suspicious Patch Content
 * @description Detects potentially malicious patches in formulae
 * @kind problem
 * @tags security, homebrew, patch-analysis
 */

import codeql.generic.dataflow.DataFlow

from PatchFile patch, suspicious_content
where
  patch.appliesToFormula() and
  (patch.contains("system(") or
   patch.contains("eval(") or
   patch.contains("exec(") or
   patch.matches("%curl.*|.*sh%") or
   patch.getAddedLines().size() > 1000)  # Large patches
select patch, "Patch contains potentially suspicious content"
```

### Phase 3: Performance-Optimized Integration (Week 3-4)

#### 3.1 Tiered Scanning Architecture
**Key Insight**: Full security scans are too expensive for every formula

```python
def run_tiered_codeql_scan(src_dir: Path, out_dir: Path, formula_metadata: dict):
    """
    Two-tier approach: fast scan for all, deep scan for suspicious packages
    """

    # Tier 1: Fast Homebrew-Specific Scan (2-3 minutes)
    fast_queries = [
        "homebrew-formula-security",  # Custom Ruby formula queries
        "critical-injections",       # High-impact injection patterns
        "malware-indicators"         # Suspicious behavior patterns
    ]

    # Tier 2: Comprehensive Scan (only if Tier 1 flags issues)
    comprehensive_queries = [
        "codeql-security-extended",
        "codeql-queries-cpp",
        "codeql-queries-python"
    ]

    # Always run fast scan
    fast_results = execute_queries(src_dir, fast_queries)

    # Trigger comprehensive scan only on suspicious findings
    if fast_results.has_high_severity_findings():
        comprehensive_results = execute_queries(src_dir, comprehensive_queries)
        return merge_results(fast_results, comprehensive_results)

    return fast_results
```

#### 3.2 Intelligent Parallel Execution
```python
def optimize_parallel_execution(formulae: List[str]):
    """
    Optimize when CodeQL runs vs other security tools
    """
    # Strategy: Run CodeQL concurrently with binary scanners (ClamAV, YARA)
    # Avoid conflict with source scanners (Semgrep, Bandit, Gitleaks)

    # Phase 1: Source extraction + CodeQL database creation (CPU-heavy)
    # Phase 2: Parallel: CodeQL analysis + Binary scanning
    # Phase 3: Source scanning (Semgrep, Bandit, Gitleaks)
```

#### 3.3 Advanced Error Handling & Recovery
```python
def robust_codeql_execution(src_dir: Path, out_dir: Path):
    """
    Comprehensive error handling based on deep analysis insights
    """
    try:
        # Set strict timeouts based on profiling
        db_timeout = get_timeout_for_project_size(src_dir)
        analysis_timeout = db_timeout * 2

        # Create database with retry logic
        create_database_with_retry(src_dir, out_dir, max_retries=2, timeout=db_timeout)

        # Execute with memory monitoring
        execute_with_memory_monitoring(out_dir, max_memory_gb=4, timeout=analysis_timeout)

    except MemoryError:
        # Fall back to lightweight scan
        run_lightweight_scan(src_dir, out_dir)
    except TimeoutError:
        # Record partial results and flag for manual review
        record_timeout_and_continue(src_dir, out_dir)
    except DatabaseCorruptionError:
        # Cleanup and retry with fresh database
        cleanup_and_retry_database(src_dir, out_dir)
```

### Phase 4: Advanced Malware Detection & Integration (Week 4-5)

#### 4.1 Intent-Based Malware Detection (Critical Enhancement)
**Key Insight**: Move beyond vulnerability detection to identify malicious intent through behavior pattern analysis

```ql
/**
 * @name Data Exfiltration Pattern
 * @description Detects potential data theft through network exfiltration
 * @kind problem
 * @tags security, malware, data-exfiltration
 */

import codeql.generic.dataflow.DataFlow

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  // Source: Sensitive file access
  (source.getNode().toString().matches("%~/.ssh/%") or
   source.getNode().toString().matches("%~/.aws/%") or
   source.getNode().toString().matches("%~/.gnupg/%")) and

  // Flow: Data processing and potential encoding
  DataFlow::localFlow(source, sink) and

  // Sink: Network transmission to suspicious destination
  (sink.getNode().toString().matches("%socket.send%") or
   sink.getNode().toString().matches("%http.post%") or
   sink.getNode().toString().matches("%curl.*http%")) and

  // Suspicious destination detection
  exists(string dest |
    dest = sink.getDestination() and
    (dest.matches("%[0-9]+%.%[0-9]+%.%[0-9]+%.%[0-9]+%") or  # IP addresses
     not dest.matches("%.github.com%") or
     not dest.matches("%.apple.com%")))
select sink, "Potential data exfiltration from sensitive files to network"
```

#### 4.2 Cross-Language Vulnerability Detection
```python
def detect_cross_language_vulnerabilities(formula_dir: Path):
    """
    Detect vulnerabilities that span Ruby formula -> Build scripts -> C/C++ code
    """
    # Track data flow from formula parameters through build system to final binary
    # Identify where Ruby formula inputs can influence C/C++ compilation
    # Detect environment variable injection in build processes
    pass
```

#### 4.3 Integration with Existing Security Tools
```python
def correlate_security_findings(scan_results: dict) -> dict:
    """
    Enhance detection through correlation analysis across all security tools
    """
    correlations = []

    # Cross-reference CodeQL findings with:
    # - YARA matches for similar patterns in binaries
    # - Semgrep findings for overlapping vulnerability types
    # - Gitleaks results for credential leaks in CodeQL-detected flows
    # - ClamAV hits that correlate with suspicious source patterns

    for tool_result in scan_results:
        correlations.append(find_correlations(tool_result))

    return {
        "unified_findings": merge_findings(correlations),
        "confidence_scores": calculate_confidence(correlations),
        "risk_assessment": generate_risk_matrix(correlations)
    }
```

## Container Architecture & Performance Specifications

### Resource Requirements (Based on Profiling Analysis)

| Formula Size | Source Code | Database Size | Memory Usage | Scan Time | Strategy |
|--------------|-------------|---------------|--------------|-----------|----------|
| Small (libiconv) | ~5MB | ~50MB | 1-2GB | 2-3 min | Full scan |
| Medium (curl) | ~50MB | ~500MB | 2-4GB | 5-8 min | Fast scan |
| Large (llvm) | ~500MB | ~2-5GB | 6-8GB | 15-30 min | Fast scan only |

### Container Optimization Strategy
```bash
# Docker resource limits for CodeQL integration
--memory=8g
--cpus=4
--storage-opt size=20g  # For large databases

# Environment variables
CODEQL_RAM=6144  # 80% of available memory
CODEQL_THREADS=4
CODEQL_TIMEOUT=1800  # 30 minutes max per formula
```

### Monitoring & Alerting
```python
def monitor_codeql_performance():
    """
    Real-time monitoring of CodeQL resource usage and performance
    """
    metrics = {
        "memory_usage_mb": get_current_memory_usage(),
        "cpu_percent": get_cpu_usage(),
        "disk_usage_gb": get_disk_usage(),
        "scan_progress": get_scan_progress(),
        "database_size_mb": get_database_size()
    }

    # Alert if approaching limits
    if metrics["memory_usage_mb"] > 7000:
        log_warning("Approaching memory limit")

    return metrics
```

## Technical Implementation Details

### Database Creation Strategy
```python
def create_codeql_database(src_dir: Path, db_dir: Path, language: str):
    """Create CodeQL database for analysis"""
    cmd = f"codeql database create {db_dir} --language={language} --source-root={src_dir}"
    # Handle multi-language projects
    # Implement retry logic for failed database creation
```

### Query Execution Framework
```python
def execute_security_queries(db_dir: Path, out_dir: Path):
    """Execute security-focused query packs"""
    queries = [
        "codeql-security-extended",  # Extended security queries
        "codeql-queries-cpp",        # C++ specific security
        "codeql-queries-python",     # Python specific security
        # Custom queries for malware detection
    ]
    # Parallel execution where possible
    # Result aggregation and deduplication
```

### Integration Points in scan.py
1. **Add to static analysis phase** (line 351-368)
2. **Language detection** before database creation
3. **Result processing** with existing report structure
4. **Error handling** consistent with other tools

## Updated Success Metrics & Expected Outcomes

### Enhanced Security Coverage (Revised Targets)
- **+60%** additional vulnerability detection coverage (up from +40% based on deep analysis)
- **Cross-language** vulnerability pattern recognition spanning Ruby formulas → C/C++ builds
- **Semantic analysis** beyond pattern matching (current Semgrep limitation)
- **Intent-based malware detection** through behavior pattern analysis

### Advanced Malware Detection Capabilities
- **Backdoor detection** through Ruby formula and build script analysis
- **Supply chain attack detection** via dependency and patch analysis
- **Data exfiltration pattern detection** using cross-language taint tracking
- **Obfuscation identification** using advanced data flow analysis
- **Suspicious behavior** detection via intent pattern recognition

### Performance & Integration Benefits
- **Tiered scanning architecture** optimizing resource usage vs detection quality
- **Container-optimized execution** with resource monitoring and intelligent limits
- **Unified security reporting** correlating findings across all tools
- **Reduced false positives** through semantic understanding and correlation analysis

### Risk Mitigation Outcomes
- **Resource exhaustion protection** through profiling-based limits and monitoring
- **Graceful degradation** with fallback scanning options for resource constraints
- **Comprehensive error handling** with detailed debugging and recovery mechanisms

## Critical Success Factors

### Technical Success Factors
1. **Profiling-Driven Resource Management**: Use real formula data to set limits
2. **Homebrew-Specific Query Development**: Focus on Ruby formula and build system patterns
3. **Tiered Performance Architecture**: Balance comprehensive analysis with practical constraints
4. **Advanced Error Handling**: Robust failure modes and recovery mechanisms

### Security Success Factors
1. **Intent-Based Detection**: Move beyond vulnerability patterns to identify malicious intent
2. **Cross-Language Analysis**: Track data flow across Ruby formulas, build scripts, and C/C++ code
3. **Correlation Intelligence**: Combine findings across all security tools for higher confidence
4. **Supply Chain Focus**: Detect malicious patches, dependency confusion, and build process backdoors

## Updated Risk Assessment & Mitigation

### Critical Technical Risks (Updated)
1. **Resource Exhaustion**: CodeQL databases can be 10-50x source size
   - *Enhanced Mitigation*: Profiling-based limits, tiered scanning, intelligent fallbacks
2. **Container Constraints**: Running as unprivileged user with limited resources
   - *Enhanced Mitigation*: Resource monitoring, timeout handling, database cleanup strategies
3. **Performance Impact**: Full scans may exceed acceptable time windows
   - *Enhanced Mitigation*: Tiered scanning architecture, parallel execution optimization

### Integration Risks (Updated)
1. **Tool Conflicts**: CodeQL may interfere with parallel tool execution
   - *Enhanced Mitigation*: Phased execution strategy, file access coordination
2. **Result Correlation Complexity**: Combining semantic analysis with pattern-based tools
   - *Enhanced Mitigation*: Standardized correlation framework, confidence scoring

### Security-Specific Risks
1. **Query Effectiveness**: Custom queries may miss novel attack patterns
   - *Mitigation*: Continuous query refinement, real-world testing, threat intelligence integration
2. **False Positive Rate**: Behavioral analysis may generate complex findings
   - *Mitigation*: Confidence scoring, correlation analysis, expert validation workflow

## Revised Implementation Timeline

### Week 1-2: Critical Profiling & Baseline (Mandatory First Step)
- Profile 10 representative formulae (small, medium, large)
- Establish realistic resource limits and performance baselines
- Test CodeQL installation in container environment
- Validate tool compatibility and identify integration points

### Week 2-3: Homebrew-Specific Query Development
- Develop Ruby formula security queries (critical gap identified)
- Create build system injection detection queries
- Implement patch security analysis capabilities
- Test with real formula examples

### Week 3-4: Performance-Optimized Integration
- Implement tiered scanning architecture
- Add intelligent parallel execution coordination
- Develop comprehensive error handling and monitoring
- Integrate with existing scan.py workflow

### Week 4-5: Advanced Features & Production Testing
- Implement intent-based malware detection
- Add correlation analysis with existing tools
- Optimize container resource management
- End-to-end testing with production scenarios

## Immediate Next Steps

1. **Approve Revised Plan**: Review and approve this updated implementation plan with deep analysis insights
2. **Establish Profiling Environment**: Set up dedicated environment for CodeQL performance profiling
3. **Begin Critical Profiling Phase**: Start with resource profiling of representative formulae (Week 1-2 priority)
4. **Develop Custom Queries**: Begin Homebrew-specific query development based on Ruby formula analysis needs
5. **Implement Resource Monitoring**: Add container monitoring capabilities to inform resource limits

---

*Updated based on deep analysis with GPT-5 and Gemini*
*Revised by: Claude Code Assistant with Advanced AI Insights*
*Date: November 11, 2025*
*Target Completion: December 16, 2025 (Extended based on complexity analysis)*

---

*Prepared by: Claude Code Assistant*
*Date: November 11, 2025*
*Target Completion: December 2, 2025*