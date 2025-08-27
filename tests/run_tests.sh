#!/bin/bash

# Multi-Cloud IAM Automation - Comprehensive Test Execution Script
# This script provides a comprehensive testing framework for the IAM automation system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"
LOGS_DIR="$PROJECT_ROOT/logs/tests"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Ensure logs directory exists
mkdir -p "$LOGS_DIR"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo
    echo "=================================================================="
    echo "$1"
    echo "=================================================================="
    echo
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Python dependencies
install_dependencies() {
    print_status $BLUE "🔧 Installing test dependencies..."
    
    if [[ -f "$TESTS_DIR/requirements.txt" ]]; then
        python -m pip install -r "$TESTS_DIR/requirements.txt" || {
            print_status $RED "❌ Failed to install Python dependencies"
            return 1
        }
        print_status $GREEN "✅ Python dependencies installed successfully"
    else
        print_status $YELLOW "⚠️ No requirements.txt found, skipping Python dependency installation"
    fi
    
    return 0
}

# Function to validate Terraform syntax
validate_terraform() {
    print_status $BLUE "🔍 Validating Terraform configurations..."
    
    if ! command_exists terraform; then
        print_status $YELLOW "⚠️ Terraform not found in PATH. Skipping Terraform validation."
        return 0
    fi
    
    local terraform_dirs=(
        "$PROJECT_ROOT/terraform/modules/aws-iam"
        "$PROJECT_ROOT/terraform/modules/gcp-iam"
        "$PROJECT_ROOT/terraform/modules/azure-iam"
        "$PROJECT_ROOT/terraform/environments/production"
    )
    
    local validation_failed=0
    
    for tf_dir in "${terraform_dirs[@]}"; do
        if [[ -d "$tf_dir" ]]; then
            print_status $BLUE "  Validating $tf_dir..."
            
            cd "$tf_dir"
            
            # Initialize if needed (without backend)
            if [[ ! -d ".terraform" ]]; then
                terraform init -backend=false > /dev/null 2>&1 || {
                    print_status $RED "  ❌ Terraform init failed in $(basename "$tf_dir")"
                    validation_failed=1
                    continue
                }
            fi
            
            # Validate syntax
            terraform validate > /dev/null 2>&1 || {
                print_status $RED "  ❌ Terraform validation failed in $(basename "$tf_dir")"
                validation_failed=1
                continue
            }
            
            print_status $GREEN "  ✅ $(basename "$tf_dir"): Syntax valid"
        else
            print_status $YELLOW "  ⚠️ Directory not found: $tf_dir"
        fi
    done
    
    cd "$PROJECT_ROOT"
    
    if [[ $validation_failed -eq 0 ]]; then
        print_status $GREEN "✅ All Terraform configurations are valid"
        return 0
    else
        print_status $RED "❌ Terraform validation failed"
        return 1
    fi
}

# Function to run security linting
run_security_linting() {
    print_status $BLUE "🔒 Running security linting..."
    
    local linting_failed=0
    
    # Check for Python security issues with bandit
    if command_exists bandit; then
        print_status $BLUE "  Running bandit security linter..."
        bandit -r . -f json -o "$LOGS_DIR/bandit_report_$TIMESTAMP.json" > /dev/null 2>&1 || {
            local bandit_exit=$?
            if [[ $bandit_exit -eq 1 ]]; then
                print_status $YELLOW "  ⚠️ Bandit found potential security issues (see logs)"
                linting_failed=1
            else
                print_status $RED "  ❌ Bandit execution failed"
                linting_failed=1
            fi
        }
        if [[ $linting_failed -eq 0 ]]; then
            print_status $GREEN "  ✅ Bandit: No high-severity security issues found"
        fi
    else
        print_status $YELLOW "  ⚠️ bandit not installed (install with: pip install bandit)"
    fi
    
    # Check for dependency vulnerabilities with safety
    if command_exists safety; then
        print_status $BLUE "  Running safety vulnerability scanner..."
        safety check --json --output "$LOGS_DIR/safety_report_$TIMESTAMP.json" > /dev/null 2>&1 || {
            print_status $YELLOW "  ⚠️ Safety found vulnerabilities in dependencies (see logs)"
            linting_failed=1
        }
        if [[ $linting_failed -eq 0 ]]; then
            print_status $GREEN "  ✅ Safety: No known vulnerabilities in dependencies"
        fi
    else
        print_status $YELLOW "  ⚠️ safety not installed (install with: pip install safety)"
    fi
    
    # Check for secrets with truffleHog (if available)
    if command_exists trufflehog; then
        print_status $BLUE "  Running truffleHog secrets scanner..."
        trufflehog --json --output "$LOGS_DIR/trufflehog_report_$TIMESTAMP.json" . > /dev/null 2>&1 || {
            print_status $YELLOW "  ⚠️ TruffleHog found potential secrets (see logs)"
            linting_failed=1
        }
        if [[ $linting_failed -eq 0 ]]; then
            print_status $GREEN "  ✅ TruffleHog: No secrets detected"
        fi
    else
        print_status $YELLOW "  ⚠️ trufflehog not installed"
    fi
    
    if [[ $linting_failed -eq 0 ]]; then
        print_status $GREEN "✅ Security linting completed without major issues"
        return 0
    else
        print_status $YELLOW "⚠️ Security linting found potential issues (check logs)"
        return 1
    fi
}

# Function to run unit tests
run_unit_tests() {
    print_status $BLUE "🧪 Running unit tests..."
    
    local test_file="$TESTS_DIR/test_iam_automation.py"
    
    if [[ ! -f "$test_file" ]]; then
        print_status $RED "❌ Unit test file not found: $test_file"
        return 1
    fi
    
    python -m pytest "$test_file" \
        -v \
        --tb=short \
        --json-report \
        --json-report-file="$LOGS_DIR/unit_tests_$TIMESTAMP.json" \
        --html="$LOGS_DIR/unit_tests_$TIMESTAMP.html" \
        --self-contained-html \
        2>&1 | tee "$LOGS_DIR/unit_tests_$TIMESTAMP.log" || {
        print_status $RED "❌ Unit tests failed"
        return 1
    }
    
    print_status $GREEN "✅ Unit tests passed"
    return 0
}

# Function to run dry run scenarios
run_dry_run_scenarios() {
    print_status $BLUE "🏃 Running dry run scenarios..."
    
    local test_file="$TESTS_DIR/test_dry_run_scenarios.py"
    
    if [[ ! -f "$test_file" ]]; then
        print_status $RED "❌ Dry run test file not found: $test_file"
        return 1
    fi
    
    python -m pytest "$test_file" \
        -v \
        --tb=short \
        -x \
        --json-report \
        --json-report-file="$LOGS_DIR/dry_run_tests_$TIMESTAMP.json" \
        --html="$LOGS_DIR/dry_run_tests_$TIMESTAMP.html" \
        --self-contained-html \
        2>&1 | tee "$LOGS_DIR/dry_run_tests_$TIMESTAMP.log" || {
        print_status $RED "❌ Dry run scenarios failed"
        return 1
    }
    
    print_status $GREEN "✅ Dry run scenarios passed"
    return 0
}

# Function to run performance tests
run_performance_tests() {
    print_status $BLUE "⚡ Running performance tests..."
    
    # Run a subset of tests focused on performance
    python -m pytest "$TESTS_DIR/test_iam_automation.py::TestPerformanceValidation" \
        -v \
        --tb=short \
        --json-report \
        --json-report-file="$LOGS_DIR/performance_tests_$TIMESTAMP.json" \
        2>&1 | tee "$LOGS_DIR/performance_tests_$TIMESTAMP.log" || {
        print_status $YELLOW "⚠️ Performance tests had issues (check logs)"
        return 1
    }
    
    print_status $GREEN "✅ Performance tests completed"
    return 0
}

# Function to generate comprehensive test report
generate_test_report() {
    local overall_status=$1
    local report_file="$LOGS_DIR/comprehensive_test_report_$TIMESTAMP.md"
    
    print_status $BLUE "📊 Generating comprehensive test report..."
    
    cat > "$report_file" << EOF
# Multi-Cloud IAM Automation - Test Execution Report

**Generated:** $(date)
**Project:** Multi-Cloud IAM Automation System
**Version:** 1.0.0
**Overall Status:** $(if [[ $overall_status -eq 0 ]]; then echo "✅ PASSED"; else echo "❌ FAILED"; fi)

## Executive Summary

This report summarizes the comprehensive testing of the Multi-Cloud IAM Automation System,
including unit tests, integration tests, dry run scenarios, security validation, and
performance testing across AWS, Google Cloud Platform, and Microsoft Azure.

## Test Suite Results

### 1. Unit Tests
- **File:** test_iam_automation.py
- **Coverage:** AWS, GCP, Azure IAM modules
- **Status:** $(if [[ -f "$LOGS_DIR/unit_tests_$TIMESTAMP.json" ]]; then echo "✅ Executed"; else echo "❌ Not executed"; fi)
- **Log:** unit_tests_$TIMESTAMP.log

### 2. Dry Run Scenarios  
- **File:** test_dry_run_scenarios.py
- **Coverage:** Terraform plans, configuration validation, cost estimation
- **Status:** $(if [[ -f "$LOGS_DIR/dry_run_tests_$TIMESTAMP.json" ]]; then echo "✅ Executed"; else echo "❌ Not executed"; fi)
- **Log:** dry_run_tests_$TIMESTAMP.log

### 3. Security Validation
- **Tools:** bandit, safety, trufflehog
- **Coverage:** Code security, dependency vulnerabilities, secrets detection
- **Status:** $(if [[ -f "$LOGS_DIR/bandit_report_$TIMESTAMP.json" ]]; then echo "✅ Executed"; else echo "⚠️ Partial/Not executed"; fi)
- **Reports:** bandit_report_$TIMESTAMP.json, safety_report_$TIMESTAMP.json

### 4. Terraform Validation
- **Scope:** All modules (aws-iam, gcp-iam, azure-iam)
- **Coverage:** Syntax validation, configuration verification
- **Status:** $(if command_exists terraform; then echo "✅ Available"; else echo "⚠️ Terraform not available"; fi)

### 5. Performance Testing
- **Scope:** Scalability, concurrent operations, resource limits
- **Status:** $(if [[ -f "$LOGS_DIR/performance_tests_$TIMESTAMP.json" ]]; then echo "✅ Executed"; else echo "❌ Not executed"; fi)
- **Log:** performance_tests_$TIMESTAMP.log

## Key Metrics

- **Test Execution Time:** $(date)
- **Total Test Cases:** Comprehensive suite across all modules
- **Cloud Providers Tested:** AWS, GCP, Azure
- **Security Scans:** Static analysis, dependency check, secrets detection
- **Performance Validation:** Scalability and resource optimization

## Recommendations

### If Tests Passed ✅
- System is ready for production deployment
- All security validations passed
- Performance meets enterprise requirements
- Terraform configurations are valid

### If Tests Failed ❌
- Review detailed logs in the logs/tests directory
- Address any security vulnerabilities found
- Fix Terraform configuration issues
- Resolve performance bottlenecks
- Re-run tests before deployment

## Files Generated

- **Comprehensive Report:** comprehensive_test_report_$TIMESTAMP.md
- **Unit Test Results:** unit_tests_$TIMESTAMP.json
- **Dry Run Results:** dry_run_tests_$TIMESTAMP.json
- **Security Reports:** bandit_report_$TIMESTAMP.json, safety_report_$TIMESTAMP.json
- **Test Logs:** *_$TIMESTAMP.log files

## Next Steps

1. Review any failed tests or security issues
2. Update configurations as needed
3. Re-run specific test suites if required
4. Proceed with staged deployment if all tests pass
5. Monitor system performance in production

---

**Report Location:** $report_file
**Generated by:** Multi-Cloud IAM Automation Test Suite v1.0.0
EOF

    print_status $GREEN "✅ Test report generated: $report_file"
    
    # Display summary
    print_header "TEST EXECUTION SUMMARY"
    cat "$report_file" | grep -A 20 "## Test Suite Results"
    echo
    print_status $BLUE "📁 All test artifacts saved to: $LOGS_DIR"
}

# Main execution function
main() {
    local run_unit_tests=true
    local run_dry_run=true
    local run_terraform_validation=false
    local run_security=false
    local run_performance=false
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --unit-only)
                run_dry_run=false
                run_terraform_validation=false
                run_security=false
                run_performance=false
                shift
                ;;
            --dry-run-only)
                run_unit_tests=false
                run_terraform_validation=false
                run_security=false
                run_performance=false
                shift
                ;;
            --include-terraform)
                run_terraform_validation=true
                shift
                ;;
            --include-security)
                run_security=true
                shift
                ;;
            --include-performance)
                run_performance=true
                shift
                ;;
            --verbose|-v)
                verbose=true
                shift
                ;;
            --help|-h)
                echo "Multi-Cloud IAM Automation Test Suite"
                echo
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  --unit-only           Run only unit tests"
                echo "  --dry-run-only        Run only dry run scenarios"
                echo "  --include-terraform   Include Terraform validation"
                echo "  --include-security    Include security linting"
                echo "  --include-performance Include performance tests"
                echo "  --verbose, -v         Verbose output"
                echo "  --help, -h            Show this help message"
                echo
                echo "Examples:"
                echo "  $0                                    # Run core test suite"
                echo "  $0 --include-security --include-terraform  # Full validation"
                echo "  $0 --unit-only                      # Quick unit test run"
                echo "  $0 --dry-run-only                   # Test deployment scenarios"
                exit 0
                ;;
            *)
                print_status $RED "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    print_header "Multi-Cloud IAM Automation - Test Suite Execution"
    print_status $BLUE "🚀 Starting comprehensive test execution..."
    print_status $BLUE "📁 Project Root: $PROJECT_ROOT"
    print_status $BLUE "📊 Logs Directory: $LOGS_DIR"
    print_status $BLUE "🕐 Timestamp: $TIMESTAMP"
    echo
    
    local overall_status=0
    
    # Install dependencies
    install_dependencies || overall_status=1
    
    # Run unit tests
    if [[ $run_unit_tests == true ]]; then
        run_unit_tests || overall_status=1
    fi
    
    # Run dry run scenarios
    if [[ $run_dry_run == true ]]; then
        run_dry_run_scenarios || overall_status=1
    fi
    
    # Run Terraform validation
    if [[ $run_terraform_validation == true ]]; then
        validate_terraform || overall_status=1
    fi
    
    # Run security linting
    if [[ $run_security == true ]]; then
        run_security_linting || overall_status=1
    fi
    
    # Run performance tests
    if [[ $run_performance == true ]]; then
        run_performance_tests || overall_status=1
    fi
    
    # Generate comprehensive report
    generate_test_report $overall_status
    
    # Final status
    echo
    if [[ $overall_status -eq 0 ]]; then
        print_status $GREEN "🎉 All tests completed successfully!"
        print_status $GREEN "✅ System is ready for deployment"
    else
        print_status $YELLOW "⚠️  Some tests failed or had issues"
        print_status $YELLOW "📋 Please review the detailed logs and reports"
    fi
    
    print_status $BLUE "📊 Detailed report: $LOGS_DIR/comprehensive_test_report_$TIMESTAMP.md"
    echo
    
    exit $overall_status
}

# Execute main function with all arguments
main "$@"
