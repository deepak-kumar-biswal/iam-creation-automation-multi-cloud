#!/usr/bin/env python3
"""
Test Execution and Dry Run Management Script
Provides comprehensive test execution with dry run scenarios
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class TestExecutor:
    """Manages test execution and dry run scenarios"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.tests_dir = self.project_root / "tests"
        self.logs_dir = self.project_root / "logs" / "tests"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
    
    def setup_test_environment(self) -> bool:
        """Set up the testing environment"""
        print("🔧 Setting up test environment...")
        
        # Install test dependencies
        requirements_file = self.tests_dir / "requirements.txt"
        if requirements_file.exists():
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
                ], check=True, capture_output=True, text=True)
                print("✅ Test dependencies installed successfully")
                return True
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install dependencies: {e.stderr}")
                return False
        else:
            print("⚠️ No requirements.txt found, skipping dependency installation")
            return True
    
    def run_unit_tests(self, verbose: bool = False) -> Tuple[bool, Dict]:
        """Run unit tests"""
        print("🧪 Running unit tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.tests_dir / "test_iam_automation.py"),
            "-v" if verbose else "-q",
            "--tb=short",
            "--json-report",
            f"--json-report-file={self.logs_dir / 'unit_tests.json'}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Load test results
            report_file = self.logs_dir / 'unit_tests.json'
            if report_file.exists():
                with open(report_file, 'r') as f:
                    test_report = json.load(f)
            else:
                test_report = {"summary": {"failed": result.returncode}}
            
            success = result.returncode == 0
            print(f"{'✅' if success else '❌'} Unit tests {'passed' if success else 'failed'}")
            
            if not success and verbose:
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
            
            return success, test_report
            
        except subprocess.TimeoutExpired:
            print("❌ Unit tests timed out")
            return False, {"error": "timeout"}
        except Exception as e:
            print(f"❌ Error running unit tests: {e}")
            return False, {"error": str(e)}
    
    def run_dry_run_scenarios(self, verbose: bool = False) -> Tuple[bool, Dict]:
        """Run dry run scenarios"""
        print("🏃 Running dry run scenarios...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.tests_dir / "test_dry_run_scenarios.py"),
            "-v" if verbose else "-q",
            "--tb=short",
            "-x",  # Stop on first failure for dry runs
            "--json-report",
            f"--json-report-file={self.logs_dir / 'dry_run_tests.json'}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Load test results
            report_file = self.logs_dir / 'dry_run_tests.json'
            if report_file.exists():
                with open(report_file, 'r') as f:
                    test_report = json.load(f)
            else:
                test_report = {"summary": {"failed": result.returncode}}
            
            success = result.returncode == 0
            print(f"{'✅' if success else '❌'} Dry run scenarios {'passed' if success else 'failed'}")
            
            if not success and verbose:
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
            
            return success, test_report
            
        except subprocess.TimeoutExpired:
            print("❌ Dry run scenarios timed out")
            return False, {"error": "timeout"}
        except Exception as e:
            print(f"❌ Error running dry run scenarios: {e}")
            return False, {"error": str(e)}
    
    def validate_terraform_syntax(self) -> Tuple[bool, List[str]]:
        """Validate Terraform syntax across all modules"""
        print("🔍 Validating Terraform syntax...")
        
        terraform_dirs = [
            self.project_root / "terraform" / "modules" / "aws-iam",
            self.project_root / "terraform" / "modules" / "gcp-iam",
            self.project_root / "terraform" / "modules" / "azure-iam",
            self.project_root / "terraform" / "environments" / "production"
        ]
        
        validation_results = []
        all_valid = True
        
        for tf_dir in terraform_dirs:
            if not tf_dir.exists():
                validation_results.append(f"⚠️ Directory not found: {tf_dir}")
                continue
            
            try:
                # Terraform init (if needed)
                if not (tf_dir / ".terraform").exists():
                    init_result = subprocess.run([
                        "terraform", "init", "-backend=false"
                    ], cwd=tf_dir, capture_output=True, text=True, timeout=120)
                    
                    if init_result.returncode != 0:
                        validation_results.append(f"❌ Init failed in {tf_dir.name}: {init_result.stderr}")
                        all_valid = False
                        continue
                
                # Terraform validate
                validate_result = subprocess.run([
                    "terraform", "validate"
                ], cwd=tf_dir, capture_output=True, text=True, timeout=60)
                
                if validate_result.returncode == 0:
                    validation_results.append(f"✅ {tf_dir.name}: Syntax valid")
                else:
                    validation_results.append(f"❌ {tf_dir.name}: {validate_result.stderr}")
                    all_valid = False
                    
            except subprocess.TimeoutExpired:
                validation_results.append(f"❌ {tf_dir.name}: Validation timed out")
                all_valid = False
            except FileNotFoundError:
                validation_results.append("⚠️ Terraform not found in PATH. Install Terraform to run syntax validation.")
                break
            except Exception as e:
                validation_results.append(f"❌ {tf_dir.name}: Error - {e}")
                all_valid = False
        
        print(f"{'✅' if all_valid else '❌'} Terraform syntax validation {'completed' if all_valid else 'failed'}")
        return all_valid, validation_results
    
    def run_security_linting(self) -> Tuple[bool, List[str]]:
        """Run security linting on code"""
        print("🔒 Running security linting...")
        
        linting_results = []
        all_clean = True
        
        # Check if security tools are available
        security_tools = [
            {
                "name": "bandit",
                "cmd": ["python", "-m", "bandit", "-r", ".", "-f", "json"],
                "description": "Python security linter"
            },
            {
                "name": "safety",
                "cmd": ["python", "-m", "safety", "check", "--json"],
                "description": "Dependency vulnerability scanner"
            }
        ]
        
        for tool in security_tools:
            try:
                result = subprocess.run(
                    tool["cmd"], 
                    cwd=self.project_root,
                    capture_output=True, 
                    text=True, 
                    timeout=120
                )
                
                if result.returncode == 0:
                    linting_results.append(f"✅ {tool['name']}: No security issues found")
                else:
                    # Parse results if possible
                    try:
                        if tool["name"] == "bandit":
                            results_data = json.loads(result.stdout)
                            issues = len(results_data.get("results", []))
                            if issues > 0:
                                linting_results.append(f"⚠️ {tool['name']}: {issues} security issues found")
                                all_clean = False
                            else:
                                linting_results.append(f"✅ {tool['name']}: No security issues found")
                        elif tool["name"] == "safety":
                            # Safety returns non-zero for vulnerabilities
                            linting_results.append(f"⚠️ {tool['name']}: Vulnerabilities detected")
                            all_clean = False
                    except json.JSONDecodeError:
                        linting_results.append(f"⚠️ {tool['name']}: Could not parse results")
                        
            except subprocess.TimeoutExpired:
                linting_results.append(f"❌ {tool['name']}: Timed out")
                all_clean = False
            except FileNotFoundError:
                linting_results.append(f"⚠️ {tool['name']}: Not installed (install with: pip install {tool['name']})")
            except Exception as e:
                linting_results.append(f"❌ {tool['name']}: Error - {e}")
                all_clean = False
        
        print(f"{'✅' if all_clean else '⚠️'} Security linting {'completed cleanly' if all_clean else 'found issues'}")
        return all_clean, linting_results
    
    def generate_test_report(self, results: Dict) -> str:
        """Generate comprehensive test report"""
        timestamp = datetime.now().isoformat()
        
        report = {
            "test_execution_report": {
                "timestamp": timestamp,
                "project": "Multi-Cloud IAM Automation",
                "version": "1.0.0",
                "results": results,
                "summary": {
                    "total_test_suites": len(results),
                    "passed_suites": len([r for r in results.values() if r.get("success", False)]),
                    "failed_suites": len([r for r in results.values() if not r.get("success", False)]),
                    "overall_status": "PASS" if all(r.get("success", False) for r in results.values()) else "FAIL"
                }
            }
        }
        
        # Save detailed report
        report_file = self.logs_dir / f"test_report_{timestamp.replace(':', '-').replace('.', '-')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate summary
        summary_lines = [
            "=" * 80,
            "TEST EXECUTION SUMMARY",
            "=" * 80,
            f"Timestamp: {timestamp}",
            f"Project: Multi-Cloud IAM Automation",
            "",
            "Test Suite Results:",
        ]
        
        for suite_name, suite_results in results.items():
            status = "✅ PASS" if suite_results.get("success", False) else "❌ FAIL"
            summary_lines.append(f"  {suite_name}: {status}")
            
            if suite_results.get("details"):
                for detail in suite_results["details"][:5]:  # Show first 5 details
                    summary_lines.append(f"    - {detail}")
        
        summary_lines.extend([
            "",
            f"Overall Status: {report['test_execution_report']['summary']['overall_status']}",
            f"Passed: {report['test_execution_report']['summary']['passed_suites']}/{report['test_execution_report']['summary']['total_test_suites']}",
            f"Detailed Report: {report_file}",
            "=" * 80
        ])
        
        summary = "\n".join(summary_lines)
        
        # Save summary
        summary_file = self.logs_dir / "latest_test_summary.txt"
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        return summary
    
    def run_full_test_suite(self, include_terraform: bool = False, include_security: bool = False, verbose: bool = False) -> bool:
        """Run the complete test suite"""
        print("🚀 Starting full test suite execution...")
        print(f"Project: {self.project_root}")
        print(f"Logs: {self.logs_dir}")
        print()
        
        results = {}
        
        # Setup environment
        if not self.setup_test_environment():
            print("❌ Failed to setup test environment")
            return False
        
        # Run unit tests
        unit_success, unit_report = self.run_unit_tests(verbose=verbose)
        results["unit_tests"] = {
            "success": unit_success,
            "report": unit_report,
            "details": [f"Unit tests {'passed' if unit_success else 'failed'}"]
        }
        
        # Run dry run scenarios
        dry_run_success, dry_run_report = self.run_dry_run_scenarios(verbose=verbose)
        results["dry_run_scenarios"] = {
            "success": dry_run_success,
            "report": dry_run_report,
            "details": [f"Dry run scenarios {'passed' if dry_run_success else 'failed'}"]
        }
        
        # Optional Terraform validation
        if include_terraform:
            tf_success, tf_details = self.validate_terraform_syntax()
            results["terraform_validation"] = {
                "success": tf_success,
                "details": tf_details
            }
        
        # Optional security linting
        if include_security:
            security_success, security_details = self.run_security_linting()
            results["security_linting"] = {
                "success": security_success,
                "details": security_details
            }
        
        # Generate report
        report_summary = self.generate_test_report(results)
        print("\n" + report_summary)
        
        # Determine overall success
        overall_success = all(r.get("success", False) for r in results.values())
        
        if overall_success:
            print("\n🎉 All tests passed! System is ready for deployment.")
        else:
            print("\n⚠️ Some tests failed. Please review the results before deployment.")
        
        return overall_success


def main():
    """Main entry point for test execution"""
    parser = argparse.ArgumentParser(description="Multi-Cloud IAM Automation Test Suite")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--unit-only", action="store_true", help="Run only unit tests")
    parser.add_argument("--dry-run-only", action="store_true", help="Run only dry run scenarios")
    parser.add_argument("--include-terraform", action="store_true", help="Include Terraform validation")
    parser.add_argument("--include-security", action="store_true", help="Include security linting")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Resolve project root
    project_root = os.path.abspath(args.project_root)
    if not os.path.isdir(project_root):
        print(f"❌ Project root directory not found: {project_root}")
        sys.exit(1)
    
    executor = TestExecutor(project_root)
    
    try:
        if args.unit_only:
            success, _ = executor.run_unit_tests(verbose=args.verbose)
        elif args.dry_run_only:
            success, _ = executor.run_dry_run_scenarios(verbose=args.verbose)
        else:
            success = executor.run_full_test_suite(
                include_terraform=args.include_terraform,
                include_security=args.include_security,
                verbose=args.verbose
            )
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n🛑 Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
