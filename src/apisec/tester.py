"""Core API Security Tester class."""

import time
import requests
import yaml
from typing import Optional
from urllib.parse import urljoin

from .tests.authentication import AuthenticationTests
from .tests.authorization import AuthorizationTests
from .tests.injection import InjectionTests
from .tests.rate_limit import RateLimitTests
from .tests.exposure import ExposureTests
from .tests.headers import HeaderTests


class APISecurityTester:
    """Main API security testing class."""
    
    def __init__(self, base_url: str, auth_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.session = requests.Session()
        self.endpoints = []
        self.config = {}
        self.results = {
            "findings": [],
            "tests_run": 0,
            "passed": 0,
            "failed": 0,
            "duration": 0,
        }
        
        if auth_token:
            if auth_token.startswith("Bearer "):
                self.session.headers["Authorization"] = auth_token
            else:
                self.session.headers["Authorization"] = f"Bearer {auth_token}"
    
    def load_config(self, config_path: str):
        """Load configuration from YAML file."""
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
        
        if "endpoints" in self.config:
            self.endpoints = self.config["endpoints"]
    
    def add_endpoint(self, path: str, methods: list = None, auth_required: bool = True):
        """Add an endpoint to test."""
        self.endpoints.append({
            "path": path,
            "methods": methods or ["GET"],
            "auth_required": auth_required,
        })
    
    def _make_request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Make an HTTP request to the API."""
        url = urljoin(self.base_url, path)
        return self.session.request(method, url, timeout=30, **kwargs)
    
    def run_all(self) -> dict:
        """Run all security tests."""
        start_time = time.time()
        
        self.run_authentication_tests()
        self.run_authorization_tests()
        self.run_injection_tests()
        self.run_rate_limit_tests()
        self.run_exposure_tests()
        self.run_header_tests()
        
        self.results["duration"] = time.time() - start_time
        return self.results
    
    def run_authentication_tests(self) -> dict:
        """Run authentication-related tests."""
        print("[1/6] Running Authentication Tests...")
        tests = AuthenticationTests(self)
        findings = tests.run()
        self._process_findings(findings, "Authentication")
        return self.results
    
    def run_authorization_tests(self) -> dict:
        """Run authorization-related tests."""
        print("[2/6] Running Authorization Tests...")
        tests = AuthorizationTests(self)
        findings = tests.run()
        self._process_findings(findings, "Authorization")
        return self.results
    
    def run_injection_tests(self) -> dict:
        """Run injection-related tests."""
        print("[3/6] Running Injection Tests...")
        tests = InjectionTests(self)
        findings = tests.run()
        self._process_findings(findings, "Injection")
        return self.results
    
    def run_rate_limit_tests(self) -> dict:
        """Run rate limiting tests."""
        print("[4/6] Running Rate Limit Tests...")
        tests = RateLimitTests(self)
        findings = tests.run()
        self._process_findings(findings, "Rate Limiting")
        return self.results
    
    def run_exposure_tests(self) -> dict:
        """Run data exposure tests."""
        print("[5/6] Running Data Exposure Tests...")
        tests = ExposureTests(self)
        findings = tests.run()
        self._process_findings(findings, "Data Exposure")
        return self.results
    
    def run_header_tests(self) -> dict:
        """Run security header tests."""
        print("[6/6] Running Security Header Tests...")
        tests = HeaderTests(self)
        findings = tests.run()
        self._process_findings(findings, "Headers")
        return self.results
    
    def _process_findings(self, findings: list, category: str):
        """Process and store test findings."""
        for finding in findings:
            finding["category"] = category
            self.results["findings"].append(finding)
            self.results["tests_run"] += 1
            
            if finding.get("passed", False):
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
