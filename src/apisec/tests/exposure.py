"""Data exposure security tests."""

import re
import json


class ExposureTests:
    """Tests for excessive data exposure vulnerabilities."""
    
    SENSITIVE_PATTERNS = [
        (r"password", "Password field"),
        (r"passwd", "Password field"),
        (r"secret", "Secret field"),
        (r"api[_-]?key", "API key"),
        (r"token", "Token field"),
        (r"auth", "Auth field"),
        (r"credit[_-]?card", "Credit card"),
        (r"ssn|social[_-]?security", "SSN"),
        (r"private[_-]?key", "Private key"),
    ]
    
    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0
    
    def run(self) -> list:
        """Run all data exposure tests."""
        self.tests_run = 3
        self.test_sensitive_data_exposure()
        self.test_verbose_errors()
        self.test_debug_info()
        return self.findings
    
    def test_sensitive_data_exposure(self):
        """Check if API responses contain sensitive data."""
        for endpoint in self.tester.endpoints:
            path = endpoint["path"]
            
            try:
                response = self.tester._make_request("GET", path)
                
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    for pattern, field_name in self.SENSITIVE_PATTERNS:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            # Check if it's in a JSON response
                            try:
                                data = response.json()
                                if self._find_sensitive_keys(data, pattern):
                                    self.findings.append({
                                        "test": "Sensitive Data Exposure",
                                        "endpoint": path,
                                        "severity": "high",
                                        "description": f"{field_name} found in API response",
                                        "passed": False,
                                        "evidence": {
                                            "field_type": field_name,
                                            "pattern": pattern,
                                        },
                                    })
                            except json.JSONDecodeError:
                                pass
            except Exception:
                pass
    
    def _find_sensitive_keys(self, data, pattern, path=""):
        """Recursively search for sensitive keys in JSON data."""
        if isinstance(data, dict):
            for key, value in data.items():
                if re.search(pattern, key, re.IGNORECASE):
                    return True
                if self._find_sensitive_keys(value, pattern, f"{path}.{key}"):
                    return True
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if self._find_sensitive_keys(item, pattern, f"{path}[{i}]"):
                    return True
        return False
    
    def test_verbose_errors(self):
        """Check if API returns verbose error messages."""
        error_triggers = [
            ("GET", "/?id=", ["stacktrace", "stack trace", "exception", "traceback"]),
            ("GET", "/nonexistent-endpoint-12345", ["not found", "404"]),
            ("POST", "/", ["invalid", "error"]),
        ]
        
        for method, path_suffix, _ in error_triggers:
            full_path = (self.tester.endpoints[0]["path"] if self.tester.endpoints else "") + path_suffix
            
            try:
                response = self.tester._make_request(method, full_path)
                response_lower = response.text.lower()
                
                # Check for stack traces
                stack_indicators = [
                    "traceback",
                    "at line",
                    "stack trace",
                    "exception in",
                    ".py:",
                    ".js:",
                    "node_modules",
                    "vendor/",
                ]
                
                for indicator in stack_indicators:
                    if indicator in response_lower:
                        self.findings.append({
                            "test": "Verbose Error",
                            "endpoint": full_path,
                            "severity": "medium",
                            "description": f"Stack trace or debug info exposed in error response",
                            "passed": False,
                            "evidence": {
                                "indicator": indicator,
                                "response_preview": response.text[:500],
                            },
                        })
                        break
            except Exception:
                pass
    
    def test_debug_info(self):
        """Check for debug information in responses."""
        for endpoint in self.tester.endpoints:
            path = endpoint["path"]
            
            try:
                response = self.tester._make_request("GET", path)
                
                # Check headers for debug info
                debug_headers = [
                    "X-Debug",
                    "X-Debug-Token",
                    "X-Debug-Token-Link",
                    "Server",
                    "X-Powered-By",
                ]
                
                for header in debug_headers:
                    if header in response.headers:
                        value = response.headers[header]
                        if any(x in value.lower() for x in ["debug", "dev", "test", "php", "asp"]):
                            self.findings.append({
                                "test": "Debug Header",
                                "endpoint": path,
                                "severity": "low",
                                "description": f"Debug header exposed: {header}: {value}",
                                "passed": False,
                                "evidence": {
                                    "header": header,
                                    "value": value,
                                },
                            })
            except Exception:
                pass
