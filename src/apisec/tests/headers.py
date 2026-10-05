"""Security headers tests."""


class HeaderTests:
    """Tests for security headers."""

    REQUIRED_HEADERS = {
        "X-Content-Type-Options": {
            "expected": "nosniff",
            "severity": "medium",
            "description": "Prevents MIME type sniffing",
        },
        "X-Frame-Options": {
            "expected": ["DENY", "SAMEORIGIN"],
            "severity": "medium",
            "description": "Prevents clickjacking attacks",
        },
        "Strict-Transport-Security": {
            "expected": None,
            "severity": "high",
            "description": "Enforces HTTPS connections",
        },
        "Content-Security-Policy": {
            "expected": None,
            "severity": "medium",
            "description": "Prevents XSS and injection attacks",
        },
        "X-XSS-Protection": {
            "expected": "1; mode=block",
            "severity": "low",
            "description": "Legacy XSS protection (deprecated but still useful)",
        },
    }

    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0

    def run(self) -> list:
        """Run all header tests."""
        self.tests_run = 3
        self.test_security_headers()
        self.test_cors_configuration()
        self.test_cache_headers()
        return self.findings

    def test_security_headers(self):
        """Check for required security headers."""
        if not self.tester.endpoints:
            return

        for endpoint in self.tester.endpoints:
            path = endpoint["path"]

            try:
                response = self.tester._make_request("GET", path)
                headers = response.headers

                for header_name, config in self.REQUIRED_HEADERS.items():
                    if header_name not in headers:
                        self.findings.append({
                            "test": f"Missing {header_name}",
                            "endpoint": path,
                            "severity": config["severity"],
                            "description": (
                                f"Missing security header: {header_name} - "
                                f"{config['description']}"
                            ),
                            "evidence": {
                                "header": header_name,
                                "status_code": response.status_code,
                                "present": False,
                            },
                            "passed": False,
                        })

                    elif config["expected"]:
                        value = headers[header_name]
                        expected = config["expected"]

                        if isinstance(expected, list):
                            if value not in expected:
                                self.findings.append({
                                    "test": f"Weak {header_name}",
                                    "endpoint": path,
                                    "severity": config["severity"],
                                    "description": (
                                        f"{header_name} has weak value: {value}"
                                    ),
                                    "evidence": {
                                        "header": header_name,
                                        "actual_value": value,
                                        "expected_values": expected,
                                        "status_code": response.status_code,
                                    },
                                    "passed": False,
                                })

                        elif value != expected:
                            self.findings.append({
                                "test": f"Incorrect {header_name}",
                                "endpoint": path,
                                "severity": config["severity"],
                                "description": (
                                    f"{header_name} should be '{expected}', "
                                    f"got '{value}'"
                                ),
                                "evidence": {
                                    "header": header_name,
                                    "actual_value": value,
                                    "expected_value": expected,
                                    "status_code": response.status_code,
                                },
                                "passed": False,
                            })

            except Exception:
                pass

    def test_cors_configuration(self):
        """Test CORS configuration for security issues."""
        if not self.tester.endpoints:
            return

        endpoint = self.tester.endpoints[0]
        path = endpoint["path"]

        try:
            response = self.tester._make_request(
                "OPTIONS",
                path,
                headers={"Origin": "https://evil.com"}
            )

            cors_header = response.headers.get(
                "Access-Control-Allow-Origin", ""
            )

            if cors_header == "*":
                self.findings.append({
                    "test": "CORS Wildcard",
                    "endpoint": path,
                    "severity": "medium",
                    "description": (
                        "CORS allows any origin (*) - may expose sensitive data"
                    ),
                    "passed": False,
                    "evidence": {
                        "allow_origin": cors_header,
                        "status_code": response.status_code,
                    },
                })

            elif cors_header == "https://evil.com":
                self.findings.append({
                    "test": "CORS Reflection",
                    "endpoint": path,
                    "severity": "high",
                    "description": (
                        "CORS reflects any Origin header - "
                        "vulnerable to cross-origin attacks"
                    ),
                    "passed": False,
                    "evidence": {
                        "allow_origin": cors_header,
                        "request_origin": "https://evil.com",
                        "status_code": response.status_code,
                    },
                })

            allow_creds = response.headers.get(
                "Access-Control-Allow-Credentials", ""
            )

            if cors_header == "*" and allow_creds.lower() == "true":
                self.findings.append({
                    "test": "CORS Credentials with Wildcard",
                    "endpoint": path,
                    "severity": "high",
                    "description": (
                        "CORS allows credentials with wildcard origin"
                    ),
                    "passed": False,
                    "evidence": {
                        "allow_origin": cors_header,
                        "allow_credentials": allow_creds,
                        "status_code": response.status_code,
                    },
                })

        except Exception:
            pass

    def test_cache_headers(self):
        """Test cache headers for sensitive endpoints."""
        for endpoint in self.tester.endpoints:
            if not endpoint.get("auth_required", True):
                continue

            path = endpoint["path"]

            try:
                response = self.tester._make_request("GET", path)

                cache_control = response.headers.get("Cache-Control", "")
                pragma = response.headers.get("Pragma", "")

                sensitive_indicators = [
                    "no-store",
                    "no-cache",
                    "private",
                ]

                has_protection = any(
                    indicator in cache_control.lower()
                    for indicator in sensitive_indicators
                )

                if not has_protection:
                    self.findings.append({
                        "test": "Insecure Cache",
                        "endpoint": path,
                        "severity": "low",
                        "description": (
                            "Authenticated endpoint may be cached - "
                            "consider adding Cache-Control: no-store"
                        ),
                        "passed": False,
                        "evidence": {
                            "cache_control": cache_control or "Not set",
                            "pragma": pragma or "Not set",
                        },
                    })

            except Exception:
                pass