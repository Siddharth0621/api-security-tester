"""Authentication security tests."""

import re


class AuthenticationTests:
    """Tests for authentication vulnerabilities."""
    
    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0
    
    def run(self) -> list:
        """Run all authentication tests."""
        self.tests_run = 4
        
        self.test_missing_auth()
        self.test_invalid_token()
        self.test_token_in_url()
        self.test_weak_token_entropy()
        return self.findings
    
    def test_missing_auth(self):
        """Test if endpoints are accessible without authentication."""
        # Save current auth
        original_auth = self.tester.session.headers.get("Authorization")
        
        # Remove auth
        if "Authorization" in self.tester.session.headers:
            del self.tester.session.headers["Authorization"]
        
        for endpoint in self.tester.endpoints:
            if endpoint.get("auth_required", True):
                path = endpoint["path"]
                try:
                    response = self.tester._make_request("GET", path)
                    
                    if response.status_code == 200:
                        self.findings.append({
                            "test": "Missing Authentication",
                            "endpoint": path,
                            "severity": "high",
                            "description": f"Endpoint {path} accessible without authentication (got {response.status_code})",
                            "passed": False,
                            "evidence": {
                                "status_code": response.status_code,
                                "response_preview": response.text[:200],
                            },
                        })
                    else:
                        self.findings.append({
                            "test": "Missing Authentication",
                            "endpoint": path,
                            "severity": "info",
                            "description": f"Endpoint {path} correctly requires authentication",
                            "passed": True,
                        })
                except Exception as e:
                    pass
        
        # Restore auth
        if original_auth:
            self.tester.session.headers["Authorization"] = original_auth
    
    def test_invalid_token(self):
        """Test response to invalid authentication tokens."""
        original_auth = self.tester.session.headers.get("Authorization")
        
        invalid_tokens = [
            "Bearer invalid_token_123",
            "Bearer ",
            "InvalidFormat",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
        ]
        
        for token in invalid_tokens:
            self.tester.session.headers["Authorization"] = token
            
            for endpoint in self.tester.endpoints[:1]:  # Test first endpoint
                if not endpoint.get("auth_required", True):
                    continue

                path = endpoint["path"]
                try:
                    response = self.tester._make_request("GET", path)
                    
                    if response.status_code == 200:
                        self.findings.append({
                            "test": "Invalid Token Accepted",
                            "endpoint": path,
                            "severity": "critical",
                            "description": f"Endpoint accepts invalid token: {token[:30]}...",
                            "passed": False,
                            "evidence": {
                                "token_used": token,
                                "status_code": response.status_code,
                            },
                        })
                except Exception:
                    pass
        
        if original_auth:
            self.tester.session.headers["Authorization"] = original_auth
    
    def test_token_in_url(self):
        """Check if API accepts tokens in URL parameters (insecure)."""
        if not self.tester.auth_token:
            return
        
        original_auth = self.tester.session.headers.get("Authorization")
        if "Authorization" in self.tester.session.headers:
            del self.tester.session.headers["Authorization"]
        
        for endpoint in self.tester.endpoints[:1]:
            path = endpoint["path"]
            try:
                # Try token in URL
                token = self.tester.auth_token.replace("Bearer ", "")
                response = self.tester._make_request("GET", f"{path}?token={token}")
                
                if response.status_code == 200:
                    self.findings.append({
                        "test": "Token in URL",
                        "endpoint": path,
                        "severity": "medium",
                        "description": "API accepts authentication token in URL parameter (logged in access logs)",
                        "passed": False,
                    })
            except Exception:
                pass
        
        if original_auth:
            self.tester.session.headers["Authorization"] = original_auth
    
    def test_weak_token_entropy(self):
        """Check if the token has sufficient entropy."""
        if not self.tester.auth_token:
            return
        
        token = self.tester.auth_token.replace("Bearer ", "")
        
        # Check for common weak patterns
        weak_patterns = [
            r"^[0-9]+$",  # Only numbers
            r"^[a-z]+$",  # Only lowercase
            r"^(test|demo|admin|user)",  # Common prefixes
        ]
        
        for pattern in weak_patterns:
            if re.match(pattern, token, re.IGNORECASE):
                self.findings.append({
                    "test": "Weak Token",
                    "severity": "medium",
                    "description": "Authentication token appears to have weak entropy",
                    "passed": False,
                })
                return
        
        # Check minimum length
        if len(token) < 32:
            self.findings.append({
                "test": "Short Token",
                "severity": "low",
                "description": f"Token length ({len(token)}) may be too short for security",
                "passed": False,
            })
