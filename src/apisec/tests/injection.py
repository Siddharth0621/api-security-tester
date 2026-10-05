"""Injection security tests."""


class InjectionTests:
    """Tests for injection vulnerabilities."""
    
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "1; DROP TABLE users--",
        "1 UNION SELECT * FROM users",
        "' WAITFOR DELAY '0:0:5'--",
    ]
    
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
    ]
    
    COMMAND_PAYLOADS = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
        "; sleep 5",
    ]
    
    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0
    
    def run(self) -> list:
        """Run all injection tests."""
        self.tests_run = 3
        self.test_sql_injection()
        self.test_nosql_injection()
        self.test_command_injection()
        return self.findings
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities."""
        for endpoint in self.tester.endpoints:
            path = endpoint["path"]
            methods = endpoint.get("methods", ["GET"])
            
            for payload in self.SQL_PAYLOADS:
                # Test in query parameters
                if "GET" in methods:
                    try:
                        response = self.tester._make_request(
                            "GET",
                            f"{path}?id={payload}&search={payload}"
                        )
                        
                        # Check for SQL error messages
                        error_indicators = [
                            "sql syntax",
                            "mysql",
                            "postgresql",
                            "sqlite",
                            "ora-",
                            "syntax error",
                        ]
                        
                        response_lower = response.text.lower()
                        for indicator in error_indicators:
                            if indicator in response_lower:
                                self.findings.append({
                                    "test": "SQL Injection",
                                    "endpoint": path,
                                    "severity": "critical",
                                    "description": f"Potential SQL injection - error message exposed",
                                    "passed": False,
                                    "evidence": {
                                        "payload": payload,
                                        "indicator": indicator,
                                    },
                                })
                                break
                    except Exception:
                        pass
                
                # Test in POST body
                if "POST" in methods:
                    try:
                        response = self.tester._make_request(
                            "POST",
                            path,
                            json={"id": payload, "query": payload}
                        )
                        
                        response_lower = response.text.lower()
                        for indicator in ["sql", "syntax error", "mysql", "postgres"]:
                            if indicator in response_lower:
                                self.findings.append({
                                    "test": "SQL Injection (POST)",
                                    "endpoint": path,
                                    "severity": "critical",
                                    "description": "Potential SQL injection in POST body",
                                    "passed": False,
                                    "evidence": {
                                        "payload": payload,
                                    },
                                })
                                break
                    except Exception:
                        pass
    
    def test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities."""
        for endpoint in self.tester.endpoints:
            path = endpoint["path"]
            
            for payload in self.NOSQL_PAYLOADS:
                try:
                    response = self.tester._make_request(
                        "POST",
                        path,
                        json={"filter": payload}
                    )
                    
                    # Check for MongoDB-style errors
                    if "mongodb" in response.text.lower() or "bson" in response.text.lower():
                        self.findings.append({
                            "test": "NoSQL Injection",
                            "endpoint": path,
                            "severity": "critical",
                            "description": "Potential NoSQL injection vulnerability",
                            "passed": False,
                            "evidence": {
                                "payload": payload,
                            },
                        })
                except Exception:
                    pass
    
    def test_command_injection(self):
        """Test for command injection vulnerabilities."""
        for endpoint in self.tester.endpoints:
            path = endpoint["path"]
            
            for payload in self.COMMAND_PAYLOADS:
                try:
                    response = self.tester._make_request(
                        "GET",
                        f"{path}?cmd={payload}&file={payload}"
                    )
                    
                    # Check for command output indicators
                    indicators = ["root:", "uid=", "total ", "drwx"]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            self.findings.append({
                                "test": "Command Injection",
                                "endpoint": path,
                                "severity": "critical",
                                "description": "Command injection vulnerability detected",
                                "passed": False,
                                "evidence": {
                                    "payload": payload,
                                    "indicator": indicator,
                                },
                            })
                            break
                except Exception:
                    pass
