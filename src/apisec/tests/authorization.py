"""Authorization security tests."""

import re


class AuthorizationTests:
    """Tests for authorization vulnerabilities (BOLA/IDOR)."""
    
    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0
    
    def run(self) -> list:
        """Run all authorization tests."""
        self.tests_run = 2
        self.test_idor()
        self.test_http_method_override()
        return self.findings
    
    def test_idor(self):
        """Test for Insecure Direct Object Reference vulnerabilities."""
        for endpoint in self.tester.endpoints:
            path = endpoint["path"]
            
            # Check if endpoint has ID parameter
            if "{id}" in path or re.search(r"/\d+", path):
                # Try accessing with different IDs
                test_ids = ["1", "2", "999", "0", "-1", "admin"]
                
                for test_id in test_ids:
                    test_path = re.sub(r"\{id\}", test_id, path)
                    test_path = re.sub(r"/\d+", f"/{test_id}", test_path)
                    
                    try:
                        response = self.tester._make_request("GET", test_path)
                        
                        if response.status_code == 200:
                            # This might be IDOR - would need context to confirm
                            self.findings.append({
                                "test": "Potential IDOR",
                                "endpoint": test_path,
                                "severity": "high",
                                "description": f"Successfully accessed {test_path} - verify if this should be allowed",
                                "passed": False,
                                "evidence": {
                                    "status_code": response.status_code,
                                    "test_id": test_id,
                                },
                            })
                    except Exception:
                        pass
    
    def test_http_method_override(self):
        """Test if HTTP method can be overridden via headers."""
        override_headers = [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
        ]
        
        for endpoint in self.tester.endpoints[:1]:
            path = endpoint["path"]
            
            for header in override_headers:
                try:
                    # Try to override GET to DELETE
                    response = self.tester._make_request(
                        "GET", 
                        path,
                        headers={header: "DELETE"}
                    )
                    
                    # If we get a different response, method override might work
                    normal_response = self.tester._make_request("GET", path)
                    
                    if response.status_code != normal_response.status_code:
                        self.findings.append({
                            "test": "HTTP Method Override",
                            "endpoint": path,
                            "severity": "medium",
                            "description": f"HTTP method override possible via {header}",
                            "passed": False,
                            "evidence": {
                                "header": header,
                                "original_status": normal_response.status_code,
                                "override_status": response.status_code,
                            },
                        })
                except Exception:
                    pass
