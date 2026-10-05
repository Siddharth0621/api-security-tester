"""Rate limiting security tests."""

import time
from concurrent.futures import ThreadPoolExecutor


class RateLimitTests:
    """Tests for rate limiting vulnerabilities."""
    
    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0
    
    def run(self) -> list:
        """Run all rate limit tests."""
        self.tests_run = 2
        self.test_rate_limit_exists()
        self.test_rate_limit_bypass()
        return self.findings
    
    def test_rate_limit_exists(self):
        """Test if rate limiting is implemented."""
        if not self.tester.endpoints:
            return

        endpoint = self.tester.endpoints[0]

        if not endpoint.get("auth_required", True):
            return  
    
        path = endpoint["path"]
        
        # Send rapid requests
        num_requests = 50
        success_count = 0
        rate_limited = False
        
        start_time = time.time()
        
        for i in range(num_requests):
            try:
                response = self.tester._make_request("GET", path)
                
                if response.status_code == 429:
                    rate_limited = True
                    break
                elif response.status_code in [200, 401, 403]:
                    success_count += 1
            except Exception:
                pass
        
        elapsed = time.time() - start_time
        
        if not rate_limited and success_count > 40:
            self.findings.append({
                "test": "Missing Rate Limit",
                "endpoint": path,
                "severity": "medium",
                "description": f"No rate limiting detected after {num_requests} requests in {elapsed:.2f}s",
                "passed": False,
                "evidence": {
                    "requests_sent": num_requests,
                    "successful": success_count,
                    "time_elapsed": elapsed,
                },
            })
        elif rate_limited:
            self.findings.append({
                "test": "Rate Limiting",
                "endpoint": path,
                "severity": "info",
                "description": "Rate limiting is implemented",
                "passed": True,
            })
    
    def test_rate_limit_bypass(self):
        """Test common rate limit bypass techniques."""
        if not self.tester.endpoints:
            return
        
        endpoint = self.tester.endpoints[0]

        if not endpoint.get("auth_required", True):
            return
        
        path = endpoint["path"]
        
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
        ]
        
        for headers in bypass_headers:
            # First, try to trigger rate limit
            for _ in range(30):
                try:
                    self.tester._make_request("GET", path)
                except Exception:
                    pass
            
            # Now try with bypass header
            try:
                response = self.tester._make_request("GET", path, headers=headers)
                
                if response.status_code != 429:
                    self.findings.append({
                        "test": "Rate Limit Bypass",
                        "endpoint": path,
                        "severity": "high",
                        "description": f"Rate limit may be bypassable with header: {list(headers.keys())[0]}",
                        "passed": False,
                        "evidence": {
                            "bypass_header": headers,
                            "status_code": response.status_code,
                        },
                    })
            except Exception:
                pass
