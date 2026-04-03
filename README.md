# API Security Tester

Automated security testing tool for REST APIs. Detect common vulnerabilities based on OWASP API Security Top 10.

## Features

- **Authentication Testing** - Broken authentication, weak tokens, session issues
- **Authorization Testing** - BOLA/IDOR, privilege escalation, function-level access
- **Injection Testing** - SQL injection, NoSQL injection, command injection
- **Rate Limiting** - Brute force protection, resource exhaustion
- **Data Exposure** - Sensitive data in responses, verbose errors
- **Mass Assignment** - Parameter pollution, unexpected properties
- **Security Headers** - Missing or misconfigured headers

## Installation

```bash
# Clone the repository
git clone https://github.com/prateek-ydv/api-security-tester.git
cd api-security-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install CLI
pip install -e .
```

## Quick Start

```bash
# Run all tests against an API
apisec scan --url https://api.example.com --config config.yaml

# Run specific test category
apisec scan --url https://api.example.com --test auth

# Test with authentication
apisec scan --url https://api.example.com --token "Bearer xxx"

# Generate HTML report
apisec scan --url https://api.example.com --report report.html
```

## Configuration

Create a `config.yaml` file:

```yaml
target:
  base_url: https://api.example.com
  version: v1

authentication:
  type: bearer  # bearer, basic, api_key
  token: ${API_TOKEN}  # Environment variable
  # Or for API key:
  # header: X-API-Key
  # value: ${API_KEY}

endpoints:
  - path: /users
    methods: [GET, POST]
    auth_required: true
    params:
      - name: id
        type: integer
        location: path
  
  - path: /users/{id}
    methods: [GET, PUT, DELETE]
    auth_required: true
    
  - path: /public/status
    methods: [GET]
    auth_required: false

tests:
  authentication:
    enabled: true
    test_invalid_tokens: true
    test_expired_tokens: true
    test_missing_auth: true
  
  authorization:
    enabled: true
    test_idor: true
    test_privilege_escalation: true
    
  injection:
    enabled: true
    payloads: default  # or path to custom payloads
    
  rate_limiting:
    enabled: true
    requests_per_test: 100
    
  headers:
    enabled: true

reporting:
  format: html  # html, json, markdown
  output: reports/
  include_evidence: true
```

## Test Categories

### 1. Authentication Tests (OWASP API1)

```bash
apisec scan --url https://api.example.com --test auth
```

Tests performed:
- Missing authentication header
- Invalid/malformed tokens
- Expired tokens
- Weak token entropy
- Token in URL parameters
- Session fixation

### 2. Authorization Tests (OWASP API2, API5)

```bash
apisec scan --url https://api.example.com --test authz
```

Tests performed:
- BOLA/IDOR (accessing other users' resources)
- Horizontal privilege escalation
- Vertical privilege escalation
- Function-level access control

### 3. Injection Tests (OWASP API8)

```bash
apisec scan --url https://api.example.com --test injection
```

Tests performed:
- SQL injection
- NoSQL injection
- Command injection
- LDAP injection
- XPath injection

### 4. Rate Limiting Tests (OWASP API4)

```bash
apisec scan --url https://api.example.com --test ratelimit
```

Tests performed:
- Brute force resistance
- Resource exhaustion
- Missing rate limits
- Rate limit bypass techniques

### 5. Data Exposure Tests (OWASP API3)

```bash
apisec scan --url https://api.example.com --test exposure
```

Tests performed:
- Sensitive data in responses
- Excessive data exposure
- Verbose error messages
- Debug information leakage

### 6. Security Headers Test

```bash
apisec scan --url https://api.example.com --test headers
```

Checks for:
- Content-Type validation
- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security
- Content-Security-Policy
- CORS configuration

## Usage Examples

### Basic Scan

```bash
# Scan with default tests
apisec scan --url https://api.example.com

# Output:
# 🔍 API Security Tester v1.0.0
# Target: https://api.example.com
# 
# [1/6] Authentication Tests...
#   ✓ Token validation: PASS
#   ✗ Missing auth header: FAIL (returns 200 instead of 401)
#
# [2/6] Authorization Tests...
#   ✗ IDOR on /users/{id}: FAIL (can access other users)
# ...
```

### With Custom Endpoints

```python
from apisec import APISecurityTester

tester = APISecurityTester(
    base_url="https://api.example.com",
    auth_token="Bearer xxx"
)

# Add endpoints to test
tester.add_endpoint("/users", methods=["GET", "POST"])
tester.add_endpoint("/users/{id}", methods=["GET", "PUT", "DELETE"])

# Run tests
results = tester.run_all()

# Generate report
tester.generate_report("report.html")
```

### CI/CD Integration

```yaml
# .github/workflows/api-security.yml
name: API Security Tests

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install apisec
        run: pip install api-security-tester
      
      - name: Run security tests
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          apisec scan \
            --url ${{ vars.API_URL }} \
            --token "Bearer $API_TOKEN" \
            --config security-config.yaml \
            --report report.html \
            --fail-on high
      
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.html
```

## Report Example

The tool generates detailed reports:

```
# API Security Test Report

**Target:** https://api.example.com
**Date:** 2024-01-15 14:30:00
**Tests Run:** 45
**Issues Found:** 3

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 1     |
| Medium   | 1     |
| Low      | 0     |

## Findings

### [CRITICAL] IDOR Vulnerability - /users/{id}

**Description:** The endpoint allows access to other users' data by changing the ID parameter.

**Evidence:**
- Request: GET /users/456 (with user 123's token)
- Response: 200 OK with user 456's data

**Remediation:** Implement proper authorization checks to verify the requesting user has access to the resource.

### [HIGH] Missing Authentication - /admin/config

**Description:** Administrative endpoint accessible without authentication.
...
```

## Custom Payloads

Create custom injection payloads:

```yaml
# custom-payloads.yaml
sql_injection:
  - "' OR '1'='1"
  - "1; DROP TABLE users--"
  - "1 UNION SELECT * FROM users"

nosql_injection:
  - '{"$gt": ""}'
  - '{"$ne": null}'
  
command_injection:
  - "; ls -la"
  - "| cat /etc/passwd"
  - "`whoami`"
```

Use with:
```bash
apisec scan --url https://api.example.com --payloads custom-payloads.yaml
```

## License

MIT License - see [LICENSE](LICENSE)

---

Built by [Prateek Yadav](https://github.com/prateek-ydv) | DevSecOps Engineer
