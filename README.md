# API Security Tester

A Python-based API security testing tool for identifying common security issues in REST APIs.

This project was extended from the open-source `api-security-tester` project. The original MIT license is preserved.

## Features

- Authentication security testing
- Authorization and IDOR testing
- HTTP method override testing
- SQL injection testing
- NoSQL injection testing
- Command injection testing
- Rate-limit testing
- Sensitive data exposure detection
- Verbose error detection
- Debug information detection
- Security header validation
- CORS configuration checks
- Cache-control validation
- DNS resolution testing
- TCP connectivity testing
- HTTP/HTTPS reachability testing
- Basic TLS connectivity validation
- HTML, JSON and Markdown reports
- Security finding evidence in reports
- Configurable API endpoints using YAML
- Command-line interface

## Security Test Categories

The scanner currently executes 21 checks across 7 categories:

| Category | Checks |
|---|---:|
| Authentication | 4 |
| Authorization | 2 |
| Injection | 3 |
| Rate Limiting | 2 |
| Data Exposure | 3 |
| Security Headers | 3 |
| Network/TLS | 4 |
| **Total** | **21** |

## Requirements

- Python 3.10+
- pip
- Git

## Installation

Clone the repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd api-security-tester