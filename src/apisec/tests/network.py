"""Network connectivity and TLS validation tests."""

import socket
import ssl
from urllib.parse import urlparse


class NetworkTests:
    """Tests for basic network and TLS connectivity."""

    def __init__(self, tester):
        self.tester = tester
        self.findings = []
        self.tests_run = 0

    def run(self) -> list:
        """Run all network tests."""
        self.tests_run = 4
        self.test_dns_resolution()
        self.test_tcp_connectivity()
        self.test_http_reachability()
        self.test_tls_configuration()
        return self.findings

    def test_dns_resolution(self):
        """Validate hostname resolution."""
        parsed = urlparse(self.tester.base_url)
        hostname = parsed.hostname

        if not hostname:
            return

        try:
            socket.gethostbyname(hostname)
            self.findings.append({
                "test": "DNS Resolution",
                "endpoint": hostname,
                "severity": "info",
                "description": f"Hostname {hostname} resolved successfully",
                "passed": True,
            })
        except socket.gaierror as e:
            self.findings.append({
                "test": "DNS Resolution",
                "endpoint": hostname,
                "severity": "high",
                "description": f"Hostname resolution failed: {e}",
                "passed": False,
            })

    def test_tcp_connectivity(self):
        """Validate TCP connectivity to the target."""
        parsed = urlparse(self.tester.base_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not hostname:
            return

        try:
            with socket.create_connection((hostname, port), timeout=5):
                self.findings.append({
                    "test": "TCP Connectivity",
                    "endpoint": f"{hostname}:{port}",
                    "severity": "info",
                    "description": "TCP connection established successfully",
                    "passed": True,
                })
        except (socket.timeout, OSError) as e:
            self.findings.append({
                "test": "TCP Connectivity",
                "endpoint": f"{hostname}:{port}",
                "severity": "high",
                "description": f"TCP connection failed: {e}",
                "passed": False,
            })

    def test_http_reachability(self):
        """Validate HTTP/HTTPS application reachability."""
        try:
            path = self.tester.endpoints[0]["path"] if self.tester.endpoints else "/"
            response = self.tester._make_request("GET", path)
            self.findings.append({
                "test": "HTTP Reachability",
                "endpoint": self.tester.base_url,
                "severity": "info",
                "description": f"HTTP request returned status {response.status_code}",
                "passed": response.status_code < 500,
            })
        except Exception as e:
            self.findings.append({
                "test": "HTTP Reachability",
                "endpoint": self.tester.base_url,
                "severity": "high",
                "description": f"HTTP request failed: {e}",
                "passed": False,
            })

    def test_tls_configuration(self):
        """Check basic TLS connectivity for HTTPS targets."""
        parsed = urlparse(self.tester.base_url)

        if parsed.scheme != "https":
            return

        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cipher = tls_sock.cipher()

            self.findings.append({
                "test": "TLS Configuration",
                "endpoint": f"{hostname}:{port}",
                "severity": "info",
                "description": f"TLS connection established using {cipher[0]}",
                "passed": True,
            })
        except (ssl.SSLError, OSError) as e:
            self.findings.append({
                "test": "TLS Configuration",
                "endpoint": f"{hostname}:{port}",
                "severity": "high",
                "description": f"TLS connection failed: {e}",
                "passed": False,
            })