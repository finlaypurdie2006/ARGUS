"""TLS certificate inspection and HTTP security header checks — stdlib only, no external tools."""
import datetime
import http.client
import socket
import ssl

RECOMMENDED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def get_ssl_certificate(target: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Connect over TLS and pull certificate details. Sets 'error' if no TLS service is present."""
    result = {"target": target, "port": port, "command": f"TLS handshake inspection on {target}:{port}"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # inspecting, not validating trust
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert()
                result["protocol"] = tls.version()
                cipher = tls.cipher()
                result["cipher"] = cipher[0] if cipher else None
                if cert:
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["not_before"] = cert.get("notBefore")
                    result["not_after"] = cert.get("notAfter")
                    if cert.get("notAfter"):
                        try:
                            expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.datetime.utcnow()).days
                            result["days_until_expiry"] = days_left
                            result["expired"] = days_left < 0
                        except ValueError:
                            pass
                else:
                    result["note"] = "TLS handshake succeeded but no certificate details were returned."
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"No TLS service reachable on port {port}: {e}"
    return result


def _check_headers(target: str, port: int, use_https: bool, timeout: float) -> dict:
    scheme = "https" if use_https else "http"
    result = {"target": target, "scheme": scheme, "port": port,
              "command": f"GET {scheme}://{target}:{port}/ (security header check)"}
    try:
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "ARGUS-recon"})
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()

        result["status_code"] = resp.status
        result["present_headers"] = {h: headers[h] for h in RECOMMENDED_HEADERS if h in headers}
        result["missing_headers"] = [h for h in RECOMMENDED_HEADERS if h not in headers]
        result["server_header"] = headers.get("Server", "")
    except Exception as e:
        result["error"] = f"Could not connect via {scheme} on port {port}: {e}"
    return result


def check_security_headers_auto(target: str, https_port: int = 443, http_port: int = 80,
                                 timeout: float = 8.0) -> dict:
    """Try HTTPS first; fall back to plain HTTP if HTTPS isn't reachable."""
    res = _check_headers(target, https_port, use_https=True, timeout=timeout)
    if res.get("error"):
        res_http = _check_headers(target, http_port, use_https=False, timeout=timeout)
        if not res_http.get("error"):
            return res_http
    return res
