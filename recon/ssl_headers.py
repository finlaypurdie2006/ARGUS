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


def _insecure_ssl_context() -> ssl.SSLContext:
    """SSL context for *inspecting* a certificate, not validating trust.

    We deliberately disable hostname/cert verification — the point of this tool is to
    report on whatever certificate a host presents (including self-signed or expired
    ones), not to refuse to look at it the way a browser would.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_ssl_certificate(target: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Connect over TLS and pull certificate details. Sets 'error' if no TLS service is present."""
    result = {"target": target, "port": port, "command": f"TLS handshake inspection on {target}:{port}"}
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with _insecure_ssl_context().wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert()
                result["protocol"] = tls.version()
                cipher = tls.cipher()
                result["cipher"] = cipher[0] if cipher else None

                if not cert:
                    result["note"] = "TLS handshake succeeded but no certificate details were returned."
                    return result

                # ssl.getpeercert() returns subject/issuer as a tuple of single-attribute
                # RDNs, e.g. (((commonName, 'example.com'),), ((org, 'Example'),)).
                # Taking x[0] from each RDN and feeding that into dict() flattens this
                # into a normal {attribute: value} dict for the common case of one
                # attribute per RDN (true for commonName/organizationName etc. here).
                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")

                if cert.get("notAfter"):
                    try:
                        # cert dates come back in OpenSSL's fixed ASN.1 display format,
                        # e.g. "Jun 21 12:00:00 2026 GMT" — not ISO 8601.
                        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.datetime.utcnow()).days
                        result["days_until_expiry"] = days_left
                        result["expired"] = days_left < 0
                    except ValueError:
                        pass  # unexpected date format — leave days_until_expiry/expired unset rather than guess
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"No TLS service reachable on port {port}: {e}"
    return result


def _check_headers(target: str, port: int, use_https: bool, timeout: float) -> dict:
    scheme = "https" if use_https else "http"
    result = {"target": target, "scheme": scheme, "port": port,
              "command": f"GET {scheme}://{target}:{port}/ (security header check)"}

    conn = None
    try:
        if use_https:
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=_insecure_ssl_context())
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)

        conn.request("GET", "/", headers={"User-Agent": "ARGUS-recon"})
        resp = conn.getresponse()
        headers = dict(resp.getheaders())

        result["status_code"] = resp.status
        result["present_headers"] = {h: headers[h] for h in RECOMMENDED_HEADERS if h in headers}
        result["missing_headers"] = [h for h in RECOMMENDED_HEADERS if h not in headers]
        result["server_header"] = headers.get("Server", "")
    except Exception as e:
        result["error"] = f"Could not connect via {scheme} on port {port}: {e}"
    finally:
        # http.client.HTTPConnection has no context-manager support (no __enter__/__exit__),
        # so close it explicitly — otherwise a failed request() after connect() leaks the socket.
        if conn is not None:
            conn.close()
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
