#!/usr/bin/env python3
"""
LIPAS - Lightweight Penetration Assessment Suite
Version 1.1.0

A modular web security assessment tool:
  - Subdomain enumeration (DNS + HTTP validation)
  - DNS reconnaissance, port scanning and banner grabbing
  - TLS certificate inspection
  - Technology fingerprinting and WAF/CDN detection
  - Error-based SQLi and reflected-XSS probing
  - CORS misconfiguration and risky HTTP method checks
  - Exposed sensitive file detection (.env, .git/HEAD, backups...)
  - Cookie, security-header and HTML comment analysis
  - security.txt discovery

Responsible use: only scan targets you own or have
explicit written permission to test. Unauthorized
scanning may be illegal.
"""

import argparse
import ipaddress
import json
import os
import tempfile
import logging
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urljoin, urlunparse

import dns.exception
import dns.resolver
import requests
import urllib3
from bs4 import BeautifulSoup, Comment
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import tldextract
except ImportError:  # optional: falls back to simple suffix handling
    tldextract = None

VERSION = "1.2.0"
log = logging.getLogger("lipas")

# Bundled public-suffix snapshot is used (no first-run network fetch).
_tld_extract = (
    tldextract.TLDExtract(suffix_list_urls=()) if tldextract else None
)

COMMON_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "com.br", "com.mx", "co.in", "com.sg", "co.nz", "co.ke",
}

DB_ERROR_PATTERNS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{4,5}|PostgreSQL.{0,40}ERROR|"
    r"unclosed quotation|sqlite3\.OperationalError|ODBC SQL Server Driver)",
    re.I,
)
SECRET_IN_COMMENT = re.compile(r"(password|passwd|api[_-]?key|secret|token)\s*[:=]", re.I)

XSS_CANARY = "lipasx7q<>\""
SQLI_PROBE = "' OR '1'='1"
CONTROL_VALUE = "lipasctrl"
EVIL_ORIGIN = "https://evil-cors-probe.example"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS (enforce HTTPS)",
    "Content-Security-Policy": "CSP (mitigate XSS/injection)",
    "X-Frame-Options": "clickjacking protection",
    "X-Content-Type-Options": "MIME-sniffing protection",
    "Referrer-Policy": "referrer control",
    "Permissions-Policy": "browser feature control",
}

SENSITIVE_PATHS = (
    "/.env", "/.git/HEAD", "/config.php~", "/config.bak", "/.htpasswd",
    "/wp-config.php.bak", "/backup.zip", "/.svn/entries", "/.DS_Store",
    "/server-status",
)

RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT")

DEFAULT_SUBDOMAINS = (
    "www", "mail", "ftp", "admin", "test", "dev", "stage", "api",
    "secure", "portal", "app", "blog", "shop", "staging", "beta",
    "panel", "dashboard", "status", "docs", "cdn", "m",
)

REMEDIATION = {
    "SQL Injection (error-based)":
        "Use parameterized queries/prepared statements; validate and encode all input.",
    "Reflected XSS (unescaped)":
        "Context-encode all output, add a Content-Security-Policy, never render raw input.",
    "Cookie Security":
        "Set HttpOnly, Secure (over HTTPS) and SameSite on all session cookies.",
    "Missing Security Header":
        "Add the header at the web server or framework middleware level.",
    "CORS Misconfiguration":
        "Allowlist trusted origins only; never reflect arbitrary origins with credentials.",
    "Risky HTTP Method":
        "Disable the method in the web server configuration if it is not required.",
    "Exposed Sensitive File":
        "Remove the file from the web root or block access; rotate any exposed secrets.",
    "Information Disclosure":
        "Strip sensitive data from comments, error messages and public metadata.",
}


@dataclass
class Config:
    """Centralized configuration."""
    max_threads: int = 15
    request_timeout: int = 20
    max_redirects: int = 5
    retry_attempts: int = 3
    rate_limit_delay: float = 0.5
    verify_tls: bool = True
    passive: bool = False
    common_ports: tuple = (80, 443, 8080, 8443, 22, 21)
    max_active_tests: int = 50
    user_agent: str = f"Lipas/{VERSION} (+https://github.com/abelmuturi-dev/LIPAS)"


# ---------------------------------------------------------------------------
# Input parsing helpers (pure functions, unit-testable)
# ---------------------------------------------------------------------------

def parse_cookie_string(raw):
    """Parse 'name=value; name2=value2' into a dict."""
    cookies = {}
    for pair in (raw or "").split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(f"invalid cookie pair (expected name=value): {pair!r}")
        name, value = pair.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def parse_header_strings(values):
    """Parse repeatable 'Name: value' flags (newlines accepted) into a dict."""
    headers = {}
    for chunk in values or []:
        for line in str(chunk).splitlines() or [str(chunk)]:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise ValueError(f"invalid header (expected 'Name: value'): {line!r}")
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def load_wordlist(path):
    """Load a subdomain wordlist file; one entry per line, '#' comments."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            entries = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError as exc:
        raise ValueError(f"cannot read wordlist {path!r}: {exc}") from exc
    if not entries:
        raise ValueError(f"wordlist {path!r} is empty")
    return entries


def fallback_base_domain(host):
    """Best-effort base domain when tldextract is unavailable."""
    try:
        ipaddress.ip_address(host)
        return host  # IP literal targets stay as-is
    except ValueError:
        pass
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in COMMON_SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

class ScannerCore:
    """Shared HTTP session factory + rate-limited request helper."""

    def __init__(self, config, cookies=None, headers=None):
        self.config = config
        self.session = self._build_session(cookies or {}, headers or {})
        self._lock = threading.Lock()
        self._last_request = 0.0

    def _build_session(self, cookies, headers):
        session = requests.Session()
        session.verify = self.config.verify_tls
        session.max_redirects = self.config.max_redirects
        retry = Retry(
            total=self.config.retry_attempts,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=self.config.max_threads,
            pool_maxsize=self.config.max_threads,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })
        session.cookies.update(cookies)
        session.headers.update(headers)
        return session

    def _request(self, method, url, **kwargs):
        """Rate-limited request wrapper shared by all scanners."""
        if self.config.rate_limit_delay > 0:
            with self._lock:
                wait = self.config.rate_limit_delay - (time.monotonic() - self._last_request)
                if wait > 0:
                    time.sleep(wait)
        kwargs.setdefault("timeout", self.config.request_timeout)
        resp = self.session.request(method, url, **kwargs)
        with self._lock:
            self._last_request = time.monotonic()
        return resp


class DomainScanner(ScannerCore):
    """Domain information gathering and subdomain enumeration."""

    def __init__(self, config, target, cookies=None, headers=None):
        super().__init__(config, cookies, headers)
        self.target = self._normalize_url(target)
        self.base_domain = self._extract_base_domain()

    @staticmethod
    def _normalize_url(url):
        url = url.strip()
        if not re.match(r"^https?://", url, re.I):
            url = "http://" + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _extract_base_domain(self):
        host = urlparse(self.target).netloc.split(":")[0]
        if _tld_extract is not None:
            extracted = _tld_extract(host)
            if extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            return extracted.domain or host
        return fallback_base_domain(host)

    # -- recon ----------------------------------------------------------------

    def gather_domain_info(self):
        """Collect DNS records, check common ports, grab banners and TLS info."""
        info = {
            "domain": self.base_domain, "ip": [], "mx": [],
            "nameservers": [], "ports": [], "banners": {}, "tls": None,
        }

        for rtype, key in (("A", "ip"), ("MX", "mx"), ("NS", "nameservers")):
            try:
                answers = dns.resolver.resolve(self.base_domain, rtype, lifetime=5)
                if rtype == "A":
                    info[key] = sorted({r.address for r in answers})
                elif rtype == "MX":
                    info[key] = sorted({str(r.exchange).rstrip(".") for r in answers})
                else:
                    info[key] = sorted({str(r).rstrip(".") for r in answers})
            except dns.exception.DNSException as exc:
                log.debug("%s record lookup failed: %s", rtype, exc)

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as pool:
            futures = [pool.submit(self._check_port, p) for p in self.config.common_ports]
            for future in as_completed(futures):
                port, is_open = future.result()  # use the returned port, not an index
                if is_open:
                    info["ports"].append(port)
        info["ports"].sort()

        for port in info["ports"]:
            banner = self.banner_grab(self.base_domain, port)
            if banner:
                info["banners"][str(port)] = banner

        parsed = urlparse(self.target)
        if parsed.scheme == "https":
            tls_port = parsed.port or 443  # TLS served on the target's own port
        elif 443 in info["ports"]:
            tls_port = 443
        elif 8443 in info["ports"]:
            tls_port = 8443
        else:
            tls_port = None
        if tls_port:
            info["tls"] = self.get_tls_info(tls_port)
        return info

    def _check_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                return port, sock.connect_ex((self.base_domain, port)) == 0
        except OSError as exc:
            log.debug("port %s check failed: %s", port, exc)
            return port, False

    def banner_grab(self, host, port):
        """Read a service banner; for HTTP ports send a HEAD probe."""
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                sock.settimeout(2)
                try:
                    banner = sock.recv(128)
                except socket.timeout:
                    banner = b""
                if not banner and port in (80, 443, 8080, 8443):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                    banner = sock.recv(128)
                return banner.decode("utf-8", "replace").strip("\r\n ")[:120] or None
        except OSError as exc:
            log.debug("banner grab %s:%s failed: %s", host, port, exc)
            return None

    def get_tls_info(self, port=443):
        """Basic TLS certificate details, or None if unavailable.

        Tries a verified handshake first; if the chain is untrusted
        (e.g. self-signed) the certificate is still decoded and reported
        with "certificate_trusted": false.
        """
        trusted = True
        try:
            with socket.create_connection((self.base_domain, port), timeout=5) as raw:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(raw, server_hostname=self.base_domain) as tls:
                    cert = tls.getpeercert()
        except (OSError, ssl.SSLError) as exc:
            log.debug("verified TLS handshake failed (%s); retrying unverified", exc)
            try:
                with socket.create_connection((self.base_domain, port), timeout=5) as raw:
                    ctx = ssl._create_unverified_context()
                    with ctx.wrap_socket(raw, server_hostname=self.base_domain) as tls:
                        der = tls.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tf:
                    tf.write(pem)
                    tmp = tf.name
                try:
                    cert = ssl._ssl._test_decode_cert(tmp)
                finally:
                    os.unlink(tmp)
                trusted = False
            except (OSError, ssl.SSLError, ValueError) as exc2:
                log.debug("TLS inspection failed: %s", exc2)
                return None
        not_after = cert.get("notAfter", "")
        days_left = None
        if not_after:
            days_left = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400
        return {
            "issuer": dict(x[0] for x in cert.get("issuer", ())),
            "subject": dict(x[0] for x in cert.get("subject", ())),
            "not_after": not_after,
            "days_until_expiry": round(days_left, 1) if days_left is not None else None,
            "sans": len(cert.get("subjectAltName", ())),
            "certificate_trusted": trusted,
        }

    # -- subdomains -------------------------------------------------------------

    def enumerate_subdomains(self, wordlist):
        """Resolve each candidate over DNS, then confirm with a real GET."""
        found = {}

        def check(sub):
            host = f"{sub}.{self.base_domain}"
            try:
                answers = dns.resolver.resolve(host, "A", lifetime=3)
            except dns.exception.DNSException:
                return
            ips = sorted({r.address for r in answers})

            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    resp = self._request("GET", url, stream=True)
                    status = resp.status_code
                    resp.close()
                    found[url] = {"status": status, "ips": ips}
                    log.info("[+] %s (HTTP %s)", url, status)
                    return
                except requests.RequestException as exc:
                    log.debug("%s unreachable: %s", url, exc)

            # Resolves in DNS but serves no HTTP - still worth reporting.
            key = f"http://{host}"
            found[key] = {"status": None, "ips": ips, "note": "DNS resolves; no HTTP response"}
            log.info("[+] %s (DNS only)", key)

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as pool:
            list(pool.map(check, wordlist))
        return dict(sorted(found.items()))


class VulnerabilityScanner(ScannerCore):
    """Web vulnerability and configuration analysis."""

    def __init__(self, config, target, base_domain, cookies=None, headers=None):
        super().__init__(config, cookies, headers)
        self.target = target
        self.base_domain = base_domain
        parsed = urlparse(target)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"

    def in_scope(self, url):
        host = urlparse(url).netloc.split(":")[0].lower()
        return host == self.base_domain or host.endswith("." + self.base_domain)

    def scan_website(self):
        results = {
            "technologies": {},
            "endpoints": [],
            "security_headers": [],
            "security_txt": {"present": False},
            "vulnerabilities": [],
        }
        try:
            resp = self._request("GET", self.target)
        except requests.RequestException as exc:
            log.error("could not fetch target %s: %s", self.target, exc)
            return results

        soup = BeautifulSoup(resp.text, "html.parser")
        results["technologies"] = self._detect_technologies(resp, soup)

        endpoints = set(self._find_endpoints(soup))
        endpoints.update(self._fetch_discovery_files())
        results["endpoints"] = sorted(endpoints)

        results["security_headers"] = self._check_security_headers(resp)
        results["security_txt"] = self._check_security_txt()
        results["vulnerabilities"].extend(self._check_cookies(resp))
        results["vulnerabilities"].extend(self._check_html_comments(soup))

        if not self.config.passive:
            results["vulnerabilities"].extend(self._check_cors())
            results["vulnerabilities"].extend(self._check_http_methods())
            results["vulnerabilities"].extend(self._check_sensitive_files())
            params = self._find_parameters(endpoints, soup)
            results["vulnerabilities"].extend(self._probe_sqli(params))
            results["vulnerabilities"].extend(self._probe_xss(params))
        else:
            log.info("passive mode: active probes disabled")
        return results

    # -- passive analysis -------------------------------------------------------

    def _detect_technologies(self, resp, soup):
        tech = {
            "server": resp.headers.get("Server", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
            "waf_cdn": [],
            "frameworks": [],
        }
        headers = {k.lower(): v for k, v in resp.headers.items()}
        if "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower():
            tech["waf_cdn"].append("Cloudflare")
        if any(h.startswith("x-sucuri") for h in headers):
            tech["waf_cdn"].append("Sucuri")
        if "x-waf" in headers or "x-web-application-firewall" in headers:
            tech["waf_cdn"].append("Generic WAF")
        if "awselb" in headers.get("server", "").lower() or "x-amz" in headers:
            tech["waf_cdn"].append("AWS ELB/CloudFront")

        text = str(soup).lower()
        indicators = {
            "WordPress": (r"wp-content", r"wp-includes"),
            "Joomla": (r"/components/com_", r"joomla"),
            "Drupal": (r"drupal", r"sites/default/files"),
            "Laravel": (r"csrf-token", r"laravel_session"),
            "React": (r"data-reactroot", r"react-dom"),
            "Angular": (r"ng-app", r"angular.min.js"),
        }
        for name, patterns in indicators.items():
            if any(re.search(p, text, re.I) for p in patterns):
                tech["frameworks"].append(name)
        return tech

    def _find_endpoints(self, soup):
        endpoints = set()
        for tag in soup.find_all(["a", "link", "script", "img", "form", "iframe"]):
            url = tag.get("href") or tag.get("src") or tag.get("action")
            if url and not url.startswith(("javascript:", "mailto:", "tel:", "#")):
                endpoints.add(urljoin(self.target, url))
        return endpoints

    def _fetch_discovery_files(self):
        """Pull URLs from robots.txt and sitemap.xml."""
        found = set()
        for path in ("/robots.txt", "/sitemap.xml"):
            try:
                resp = self._request("GET", self.origin + path)
            except requests.RequestException as exc:
                log.debug("could not fetch %s: %s", path, exc)
                continue
            if resp.status_code != 200:
                continue
            if path == "/robots.txt":
                for line in resp.text.splitlines():
                    if line.lower().startswith(("allow:", "disallow:")) and len(line) > 8:
                        loc = line.split(":", 1)[1].strip()
                        if loc and not loc.startswith(("http://", "https://")):
                            found.add(urljoin(self.origin, loc))
            else:
                for loc in re.findall(r"<loc>(.*?)</loc>", resp.text, re.I | re.S):
                    loc = loc.strip()
                    if self.in_scope(loc):
                        found.add(loc)
        return found

    def _check_security_headers(self, resp):
        findings = []
        for header, purpose in SECURITY_HEADERS.items():
            if header not in resp.headers:
                findings.append({
                    "type": "Missing Security Header",
                    "header": header,
                    "purpose": purpose,
                    "severity": "low",
                    "remediation": REMEDIATION["Missing Security Header"],
                })
        return findings

    def _check_security_txt(self):
        try:
            resp = self._request("GET", self.origin + "/.well-known/security.txt")
            if resp.status_code == 200 and "Contact:" in resp.text:
                contact = next(
                    (l.split(":", 1)[1].strip()
                     for l in resp.text.splitlines()
                     if l.lower().startswith("contact:")), "")
                return {"present": True, "contact": contact}
        except requests.RequestException as exc:
            log.debug("security.txt fetch failed: %s", exc)
        return {"present": False}

    def _check_cookies(self, resp):
        """Inspect Set-Cookie flags on the response jar."""
        issues = []
        is_https = urlparse(self.target).scheme == "https"
        for cookie in resp.cookies:
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append({
                    "type": "Cookie Security", "issue": "Missing HttpOnly flag",
                    "cookie": cookie.name, "severity": "medium",
                    "remediation": REMEDIATION["Cookie Security"],
                })
            if is_https and not cookie.secure:
                issues.append({
                    "type": "Cookie Security", "issue": "Missing Secure flag",
                    "cookie": cookie.name, "severity": "medium",
                    "remediation": REMEDIATION["Cookie Security"],
                })
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append({
                    "type": "Cookie Security", "issue": "Missing SameSite attribute",
                    "cookie": cookie.name, "severity": "low",
                    "remediation": REMEDIATION["Cookie Security"],
                })
        return issues

    def _check_html_comments(self, soup):
        findings = []
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(c).strip()
            if len(text) < 8:
                continue
            if SECRET_IN_COMMENT.search(text):
                findings.append({
                    "type": "Information Disclosure",
                    "issue": "Possible secret in HTML comment",
                    "excerpt": text[:120],
                    "severity": "medium",
                    "remediation": REMEDIATION["Information Disclosure"],
                })
                log.info("[!] Possible secret in HTML comment")
        return findings

    # -- active probes ----------------------------------------------------------

    def _check_cors(self):
        findings = []
        try:
            resp = self._request("GET", self.target, headers={"Origin": EVIL_ORIGIN})
        except requests.RequestException as exc:
            log.debug("CORS probe failed: %s", exc)
            return findings
        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if allow_origin == EVIL_ORIGIN and allow_creds:
            findings.append({
                "type": "CORS Misconfiguration",
                "issue": "Arbitrary origin reflected with credentials allowed",
                "severity": "high", "confidence": "high",
                "remediation": REMEDIATION["CORS Misconfiguration"],
            })
            log.info("[!] CORS: arbitrary origin reflected with credentials")
        elif allow_origin == "*":
            findings.append({
                "type": "CORS Misconfiguration",
                "issue": "Wildcard ACAO origin",
                "severity": "low", "confidence": "medium",
                "remediation": REMEDIATION["CORS Misconfiguration"],
            })
        return findings

    def _check_http_methods(self):
        findings = []
        try:
            resp = self._request("OPTIONS", self.target)
        except requests.RequestException as exc:
            log.debug("OPTIONS probe failed: %s", exc)
            return findings
        allow = resp.headers.get("Allow", "") + "," + resp.headers.get("Public", "")
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}
        for method in RISKY_METHODS:
            if method in allowed:
                findings.append({
                    "type": "Risky HTTP Method",
                    "method": method,
                    "severity": "medium" if method in ("PUT", "DELETE") else "low",
                    "remediation": REMEDIATION["Risky HTTP Method"],
                })
                log.info("[!] Risky HTTP method enabled: %s", method)
        return findings

    def _check_sensitive_files(self):
        findings = []
        for path in SENSITIVE_PATHS:
            try:
                resp = self._request("GET", self.origin + path, stream=True)
            except requests.RequestException:
                continue
            status = resp.status_code
            resp.close()
            if status == 200:
                findings.append({
                    "type": "Exposed Sensitive File",
                    "path": path, "status": status,
                    "severity": "high", "confidence": "high",
                    "remediation": REMEDIATION["Exposed Sensitive File"],
                })
                log.info("[!] Exposed file: %s (HTTP 200)", path)
            elif status in (301, 302, 401, 403):
                findings.append({
                    "type": "Exposed Sensitive File",
                    "path": path, "status": status,
                    "severity": "info", "confidence": "medium",
                    "note": "exists but not directly accessible",
                })
        return findings

    def _find_parameters(self, endpoints, soup):
        """Map URL -> parameter names from query strings and forms."""
        params = {}
        for ep in endpoints:
            if not ep.startswith(("http://", "https://")) or not self.in_scope(ep):
                continue
            try:
                query = parse_qs(urlparse(ep).query)
            except ValueError:
                continue
            if query:
                params.setdefault(ep.split("?", 1)[0], set()).update(query.keys())
        for form in soup.find_all("form"):
            action = urljoin(self.target, form.get("action") or "")
            if not self.in_scope(action):
                continue
            for field_tag in form.find_all(["input", "textarea", "select"]):
                name = field_tag.get("name")
                ftype = (field_tag.get("type") or "").lower()
                if name and ftype not in ("submit", "button", "image", "file", "hidden"):
                    params.setdefault(action, set()).add(name)
        return {url: sorted(names) for url, names in params.items()}

    def _inject(self, url, param, value):
        """Return url with `param` set to `value` (added if absent)."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    def _test_matrix(self, params):
        """Bounded list of (url, param) pairs for active probing."""
        pairs = [(url, p) for url, names in params.items() for p in names]
        if len(pairs) > self.config.max_active_tests:
            log.warning("capping active probes at %d parameter tests",
                        self.config.max_active_tests)
            pairs = pairs[: self.config.max_active_tests]
        return pairs

    def _probe_sqli(self, params):
        """Error-based SQLi: inject probe, compare against a benign control."""
        vulns = []
        for url, param in self._test_matrix(params):
            try:
                control = self._request("GET", self._inject(url, param, CONTROL_VALUE))
                probe = self._request("GET", self._inject(url, param, SQLI_PROBE))
            except requests.RequestException as exc:
                log.debug("sqli probe failed for %s?%s: %s", url, param, exc)
                continue
            control_hit = bool(DB_ERROR_PATTERNS.search(control.text))
            probe_hit = bool(DB_ERROR_PATTERNS.search(probe.text))
            if probe_hit and not control_hit:
                vulns.append({
                    "type": "SQL Injection (error-based)",
                    "url": url, "parameter": param, "payload": SQLI_PROBE,
                    "severity": "high", "confidence": "high",
                    "remediation": REMEDIATION["SQL Injection (error-based)"],
                })
                log.info("[!] Possible SQLi: %s?%s", url, param)
        return vulns

    def _probe_xss(self, params):
        """Reflected XSS: inject a canary and check for unescaped reflection."""
        vulns = []
        canary_token = XSS_CANARY.split("<")[0]  # 'lipasx7q'
        for url, param in self._test_matrix(params):
            try:
                control = self._request("GET", self._inject(url, param, CONTROL_VALUE))
                probe = self._request("GET", self._inject(url, param, XSS_CANARY))
            except requests.RequestException as exc:
                log.debug("xss probe failed for %s?%s: %s", url, param, exc)
                continue
            escaped = probe.text.replace(XSS_CANARY, "").replace(canary_token, "")
            raw_reflections = probe.text.count(XSS_CANARY) - escaped.count(XSS_CANARY)
            control_reflections = control.text.count(XSS_CANARY)
            if raw_reflections > control_reflections:
                vulns.append({
                    "type": "Reflected XSS (unescaped)",
                    "url": url, "parameter": param,
                    "severity": "high", "confidence": "medium",
                    "remediation": REMEDIATION["Reflected XSS (unescaped)"],
                })
                log.info("[!] Possible reflected XSS: %s?%s", url, param)
        return vulns


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class ReportGenerator:
    @staticmethod
    def generate(results, scan_time):
        return json.dumps({
            "metadata": {
                "tool": "LIPAS",
                "version": VERSION,
                "scan_time": scan_time,
                "target": results["target"],
                "passive": results.get("passive", False),
                "scan_duration_seconds": round(results["scan_duration"], 2),
            },
            "results": results,
        }, indent=2)

    @staticmethod
    def print_summary(results):
        info = results["domain_info"]
        print("\n[=== SCAN SUMMARY ===]")
        print(f"Target: {results['target']}")
        print(f"Scan completed in {results['scan_duration']:.2f} seconds")
        print("\nDomain Information:")
        print("  IPs:           " + (", ".join(info.get("ip")) or "none"))
        print("  Nameservers:   " + (", ".join(info.get("nameservers")) or "none"))
        print("  Open ports:    " + (", ".join(map(str, info.get("ports"))) or "none"))
        for port, banner in info.get("banners", {}).items():
            print(f"  Banner {port}:    {banner}")
        tls = info.get("tls")
        if tls:
            exp = tls.get("days_until_expiry")
            print(f"  TLS cert:      expires in {exp} days" if exp is not None
                  else "  TLS cert:      present")
        waf = results.get("technologies", {}).get("waf_cdn", [])
        if waf:
            print("  WAF/CDN:       " + ", ".join(waf))
        if results.get("security_txt", {}).get("present"):
            print("  security.txt:  present")
        print(f"\nSubdomains found:    {len(results['subdomains'])}")
        print(f"Endpoints collected: {len(results['endpoints'])}")
        print(f"Findings:            {len(results['vulnerabilities'])}")


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class WebScanPro:
    """Main application controller."""

    def __init__(self, config):
        self.config = config
        self.results = {
            "target": "",
            "domain_info": {},
            "subdomains": {},
            "technologies": {},
            "endpoints": [],
            "security_headers": [],
            "security_txt": {"present": False},
            "vulnerabilities": [],
            "scan_duration": 0.0,
        }

    def run_scan(self, target_url, cookies=None, headers=None, wordlist=None):
        start = time.time()
        try:
            domain_scanner = DomainScanner(self.config, target_url, cookies, headers)
            self.results["target"] = domain_scanner.target
            self.results["domain_info"] = domain_scanner.gather_domain_info()
            self.results["subdomains"] = domain_scanner.enumerate_subdomains(
                wordlist or DEFAULT_SUBDOMAINS
            )

            vuln_scanner = VulnerabilityScanner(
                self.config, domain_scanner.target,
                domain_scanner.base_domain, cookies, headers,
            )
            self.results.update(vuln_scanner.scan_website())
            self.results["scan_duration"] = time.time() - start
            self.results["passive"] = self.config.passive
            return True
        except Exception as exc:
            log.error("critical scan error: %s", exc)
            return False


def build_parser():
    return argparse.ArgumentParser(
        prog="lipas",
        description="LIPAS - Lightweight Penetration Assessment Suite",
        epilog="Responsible use: only scan targets you own or are "
               "explicitly authorized to test.",
    )


def main(argv=None):
    print(r"""
        _     ___ ___  _    ___
       | |   | _ \ _ \/_\ / __|
       | |__ |  _/  _/ _ \__      
       |____||_| |_| \___/|___/
    """)
    print("LIPAS - Lightweight Penetration Assessment Suite")
    print(f"Version {VERSION}\n")

    parser = build_parser()
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-c", "--cookies",
                        help='Cookies as "name=value; name2=value2"')
    parser.add_argument("-H", "--headers", action="append", default=[],
                        help='Header as "Name: value" (repeatable; newlines OK)')
    parser.add_argument("-t", "--threads", type=int, default=15)
    parser.add_argument("-w", "--wordlist", help="Subdomain wordlist file")
    parser.add_argument("-o", "--output", help="Write JSON report to this file")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--passive", action="store_true",
                        help="Disable all active probes (safe mode)")
    parser.add_argument("--rate-limit", type=float, default=0.5,
                        help="Seconds between requests (default 0.5)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("TLS certificate verification disabled (--insecure)")

    config = Config(
        max_threads=args.threads,
        request_timeout=args.timeout,
        rate_limit_delay=max(0.0, args.rate_limit),
        verify_tls=not args.insecure,
        passive=args.passive,
    )

    try:
        cookies = parse_cookie_string(args.cookies)
        headers = parse_header_strings(args.headers)
        wordlist = load_wordlist(args.wordlist) if args.wordlist else None
    except ValueError as exc:
        parser.error(str(exc))

    scanner = WebScanPro(config)
    if not scanner.run_scan(args.url, cookies, headers, wordlist):
        print("\n[!] Scan failed to complete")
        sys.exit(1)

    ReportGenerator.print_summary(scanner.results)
    report = ReportGenerator.generate(scanner.results, time.strftime("%Y-%m-%d %H:%M:%S"))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        log.info("report written to %s", args.output)
    else:
        print("\n[+] Full report:")
        print(report)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
