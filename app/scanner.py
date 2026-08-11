import asyncio
import re
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings
from app.models import Finding, Severity
from app.safety import UnsafeTarget, validate_public_url

SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.medium),
    "strict-transport-security": ("Strict-Transport-Security", Severity.medium),
    "x-content-type-options": ("X-Content-Type-Options", Severity.low),
    "referrer-policy": ("Referrer-Policy", Severity.low),
    "permissions-policy": ("Permissions-Policy", Severity.low),
}


class Scanner:
    def __init__(self) -> None:
        self.requests_made = 0

    async def _get(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        if self.requests_made >= settings.max_requests:
            raise RuntimeError("Scan request budget exhausted")
        await validate_public_url(url)
        self.requests_made += 1
        response = await client.get(url)
        if response.is_redirect and response.headers.get("location"):
            redirected = urljoin(url, response.headers["location"])
            await validate_public_url(redirected)
            if urlparse(redirected).hostname != urlparse(url).hostname:
                raise UnsafeTarget("Cross-host redirects are blocked")
            if self.requests_made >= settings.max_requests:
                raise RuntimeError("Scan request budget exhausted")
            self.requests_made += 1
            response = await client.get(redirected)
        return response

    async def scan(self, target: str) -> tuple[list[Finding], int]:
        await validate_public_url(target)
        findings: list[Finding] = []
        limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds,
            headers={"User-Agent": settings.user_agent}, follow_redirects=False, limits=limits,
        ) as client:
            response = await self._get(client, target)
            findings.extend(self._headers(response, target))
            findings.extend(self._cookies(response))
            findings.extend(self._cors(response))
            findings.extend(self._technology(response))
            findings.extend(self._directory_listing(response))
            findings.extend(self._login_protection(response))
            findings.extend(await self._cms_checks(client, str(response.url), response.text))

        if urlparse(target).scheme == "https":
            findings.extend(await self._tls(target))
        else:
            findings.append(Finding(check="transport", title="Site is not using HTTPS",
                severity=Severity.high, evidence="The supplied target uses plain HTTP.",
                recommendation="Redirect HTTP to HTTPS and enable HSTS after validating HTTPS.",
                owasp="A02:2021 Cryptographic Failures"))
        return findings, self.requests_made

    def _headers(self, response: httpx.Response, target: str) -> list[Finding]:
        out = []
        for key, (display, severity) in SECURITY_HEADERS.items():
            if key not in response.headers and not (key == "strict-transport-security" and target.startswith("http:")):
                out.append(Finding(check="headers", title=f"Missing {display}", severity=severity,
                    evidence=f"{display} was absent from the root response.",
                    recommendation=f"Configure an appropriate {display} header and test application compatibility.",
                    owasp="A05:2021 Security Misconfiguration"))
        return out

    def _cookies(self, response: httpx.Response) -> list[Finding]:
        out = []
        for raw in response.headers.get_list("set-cookie"):
            name = raw.split("=", 1)[0][:60]
            lower = raw.lower()
            for flag in ("secure", "httponly", "samesite"):
                if flag not in lower:
                    out.append(Finding(check="cookies", title=f"Cookie {name} lacks {flag.title()}",
                        severity=Severity.medium if flag != "samesite" else Severity.low,
                        evidence=f"Set-Cookie for {name} did not include {flag}.",
                        recommendation=f"Add the {flag.title()} attribute where compatible.",
                        owasp="A05:2021 Security Misconfiguration"))
        return out

    def _cors(self, response: httpx.Response) -> list[Finding]:
        if response.headers.get("access-control-allow-origin") == "*" and response.headers.get("access-control-allow-credentials", "").lower() == "true":
            return [Finding(check="cors", title="Risky CORS policy", severity=Severity.high,
                evidence="Wildcard origin was combined with credential allowance.",
                recommendation="Allow only explicitly trusted origins and avoid credentialed wildcard policies.",
                owasp="A05:2021 Security Misconfiguration")]
        return []

    def _technology(self, response: httpx.Response) -> list[Finding]:
        disclosed = [f"{h}: {response.headers[h][:100]}" for h in ("server", "x-powered-by") if h in response.headers]
        return [Finding(check="disclosure", title="Technology details disclosed", severity=Severity.low,
            evidence="; ".join(disclosed), recommendation="Suppress unnecessary server and framework version headers.",
            owasp="A05:2021 Security Misconfiguration")] if disclosed else []

    def _directory_listing(self, response: httpx.Response) -> list[Finding]:
        body = response.text[:10000]
        if re.search(
            r"<title>Index of /|<h1>Index of /|Directory listing for",
            body,
            re.IGNORECASE,
        ):
            return [Finding(check="directory-indexing", title="Directory indexing appears enabled",
                severity=Severity.medium, evidence="The response matched a common directory-listing signature.",
                recommendation="Disable auto-indexing and restrict access to non-public files.",
                owasp="A05:2021 Security Misconfiguration")]
        return []

    def _login_protection(self, response: httpx.Response) -> list[Finding]:
        body = response.text[:250000]
        is_login = bool(re.search(r'type=["\']password["\']', body, re.IGNORECASE))
        signals = re.search(
            r"captcha|turnstile|recaptcha|rate.?limit|too many attempts|lockout",
            body,
            re.IGNORECASE,
        )
        if is_login and not signals:
            return [Finding(check="brute-force", title="No visible brute-force protection signal",
                severity=Severity.medium,
                evidence="A password form was present, but no CAPTCHA, rate-limit, or lockout marker was visible. No login attempts were made.",
                recommendation="Apply server-side rate limits, progressive delays, MFA, monitoring, and safe account lockout controls.",
                owasp="A07:2021 Identification and Authentication Failures")]
        return []

    async def _cms_checks(self, client: httpx.AsyncClient, base: str, body: str) -> list[Finding]:
        out = []
        wp = re.findall(
            r"/wp-content/plugins/([\w-]+)/[^\"'?# ]*[?&]ver=([\w.-]+)",
            body,
            re.IGNORECASE,
        )
        joomla = re.findall(
            r"/(?:components|plugins)/([\w/-]+)/[^\"'?# ]*[?&]ver=([\w.-]+)",
            body,
            re.IGNORECASE,
        )
        for cms, items in (("WordPress", wp), ("Joomla", joomla)):
            for name, version in sorted(set(items))[:15]:
                out.append(Finding(check="cms-inventory", title=f"{cms} extension detected: {name}",
                    severity=Severity.info, evidence=f"Public asset URL declares version {version}.",
                    recommendation="Compare this version with the vendor's current supported release and security advisories.",
                    owasp="A06:2021 Vulnerable and Outdated Components"))
        # A single standard endpoint improves CMS detection without enumerating content.
        if "wp-content" in body.lower() and self.requests_made < settings.max_requests:
            probe = await self._get(client, urljoin(base, "/wp-json/"))
            if probe.status_code == 200:
                out.append(Finding(check="cms", title="WordPress API is publicly reachable", severity=Severity.info,
                    evidence="GET /wp-json/ returned HTTP 200.", recommendation="Keep WordPress and extensions patched; restrict API features only if business requirements allow.",
                    owasp="A06:2021 Vulnerable and Outdated Components"))
        return out

    async def _tls(self, target: str) -> list[Finding]:
        parsed = urlparse(target)
        host, port = parsed.hostname, parsed.port or 443

        def inspect() -> tuple[dict, str]:
            context = ssl.create_default_context()
            with (
                socket.create_connection(
                    (host, port), timeout=settings.request_timeout_seconds
                ) as raw,
                context.wrap_socket(raw, server_hostname=host) as tls,
            ):
                return tls.getpeercert(), tls.version() or "unknown"

        try:
            cert, protocol = await asyncio.to_thread(inspect)
            out = []
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            days = (expiry - datetime.now(UTC)).days
            if days < 30:
                out.append(Finding(check="tls", title="TLS certificate expires soon", severity=Severity.high if days < 7 else Severity.medium,
                    evidence=f"Certificate expires in {days} days.", recommendation="Renew and deploy the certificate before expiry.",
                    owasp="A02:2021 Cryptographic Failures"))
            if protocol in {"TLSv1", "TLSv1.1"}:
                out.append(Finding(check="tls", title="Obsolete TLS negotiated", severity=Severity.high,
                    evidence=f"Negotiated protocol: {protocol}.", recommendation="Require TLS 1.2 or TLS 1.3.",
                    owasp="A02:2021 Cryptographic Failures"))
            return out
        except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
            return [Finding(check="tls", title="TLS validation failed", severity=Severity.high,
                evidence=f"A verified TLS connection could not be established: {type(exc).__name__}.",
                recommendation="Verify certificate chain, hostname, expiry, and supported TLS configuration.",
                owasp="A02:2021 Cryptographic Failures")]
