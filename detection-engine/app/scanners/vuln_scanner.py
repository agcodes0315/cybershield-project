from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT_SECONDS = 12
PATH_TIMEOUT_SECONDS = 6
TLS_TIMEOUT_SECONDS = 8
USER_AGENT = "CyberShield-VulnerabilityScanner/4.0"
MAX_BODY_BYTES = 200_000

SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "description": "Instructs browsers to use HTTPS and helps reduce protocol-downgrade exposure.",
        "fix": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "weight": 5,
    },
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "severity": "high",
        "description": "Restricts which resources may load and helps reduce the impact of script-injection attacks.",
        "fix": "Deploy a tested Content-Security-Policy appropriate for the application.",
        "weight": 9,
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents browsers from MIME-sniffing a response into a different content type.",
        "fix": "Add X-Content-Type-Options: nosniff",
        "weight": 3,
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Restricts iframe embedding and helps reduce clickjacking exposure.",
        "fix": "Add X-Frame-Options: DENY or SAMEORIGIN, or configure CSP frame-ancestors.",
        "weight": 3,
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls how much referrer information is sent with outbound browser requests.",
        "fix": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "weight": 1,
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Restricts access to browser capabilities such as camera, microphone and geolocation.",
        "fix": "Add a Permissions-Policy matching the application's actual feature requirements.",
        "weight": 1,
    },
}

LEGACY_HEADERS: dict[str, dict[str, Any]] = {
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "info",
        "description": "Legacy browser XSS-filter header. Modern browsers rely primarily on Content-Security-Policy instead.",
        "fix": "Do not rely on this legacy header. Maintain a strong Content-Security-Policy and secure output encoding.",
        "weight": 0,
    }
}

DISCLOSURE_HEADERS: dict[str, dict[str, Any]] = {
    "server": {
        "name": "Server Information Disclosure",
        "severity": "low",
        "description": "The Server response header may reveal infrastructure or software information.",
        "fix": "Remove or minimise the Server response header.",
        "weight": 2,
    },
    "x-powered-by": {
        "name": "Technology Stack Disclosure",
        "severity": "low",
        "description": "The X-Powered-By response header may reveal the application framework or runtime.",
        "fix": "Remove the X-Powered-By response header.",
        "weight": 2,
    },
}

SENSITIVE_PATHS: list[dict[str, Any]] = [
    {"path": "/.env", "name": "Environment File Exposed", "severity": "critical", "content_types": ["text/plain", "application/octet-stream"], "signatures": ["database_url=", "db_password=", "secret_key=", "api_key=", "redis_url="]},
    {"path": "/.git/config", "name": "Git Repository Metadata Exposed", "severity": "critical", "content_types": ["text/plain", "application/octet-stream"], "signatures": ["[core]", "repositoryformatversion", "bare ="]},
    {"path": "/config.php", "name": "PHP Configuration File Exposed", "severity": "critical", "content_types": ["text/plain", "application/octet-stream"], "signatures": ["<?php", "db_password", "database_name", "mysqli_connect"]},
    {"path": "/wp-admin/", "name": "WordPress Administration Interface", "severity": "medium", "content_types": ["text/html"], "signatures": ["wp-admin", "wordpress", "wp-login.php"]},
    {"path": "/wp-login.php", "name": "WordPress Login Interface", "severity": "medium", "content_types": ["text/html"], "signatures": ["wp-login.php", "wordpress", "user_login"]},
    {"path": "/phpmyadmin/", "name": "phpMyAdmin Interface Exposed", "severity": "high", "content_types": ["text/html"], "signatures": ["phpmyadmin", "pma_username", "server choice"]},
    {"path": "/server-status", "name": "Apache Status Page Exposed", "severity": "medium", "content_types": ["text/html", "text/plain"], "signatures": ["apache server status", "server uptime", "scoreboard key"]},
    {"path": "/server-info", "name": "Apache Information Page Exposed", "severity": "medium", "content_types": ["text/html", "text/plain"], "signatures": ["apache server information", "server settings", "module name"]},
    {"path": "/.htaccess", "name": "Apache Configuration File Accessible", "severity": "high", "content_types": ["text/plain", "application/octet-stream"], "signatures": ["rewriteengine", "rewritecond", "authname", "options indexes"]},
    {"path": "/swagger/", "name": "Swagger UI Accessible", "severity": "low", "content_types": ["text/html", "application/json"], "signatures": ["swagger ui", "swagger-ui", "openapi"]},
    {"path": "/api/docs", "name": "API Documentation Accessible", "severity": "low", "content_types": ["text/html", "application/json"], "signatures": ["openapi", "swagger", "redoc"]},
    {"path": "/graphql", "name": "GraphQL Endpoint Accessible", "severity": "medium", "content_types": ["text/html", "application/json"], "signatures": ["graphql", "__schema", "graphiql"]},
]

SEVERITY_WEIGHT = {"critical": 30, "high": 16, "medium": 7, "low": 2, "info": 0}


def normalise_target(target: str) -> tuple[str, str]:
    cleaned = str(target or "").strip()
    if not cleaned:
        raise ValueError("A domain or URL is required.")

    parsed = urlparse(cleaned if cleaned.startswith(("http://", "https://")) else f"https://{cleaned}")
    hostname = (parsed.hostname or "").rstrip(".").lower()

    if not hostname:
        raise ValueError("The submitted target does not contain a valid hostname.")
    if len(hostname) > 253:
        raise ValueError("The hostname is too long.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pattern = (
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        )
        if not re.fullmatch(pattern, hostname):
            raise ValueError("The hostname format is invalid.")

    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
    origin = f"{scheme}://{hostname}:{parsed.port}" if parsed.port else f"{scheme}://{hostname}"
    return hostname, origin


def _safe_text(response: requests.Response) -> str:
    content = response.content[:MAX_BODY_BYTES]
    encoding = response.encoding or "utf-8"
    try:
        return content.decode(encoding, errors="replace")
    except Exception:
        return content.decode("utf-8", errors="replace")


def _request(url: str, *, timeout: int, allow_redirects: bool = True) -> requests.Response:
    return requests.get(
        url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        verify=False,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        },
    )


def check_security_headers(headers: requests.structures.CaseInsensitiveDict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for key, metadata in SECURITY_HEADERS.items():
        value = str(headers.get(key, "") or "").strip()
        findings.append({
            "key": key,
            "header": metadata["name"],
            "present": bool(value),
            "value": value or None,
            "severity": metadata["severity"],
            "description": metadata["description"],
            "fix": metadata["fix"],
            "weight": metadata["weight"],
            "category": "security_control",
            "legacy": False,
        })

    for key, metadata in LEGACY_HEADERS.items():
        value = str(headers.get(key, "") or "").strip()
        findings.append({
            "key": key,
            "header": metadata["name"],
            "present": bool(value),
            "value": value or None,
            "severity": metadata["severity"],
            "description": metadata["description"],
            "fix": metadata["fix"],
            "weight": 0,
            "category": "legacy_control",
            "legacy": True,
        })

    for key, metadata in DISCLOSURE_HEADERS.items():
        value = str(headers.get(key, "") or "").strip()
        disclosed = bool(value)
        findings.append({
            "key": key,
            "header": metadata["name"],
            "present": disclosed,
            "value": value or None,
            "severity": metadata["severity"],
            "description": f"{metadata['description']} Observed value: {value}" if disclosed else metadata["description"],
            "fix": metadata["fix"],
            "weight": metadata["weight"] if disclosed else 0,
            "category": "information_disclosure",
            "legacy": False,
        })

    return findings


def _certificate_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except Exception:
        return None


def _issuer_name(certificate: dict[str, Any]) -> str:
    values: dict[str, str] = {}
    for entry in certificate.get("issuer", []):
        for pair in entry:
            if len(pair) == 2:
                values[pair[0]] = pair[1]
    return values.get("commonName") or values.get("organizationName") or "Unknown issuer"


def inspect_tls(hostname: str, port: int = 443) -> dict[str, Any]:
    started_at = time.perf_counter()

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TLS_TIMEOUT_SECONDS) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as secure_socket:
                certificate = secure_socket.getpeercert()
                cipher = secure_socket.cipher()
                version = secure_socket.version() or "Unknown"

                hostname_valid = True
                hostname_error = None
                try:
                    ssl.match_hostname(certificate, hostname)
                except Exception as error:
                    hostname_valid = False
                    hostname_error = str(error)

                not_before = _certificate_date(certificate.get("notBefore"))
                not_after = _certificate_date(certificate.get("notAfter"))
                now = datetime.now(timezone.utc)
                expired = bool(not_after and not_after < now)
                not_yet_valid = bool(not_before and not_before > now)
                days_remaining = max(0, (not_after - now).days) if not_after else None

                san_domains = [
                    value
                    for name_type, value in certificate.get("subjectAltName", [])
                    if name_type == "DNS"
                ]

                duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_bits = cipher[2] if cipher else 0
                protocol_weak = version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
                certificate_valid = hostname_valid and not expired and not not_yet_valid

                findings: list[dict[str, Any]] = [{
                    "name": "SSL/TLS Configuration",
                    "severity": "high" if protocol_weak else "info",
                    "detail": f"Protocol: {version}, Cipher: {cipher_name}, Bits: {cipher_bits}",
                }]

                if protocol_weak:
                    findings.append({"name": "Legacy TLS Protocol", "severity": "high", "detail": f"{version} is outdated and should be disabled."})
                if not hostname_valid:
                    findings.append({"name": "Certificate Hostname Mismatch", "severity": "high", "detail": hostname_error or "The certificate does not match the requested hostname."})
                if expired:
                    findings.append({"name": "Expired Certificate", "severity": "critical", "detail": "The TLS certificate has expired."})
                if not_yet_valid:
                    findings.append({"name": "Certificate Not Yet Valid", "severity": "high", "detail": "The TLS certificate is not valid yet."})
                if days_remaining is not None and 0 < days_remaining < 30:
                    findings.append({"name": "Certificate Expiring Soon", "severity": "medium", "detail": f"The certificate expires in {days_remaining} days."})

                return {
                    "status": "success",
                    "tls_version": version,
                    "cipher_suite": cipher_name,
                    "cipher_bits": cipher_bits,
                    "handshake_time_ms": duration_ms,
                    "hostname_valid": hostname_valid,
                    "hostname_error": hostname_error,
                    "certificate_valid": certificate_valid,
                    "forward_secrecy_likely": version.startswith("TLSv1.3") or "ECDHE" in cipher_name or "DHE" in cipher_name,
                    "certificate": {
                        "issuer": _issuer_name(certificate),
                        "not_before": certificate.get("notBefore", ""),
                        "not_after": certificate.get("notAfter", ""),
                        "days_remaining": days_remaining,
                        "expired": expired,
                        "not_yet_valid": not_yet_valid,
                        "san_domains": san_domains[:25],
                        "san_count": len(san_domains),
                    },
                    "findings": findings,
                }

    except Exception as error:
        return {
            "status": "failed",
            "error": str(error),
            "handshake_time_ms": round((time.perf_counter() - started_at) * 1000, 2),
            "findings": [{"name": "TLS Inspection Unavailable", "severity": "info", "detail": str(error)}],
        }


def _response_signature(response: requests.Response) -> dict[str, Any]:
    body = _safe_text(response)
    normalised = re.sub(r"\s+", " ", body.lower()).strip()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip().lower() if title_match else ""

    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(response.content),
        "title": title,
        "normalised_body": normalised,
        "redirect_count": len(response.history),
    }


def _looks_like_soft_404(baseline: dict[str, Any], candidate: dict[str, Any]) -> bool:
    if candidate["status_code"] == 404:
        return True

    baseline_length = max(1, int(baseline.get("content_length", 0)))
    candidate_length = max(1, int(candidate.get("content_length", 0)))
    length_difference_ratio = abs(candidate_length - baseline_length) / baseline_length
    same_title = bool(candidate.get("title")) and candidate.get("title") == baseline.get("title")
    body = candidate.get("normalised_body", "")

    generic_not_found = any(
        phrase in body
        for phrase in (
            "404 not found",
            "page not found",
            "the page you requested could not be found",
            "we couldn't find that page",
            "resource not found",
        )
    )

    return generic_not_found or (same_title and length_difference_ratio < 0.08)


def scan_sensitive_paths(base_url: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    confirmed: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    random_probe = f"/cybershield-not-found-{int(time.time() * 1000)}"

    try:
        baseline = _response_signature(_request(urljoin(base_url, random_probe), timeout=PATH_TIMEOUT_SECONDS))
    except Exception:
        baseline = {"status_code": 404, "final_url": "", "content_type": "", "content_length": 0, "title": "", "normalised_body": "", "redirect_count": 0}

    for definition in SENSITIVE_PATHS:
        target_url = urljoin(base_url.rstrip("/") + "/", definition["path"].lstrip("/"))

        try:
            response = _request(target_url, timeout=PATH_TIMEOUT_SECONDS)
            signature = _response_signature(response)
            body = signature["normalised_body"]
            content_type = str(signature["content_type"]).lower()
            matched_signatures = [marker for marker in definition["signatures"] if marker.lower() in body]
            content_type_matches = any(expected in content_type for expected in definition.get("content_types", []))
            soft_404 = _looks_like_soft_404(baseline, signature)
            final_path = urlparse(signature["final_url"]).path.lower()
            redirected_to_home = signature["redirect_count"] > 0 and final_path in {"", "/"}

            confirmed_exposure = (
                response.status_code in {200, 401, 403}
                and bool(matched_signatures)
                and content_type_matches
                and not soft_404
                and not redirected_to_home
            )

            if confirmed_exposure:
                confirmed.append({
                    "path": definition["path"],
                    "name": definition["name"],
                    "severity": definition["severity"],
                    "status_code": response.status_code,
                    "final_url": response.url,
                    "content_type": content_type,
                    "matched_signatures": matched_signatures,
                    "evidence": "Response content matched expected product or file signatures.",
                    "confirmed": True,
                })
            elif response.status_code in {200, 401, 403}:
                observations.append({
                    "path": definition["path"],
                    "status_code": response.status_code,
                    "final_url": response.url,
                    "content_type": content_type,
                    "confirmed": False,
                    "reason": "The path responded, but no reliable content signature confirmed exposure.",
                })

        except requests.RequestException as error:
            observations.append({"path": definition["path"], "confirmed": False, "reason": f"Request failed: {error}"})

    return confirmed, observations


def analyse_cookies(response: requests.Response) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    raw_set_cookie = response.headers.get("Set-Cookie", "")
    if not raw_set_cookie:
        return findings

    for segment in re.split(r", (?=[^;,]+=)", raw_set_cookie):
        first_part = segment.split(";", 1)[0]
        cookie_name = first_part.split("=", 1)[0].strip()
        lower = segment.lower()
        missing: list[str] = []

        if response.url.startswith("https://") and "; secure" not in lower:
            missing.append("Secure")
        if "; httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite=" not in lower:
            missing.append("SameSite")

        if missing:
            findings.append({
                "name": f"Cookie Security Attributes Missing: {cookie_name or 'Unnamed cookie'}",
                "severity": "medium" if "Secure" in missing else "low",
                "detail": "Missing attributes: " + ", ".join(missing),
                "cookie_name": cookie_name or None,
                "missing_attributes": missing,
            })

    return findings


def _risk_level(score: int, severity_counts: dict[str, int]) -> str:
    if severity_counts.get("critical", 0) > 0:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Informational"


def calculate_risk(
    header_checks: list[dict[str, Any]],
    ssl_findings: list[dict[str, Any]],
    path_findings: list[dict[str, Any]],
    cookie_findings: list[dict[str, Any]],
) -> tuple[int, str, dict[str, int]]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    score = 0

    for check in header_checks:
        category = check.get("category")
        severity = str(check.get("severity", "info")).lower()

        if category == "security_control" and not check.get("present") and not check.get("legacy"):
            counts[severity] += 1
            score += int(check.get("weight", 0))
        elif category == "information_disclosure" and check.get("present"):
            counts[severity] += 1
            score += int(check.get("weight", 0))
        elif category == "legacy_control" and not check.get("present"):
            counts["info"] += 1

    for finding in ssl_findings + path_findings + cookie_findings:
        severity = str(finding.get("severity", "info")).lower()
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
        score += SEVERITY_WEIGHT[severity]

    score = max(0, min(100, score))
    return score, _risk_level(score, counts), counts


def scan_common_vulnerabilities(target: str) -> dict[str, Any]:
    started_at = time.perf_counter()

    try:
        hostname, base_url = normalise_target(target)
    except ValueError as error:
        return {"status": "failed", "error": str(error)}

    try:
        response = _request(base_url, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException as error:
        return {
            "status": "failed",
            "target": target,
            "hostname": hostname,
            "base_url": base_url,
            "error": f"The target could not be reached: {error}",
        }

    final_url = response.url
    final_hostname = (urlparse(final_url).hostname or hostname).rstrip(".").lower()
    header_checks = check_security_headers(response.headers)
    tls = inspect_tls(final_hostname)
    ssl_findings = list(tls.get("findings", []))
    origin = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
    path_findings, path_observations = scan_sensitive_paths(origin)
    cookie_findings = analyse_cookies(response)

    risk_score, risk_level, severity_counts = calculate_risk(
        header_checks,
        ssl_findings,
        path_findings,
        cookie_findings,
    )

    missing_security_headers = [
        check
        for check in header_checks
        if check.get("category") == "security_control" and not check.get("present") and not check.get("legacy")
    ]
    disclosed_headers = [
        check
        for check in header_checks
        if check.get("category") == "information_disclosure" and check.get("present")
    ]

    return {
        "status": "completed",
        "scanner_version": "4.0",
        "target": target,
        "hostname": hostname,
        "base_url": base_url,
        "final_url": final_url,
        "final_hostname": final_hostname,
        "redirected": final_url.rstrip("/") != base_url.rstrip("/"),
        "http_status": response.status_code,
        "response_time_seconds": round(response.elapsed.total_seconds(), 3),
        "scan_duration": round(time.perf_counter() - started_at, 2),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": {
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "headers_missing": len(missing_security_headers),
            "headers_disclosed": len(disclosed_headers),
            "paths_exposed": len(path_findings),
            "cookies_with_issues": len(cookie_findings),
        },
        "header_checks": header_checks,
        "ssl_findings": ssl_findings,
        "tls": tls,
        "path_findings": path_findings,
        "path_observations": path_observations,
        "cookie_findings": cookie_findings,
        "evidence_notes": [
            "Sensitive paths are reported only when the response contains matching content signatures.",
            "Missing browser-security headers are configuration observations, not confirmed exploitation.",
            "X-XSS-Protection is treated as a legacy informational header and does not increase the score.",
        ],
    }


def full_vulnerability_scan(target: str) -> dict[str, Any]:
    return scan_common_vulnerabilities(target)


def scan_vulnerabilities(target: str) -> dict[str, Any]:
    return scan_common_vulnerabilities(target)