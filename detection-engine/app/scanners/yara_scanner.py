from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3
import yara

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT_SECONDS = 12
MAX_RESPONSE_BYTES = 1_500_000
MAX_REDIRECTS = 5
USER_AGENT = "CyberShield-YARA-WebScanner/4.0"


def get_default_rules() -> dict[str, str]:
    return {
        "phishing_login_form": r'''
rule phishing_login_form {
    meta:
        description = "Detects login forms that may collect credentials"
        severity = "high"
        category = "credential_harvesting"
        mitre = "T1056.003"
        recommendation = "Verify the form action, destination domain, branding, and credential handling."
    strings:
        $form = "<form" nocase
        $password1 = "type=\"password\"" nocase
        $password2 = "type='password'" nocase
        $submit1 = "type=\"submit\"" nocase
        $submit2 = "type='submit'" nocase
        $login1 = "log in" nocase
        $login2 = "login" nocase
        $signin1 = "sign in" nocase
        $signin2 = "signin" nocase
    condition:
        $form and 1 of ($password*) and 1 of ($submit*) and 1 of ($login*, $signin*)
}
''',
        "paypal_phishing": r'''
rule paypal_phishing {
    meta:
        description = "Detects PayPal-themed credential collection indicators"
        severity = "critical"
        category = "brand_impersonation"
        mitre = "T1583.001"
        recommendation = "Confirm the page is hosted on an authorised PayPal domain and inspect the form destination."
    strings:
        $brand1 = "paypal" nocase
        $brand2 = "paypal-logo" nocase
        $brand3 = "paypal.com/logo" nocase
        $form = "<form" nocase
        $password1 = "type=\"password\"" nocase
        $password2 = "type='password'" nocase
    condition:
        1 of ($brand*) and $form and 1 of ($password*)
}
''',
        "microsoft_phishing": r'''
rule microsoft_phishing {
    meta:
        description = "Detects Microsoft or Office 365 themed credential collection indicators"
        severity = "critical"
        category = "brand_impersonation"
        mitre = "T1583.001"
        recommendation = "Validate the hostname, certificate, page branding, and authentication destination."
    strings:
        $brand1 = "microsoft" nocase
        $brand2 = "office365" nocase
        $brand3 = "outlook" nocase
        $brand4 = "onedrive" nocase
        $brand5 = "sharepoint" nocase
        $form = "<form" nocase
        $password1 = "type=\"password\"" nocase
        $password2 = "type='password'" nocase
    condition:
        1 of ($brand*) and $form and 1 of ($password*)
}
''',
        "urgency_social_engineering": r'''
rule urgency_social_engineering {
    meta:
        description = "Detects repeated urgency and account-pressure language"
        severity = "medium"
        category = "social_engineering"
        mitre = "T1566"
        recommendation = "Review the message context and confirm whether urgency language is legitimate."
    strings:
        $u1 = "your account has been" nocase
        $u2 = "suspended" nocase
        $u3 = "unauthorized" nocase
        $u4 = "verify your identity" nocase
        $u5 = "confirm your account" nocase
        $u6 = "within 24 hours" nocase
        $u7 = "immediate action" nocase
        $u8 = "account will be closed" nocase
        $u9 = "unusual activity" nocase
        $u10 = "security alert" nocase
    condition:
        3 of ($u*)
}
''',
        "credential_exfiltration": r'''
rule credential_exfiltration {
    meta:
        description = "Detects combined credential capture and suspicious transmission patterns"
        severity = "high"
        category = "data_theft"
        mitre = "T1041"
        recommendation = "Inspect form fields, JavaScript value access, encoding, and the remote destination."
    strings:
        $password1 = "type=\"password\"" nocase
        $password2 = "type='password'" nocase
        $formdata = "FormData(" nocase
        $value1 = ".value" nocase
        $value2 = "querySelector" nocase
        $net1 = "XMLHttpRequest" nocase
        $net2 = "fetch(" nocase
        $net3 = "$.ajax" nocase
        $net4 = "$.post" nocase
        $encode1 = "btoa(" nocase
        $encode2 = "encodeURIComponent(" nocase
        $sink1 = "api.telegram.org" nocase
        $sink2 = "discord.com/api/webhooks" nocase
        $sink3 = "webhook.site" nocase
        $sink4 = "pastebin.com" nocase
    condition:
        1 of ($password*) and ($formdata or 1 of ($value*)) and 1 of ($net*) and (1 of ($encode*) or 1 of ($sink*))
}
''',
        "obfuscated_redirect": r'''
rule obfuscated_redirect {
    meta:
        description = "Detects redirects combined with JavaScript obfuscation"
        severity = "medium"
        category = "evasion"
        mitre = "T1027"
        recommendation = "Decode the script and verify the redirect destination."
    strings:
        $redir1 = "window.location" nocase
        $redir2 = "document.location" nocase
        $redir3 = "location.href" nocase
        $redir4 = "location.replace" nocase
        $redir5 = "meta http-equiv=\"refresh\"" nocase
        $obf1 = "eval(" nocase
        $obf2 = "atob(" nocase
        $obf3 = "String.fromCharCode" nocase
        $obf4 = "unescape(" nocase
        $obf5 = "decodeURIComponent" nocase
    condition:
        1 of ($redir*) and 1 of ($obf*)
}
''',
        "data_uri_phishing": r'''
rule data_uri_phishing {
    meta:
        description = "Detects HTML data URIs combined with hidden or embedded content"
        severity = "high"
        category = "evasion"
        mitre = "T1027"
        recommendation = "Decode the data URI and inspect embedded forms, scripts, and destinations."
    strings:
        $data_uri = "data:text/html" nocase
        $base64 = ";base64," nocase
        $iframe = "<iframe" nocase
        $hidden1 = "display:none" nocase
        $hidden2 = "visibility:hidden" nocase
        $hidden3 = "width:0" nocase
    condition:
        $data_uri and $base64 and 1 of ($hidden*, $iframe)
}
''',
    }


def compile_rules() -> tuple[dict[str, yara.Rules], list[dict[str, str]]]:
    compiled: dict[str, yara.Rules] = {}
    errors: list[dict[str, str]] = []
    for name, source in get_default_rules().items():
        try:
            compiled[name] = yara.compile(source=source)
        except yara.Error as error:
            errors.append({"rule": name, "error": str(error)})
    return compiled, errors


def _is_private_or_local(hostname: str) -> bool:
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as error:
        raise ValueError(f"DNS resolution failed for {hostname}: {error}") from error
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True
    return False


def normalise_url(value: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        raise ValueError("A URL is required.")
    parsed = urlparse(
        cleaned if cleaned.startswith(("http://", "https://")) else f"https://{cleaned}"
    )
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise ValueError("The URL does not contain a valid hostname.")
    if _is_private_or_local(hostname):
        raise ValueError("Private, local, loopback, and reserved network targets are blocked.")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{hostname}{port}{path}{query}"


def fetch_page_content(url: str) -> dict[str, Any]:
    safe_url = normalise_url(url)
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    response = session.get(
        safe_url,
        timeout=REQUEST_TIMEOUT_SECONDS,
        verify=False,
        allow_redirects=True,
        stream=True,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/javascript,text/javascript;q=0.9,*/*;q=0.8",
            "Connection": "close",
        },
    )
    content_type = response.headers.get("Content-Type", "").lower()
    allowed = any(
        marker in content_type
        for marker in (
            "text/",
            "application/javascript",
            "application/x-javascript",
            "application/json",
            "application/xhtml+xml",
        )
    )
    if content_type and not allowed:
        raise ValueError(f"Unsupported response type: {content_type}")
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=65_536):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ValueError("The page exceeded the 1.5 MB scan limit.")
        chunks.append(chunk)
    content = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
    final_hostname = (urlparse(response.url).hostname or "").lower()
    if _is_private_or_local(final_hostname):
        raise ValueError("The redirect destination resolves to a blocked network.")
    return {
        "status_code": response.status_code,
        "content": content,
        "final_url": str(response.url),
        "content_length": len(content.encode("utf-8")),
        "headers": dict(response.headers),
        "redirect_count": len(response.history),
    }


def analyse_page(content: str, final_url: str) -> dict[str, Any]:
    lowered = content.lower()
    final_host = (urlparse(final_url).hostname or "").lower()
    external_hosts = {
        host.lower()
        for host in re.findall(r"https?://([a-z0-9.-]+)", content, flags=re.IGNORECASE)
        if host and host.lower() != final_host
    }
    return {
        "has_forms": "<form" in lowered,
        "has_password_field": 'type="password"' in lowered or "type='password'" in lowered,
        "has_external_scripts": bool(re.findall(r"<script[^>]+src=[\"']https?://", content, flags=re.IGNORECASE)),
        "has_iframe": "<iframe" in lowered,
        "has_obfuscation": any(marker in lowered for marker in ("eval(", "atob(", "string.fromcharcode", "unescape(")),
        "has_data_uri": "data:text/html" in lowered,
        "has_network_api": any(marker in lowered for marker in ("xmlhttprequest", "fetch(", "$.ajax", "$.post")),
        "has_encoding_api": any(marker in lowered for marker in ("btoa(", "encodeuricomponent(")),
        "has_suspicious_sink": any(marker in lowered for marker in ("api.telegram.org", "discord.com/api/webhooks", "webhook.site", "pastebin.com")),
        "content_length": len(content),
        "external_links_count": len(re.findall(r"https?://[^\s\"'<>]+", content, flags=re.IGNORECASE)),
        "external_hosts": sorted(external_hosts)[:25],
    }


def _matched_strings(match: Any) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for string_match in match.strings:
        for instance in string_match.instances:
            text = instance.plaintext().decode("utf-8", errors="ignore").strip()
            if len(text) > 120:
                text = text[:120] + "..."
            key = (string_match.identifier, text)
            if key in seen:
                continue
            seen.add(key)
            evidence.append({"identifier": string_match.identifier, "matched_text": text})
    return evidence[:12]


def _confidence_for_match(rule_name: str, page: dict[str, Any]) -> int:
    confidence = 45
    if page["has_password_field"]:
        confidence += 20
    if page["has_forms"]:
        confidence += 10
    if page["has_obfuscation"]:
        confidence += 10
    if page["has_suspicious_sink"]:
        confidence += 20
    if rule_name == "credential_exfiltration":
        if not (page["has_password_field"] and page["has_network_api"]):
            confidence = min(confidence, 25)
        if page["has_suspicious_sink"]:
            confidence += 15
    if rule_name in {"paypal_phishing", "microsoft_phishing"}:
        confidence += 10
    return max(0, min(100, confidence))


def _false_positive_likelihood(confidence: int) -> str:
    if confidence >= 80:
        return "low"
    if confidence >= 55:
        return "moderate"
    return "high"


def _effective_severity(configured: str, confidence: int) -> str:
    if confidence < 35:
        return "informational"
    if confidence < 55 and configured in {"critical", "high"}:
        return "medium"
    return configured


def _score_for_match(severity: str, confidence: int) -> int:
    base = {"critical": 30, "high": 20, "medium": 10, "low": 5, "informational": 0}.get(severity, 0)
    return round(base * (confidence / 100))


def _executive_summary(matches: list[dict[str, Any]], risk_score: int, page: dict[str, Any]) -> dict[str, Any]:
    high_confidence = [match for match in matches if match["confidence"] >= 70]
    if not matches:
        headline = "No configured YARA rules matched the downloaded page content."
    elif not high_confidence:
        headline = "Indicators were detected, but the available evidence is insufficient for a high-confidence phishing classification."
    else:
        headline = "One or more high-confidence phishing or evasion patterns were detected and should be reviewed by an analyst."
    recommendations: list[str] = []
    if page["has_password_field"]:
        recommendations.append("Validate the form action and credential destination.")
    if page["has_obfuscation"]:
        recommendations.append("Decode and review the obfuscated JavaScript.")
    if page["has_suspicious_sink"]:
        recommendations.append("Investigate the detected webhook or external data sink.")
    if not recommendations:
        recommendations.append("Review matched evidence in context before taking action.")
    return {
        "headline": headline,
        "risk_score": risk_score,
        "high_confidence_matches": len(high_confidence),
        "recommendations": recommendations,
    }


def scan_url_with_yara(url: str) -> dict[str, Any]:
    try:
        page = fetch_page_content(url)
    except Exception as error:
        return {
            "url": url,
            "error": str(error),
            "matches": [],
            "total_matches": 0,
            "risk_score": 0,
            "risk_level": "Unknown",
            "rules_loaded": 0,
            "rules_defined": len(get_default_rules()),
            "compile_errors": [],
        }
    content = page.get("content", "")
    if not content:
        return {
            "url": url,
            "final_url": page.get("final_url", url),
            "error": "The page returned empty content.",
            "matches": [],
            "total_matches": 0,
            "risk_score": 0,
            "risk_level": "Low",
            "rules_loaded": 0,
            "rules_defined": len(get_default_rules()),
            "compile_errors": [],
        }
    compiled_rules, compile_errors = compile_rules()
    page_analysis = analyse_page(content, page.get("final_url", url))
    matches: list[dict[str, Any]] = []
    total_score = 0
    for name, rule in compiled_rules.items():
        try:
            yara_matches = rule.match(data=content)
        except yara.Error as error:
            compile_errors.append({"rule": name, "error": str(error)})
            continue
        for match in yara_matches:
            meta = match.meta
            configured = str(meta.get("severity", "medium")).lower()
            confidence = _confidence_for_match(match.rule, page_analysis)
            effective = _effective_severity(configured, confidence)
            score = _score_for_match(effective, confidence)
            total_score += score
            matches.append(
                {
                    "rule_name": match.rule,
                    "description": meta.get("description", ""),
                    "configured_severity": configured,
                    "severity": effective,
                    "category": meta.get("category", "unknown"),
                    "mitre_attack": meta.get("mitre", "Not mapped"),
                    "recommendation": meta.get("recommendation", "Review the evidence in context."),
                    "confidence": confidence,
                    "false_positive_likelihood": _false_positive_likelihood(confidence),
                    "score_contribution": score,
                    "matched_strings": _matched_strings(match),
                }
            )
    total_score = min(total_score, 100)
    if total_score >= 70:
        risk_level = "Critical"
    elif total_score >= 45:
        risk_level = "High"
    elif total_score >= 20:
        risk_level = "Medium"
    elif total_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Informational"
    matches.sort(key=lambda item: (item["confidence"], item["score_contribution"]), reverse=True)
    return {
        "url": url,
        "final_url": page.get("final_url", url),
        "status_code": page.get("status_code"),
        "content_length": page.get("content_length"),
        "redirect_count": page.get("redirect_count", 0),
        "matches": matches,
        "total_matches": len(matches),
        "risk_score": total_score,
        "risk_level": risk_level,
        "page_analysis": page_analysis,
        "rules_loaded": len(compiled_rules),
        "rules_defined": len(get_default_rules()),
        "compile_errors": compile_errors,
        "executive_summary": _executive_summary(matches, total_score, page_analysis),
        "scanner_version": "4.0",
        "disclaimer": "A YARA match is an indicator, not proof of phishing or malware. Analyst review is required.",
    }


def get_rules_info() -> dict[str, Any]:
    rules_dict = get_default_rules()
    compiled, errors = compile_rules()
    info: list[dict[str, Any]] = []
    for name, source in rules_dict.items():
        meta: dict[str, str] = {}
        in_meta = False
        for raw_line in source.splitlines():
            line = raw_line.strip()
            if line == "meta:":
                in_meta = True
                continue
            if in_meta and line == "strings:":
                break
            if in_meta and "=" in line:
                key, value = line.split("=", 1)
                meta[key.strip()] = value.strip().strip('"')
        info.append(
            {
                "name": name,
                "description": meta.get("description", ""),
                "severity": meta.get("severity", "unknown"),
                "category": meta.get("category", "unknown"),
                "mitre_attack": meta.get("mitre", "Not mapped"),
                "recommendation": meta.get("recommendation", ""),
                "compiled": name in compiled,
            }
        )
    return {
        "rules": info,
        "total": len(info),
        "compiled": len(compiled),
        "compile_errors": errors,
        "scanner_version": "4.0",
    }