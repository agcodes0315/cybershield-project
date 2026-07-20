from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


REQUEST_TIMEOUT_SECONDS = 8
TLS_TIMEOUT_SECONDS = 6


def normalise_target(target: str) -> tuple[str, str]:
    cleaned = str(target or "").strip()

    if not cleaned:
        raise ValueError("A domain or URL is required.")

    parsed = urlparse(
        cleaned
        if cleaned.startswith(("http://", "https://"))
        else f"https://{cleaned}"
    )

    domain = parsed.hostname or ""

    if not domain:
        raise ValueError("The submitted target does not contain a valid hostname.")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        domain = domain.rstrip(".").lower()

    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"

    port = parsed.port

    if port:
        url = f"{scheme}://{domain}:{port}"
    else:
        url = f"{scheme}://{domain}"

    path = parsed.path or ""

    if path and path != "/":
        url = f"{url}{path}"

    return domain, url


def unique_in_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


def capture_dns_resolution(domain: str) -> dict[str, Any]:
    started_at = time.perf_counter()

    try:
        records = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

        response_time_ms = round(
            (time.perf_counter() - started_at) * 1000,
            2,
        )

        ipv4_addresses: list[str] = []
        ipv6_addresses: list[str] = []

        for family, _, _, canonical_name, socket_address in records:
            address = socket_address[0]

            if family == socket.AF_INET:
                ipv4_addresses.append(address)
            elif family == socket.AF_INET6:
                ipv6_addresses.append(address)

        ipv4_addresses = unique_in_order(ipv4_addresses)
        ipv6_addresses = unique_in_order(ipv6_addresses)

        all_addresses = ipv4_addresses + ipv6_addresses

        canonical_name = ""

        try:
            canonical_name = socket.getfqdn(domain)
        except Exception:
            canonical_name = domain

        selected_address = (
            ipv4_addresses[0]
            if ipv4_addresses
            else ipv6_addresses[0]
            if ipv6_addresses
            else None
        )

        reverse_dns = None

        if selected_address:
            try:
                reverse_dns = socket.gethostbyaddr(selected_address)[0]
            except Exception:
                reverse_dns = None

        return {
            "status": "resolved",
            "query": domain,
            "query_type": "A/AAAA",
            "canonical_name": canonical_name,
            "resolved_ips": all_addresses,
            "ipv4_addresses": ipv4_addresses,
            "ipv6_addresses": ipv6_addresses,
            "selected_address": selected_address,
            "reverse_dns": reverse_dns,
            "response_time_ms": response_time_ms,
            "record_count": len(all_addresses),
            "address_families": [
                family
                for family, values in (
                    ("IPv4", ipv4_addresses),
                    ("IPv6", ipv6_addresses),
                )
                if values
            ],
            "dnssec_evaluated": False,
            "dnssec_status": "not_evaluated",
            "resolver_note": (
                "Resolution performed through the operating system resolver."
            ),
        }

    except socket.gaierror as error:
        return {
            "status": "failed",
            "query": domain,
            "query_type": "A/AAAA",
            "resolved_ips": [],
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "selected_address": None,
            "reverse_dns": None,
            "response_time_ms": round(
                (time.perf_counter() - started_at) * 1000,
                2,
            ),
            "record_count": 0,
            "error": str(error),
            "dnssec_evaluated": False,
            "dnssec_status": "not_evaluated",
        }


def parse_certificate_date(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        timestamp = ssl.cert_time_to_seconds(value)
        return datetime.fromtimestamp(timestamp, timezone.utc)
    except Exception:
        return None


def certificate_matches_hostname(
    certificate: dict[str, Any],
    domain: str,
) -> tuple[bool, str | None]:
    try:
        ssl.match_hostname(certificate, domain)
        return True, None
    except Exception as error:
        return False, str(error)


def build_tls_13_steps(
    version: str,
    cipher_name: str,
    cipher_bits: int,
    domain: str,
    issuer_name: str,
    duration_ms: float,
) -> list[dict[str, Any]]:
    return [
        {
            "step": 1,
            "direction": "client_to_server",
            "message": "ClientHello",
            "detail": (
                f"Client proposes {version}, supported cipher suites, "
                "extensions and an ephemeral key share."
            ),
        },
        {
            "step": 2,
            "direction": "server_to_client",
            "message": "ServerHello",
            "detail": (
                f"Server selects {cipher_name} ({cipher_bits}-bit) "
                "and returns its ephemeral key share."
            ),
        },
        {
            "step": 3,
            "direction": "server_to_client",
            "message": "EncryptedExtensions",
            "detail": (
                "Server sends negotiated encrypted connection parameters."
            ),
        },
        {
            "step": 4,
            "direction": "server_to_client",
            "message": "Certificate",
            "detail": (
                f"Server presents a certificate for {domain}, "
                f"issued by {issuer_name}."
            ),
        },
        {
            "step": 5,
            "direction": "server_to_client",
            "message": "CertificateVerify",
            "detail": (
                "Server proves possession of the certificate private key."
            ),
        },
        {
            "step": 6,
            "direction": "server_to_client",
            "message": "Server Finished",
            "detail": (
                "Server authenticates the handshake transcript."
            ),
        },
        {
            "step": 7,
            "direction": "client_to_server",
            "message": "Client Finished",
            "detail": (
                "Client validates the server and completes the handshake."
            ),
        },
        {
            "step": 8,
            "direction": "both",
            "message": "Encrypted Application Data",
            "detail": (
                f"Secure application traffic can now flow. "
                f"Handshake completed in {duration_ms} ms."
            ),
        },
    ]


def build_tls_12_steps(
    version: str,
    cipher_name: str,
    cipher_bits: int,
    domain: str,
    issuer_name: str,
    duration_ms: float,
) -> list[dict[str, Any]]:
    return [
        {
            "step": 1,
            "direction": "client_to_server",
            "message": "ClientHello",
            "detail": (
                f"Client proposes {version} and supported cipher suites."
            ),
        },
        {
            "step": 2,
            "direction": "server_to_client",
            "message": "ServerHello",
            "detail": (
                f"Server selects {cipher_name} ({cipher_bits}-bit)."
            ),
        },
        {
            "step": 3,
            "direction": "server_to_client",
            "message": "Certificate",
            "detail": (
                f"Server presents a certificate for {domain}, "
                f"issued by {issuer_name}."
            ),
        },
        {
            "step": 4,
            "direction": "server_to_client",
            "message": "Server Key Exchange",
            "detail": (
                "Server supplies ephemeral key-exchange parameters when required."
            ),
        },
        {
            "step": 5,
            "direction": "client_to_server",
            "message": "Client Key Exchange",
            "detail": (
                "Client contributes key-exchange material used to derive session keys."
            ),
        },
        {
            "step": 6,
            "direction": "both",
            "message": "Change Cipher Spec",
            "detail": (
                "Both peers begin using the negotiated encryption parameters."
            ),
        },
        {
            "step": 7,
            "direction": "both",
            "message": "Finished",
            "detail": (
                f"Secure session established in {duration_ms} ms."
            ),
        },
    ]


def capture_tls_handshake(domain: str) -> dict[str, Any]:
    started_at = time.perf_counter()

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=TLS_TIMEOUT_SECONDS,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=domain,
            ) as secure_socket:
                duration_ms = round(
                    (time.perf_counter() - started_at) * 1000,
                    2,
                )

                certificate = secure_socket.getpeercert()
                cipher = secure_socket.cipher()
                version = secure_socket.version() or "Unknown"

                subject = dict(
                    item[0]
                    for item in certificate.get("subject", [])
                )

                issuer = dict(
                    item[0]
                    for item in certificate.get("issuer", [])
                )

                san_domains = [
                    value
                    for name_type, value
                    in certificate.get("subjectAltName", [])
                    if name_type == "DNS"
                ]

                issuer_name = (
                    issuer.get("commonName")
                    or issuer.get("organizationName")
                    or "Unknown issuer"
                )

                cipher_name = (
                    cipher[0]
                    if cipher
                    else "Unknown cipher"
                )

                cipher_bits = (
                    cipher[2]
                    if cipher
                    else 0
                )

                hostname_valid, hostname_error = (
                    certificate_matches_hostname(
                        certificate,
                        domain,
                    )
                )

                not_before = parse_certificate_date(
                    certificate.get("notBefore")
                )

                not_after = parse_certificate_date(
                    certificate.get("notAfter")
                )

                now = datetime.now(timezone.utc)

                expired = bool(
                    not_after and not_after < now
                )

                not_yet_valid = bool(
                    not_before and not_before > now
                )

                days_remaining = None

                if not_after:
                    days_remaining = max(
                        0,
                        (not_after - now).days,
                    )

                if version.startswith("TLSv1.3"):
                    handshake_steps = build_tls_13_steps(
                        version=version,
                        cipher_name=cipher_name,
                        cipher_bits=cipher_bits,
                        domain=domain,
                        issuer_name=issuer_name,
                        duration_ms=duration_ms,
                    )
                else:
                    handshake_steps = build_tls_12_steps(
                        version=version,
                        cipher_name=cipher_name,
                        cipher_bits=cipher_bits,
                        domain=domain,
                        issuer_name=issuer_name,
                        duration_ms=duration_ms,
                    )

                return {
                    "status": "success",
                    "handshake_time_ms": duration_ms,
                    "tls_version": version,
                    "cipher_suite": cipher_name,
                    "cipher_bits": cipher_bits,
                    "hostname_valid": hostname_valid,
                    "hostname_error": hostname_error,
                    "certificate_valid": (
                        hostname_valid
                        and not expired
                        and not not_yet_valid
                    ),
                    "forward_secrecy_likely": (
                        version.startswith("TLSv1.3")
                        or "ECDHE" in cipher_name
                        or "DHE" in cipher_name
                    ),
                    "certificate": {
                        "subject_cn": subject.get(
                            "commonName",
                            domain,
                        ),
                        "issuer_cn": issuer.get(
                            "commonName",
                            "",
                        ),
                        "issuer_org": issuer.get(
                            "organizationName",
                            "",
                        ),
                        "not_before": certificate.get(
                            "notBefore",
                            "",
                        ),
                        "not_after": certificate.get(
                            "notAfter",
                            "",
                        ),
                        "expired": expired,
                        "not_yet_valid": not_yet_valid,
                        "days_remaining": days_remaining,
                        "serial_number": certificate.get(
                            "serialNumber",
                            "",
                        ),
                        "san_domains": san_domains[:20],
                        "san_count": len(san_domains),
                    },
                    "handshake_steps": handshake_steps,
                }

    except Exception as error:
        return {
            "status": "failed",
            "error": str(error),
            "handshake_time_ms": round(
                (time.perf_counter() - started_at) * 1000,
                2,
            ),
            "handshake_steps": [],
        }


def capture_http_exchange(url: str) -> dict[str, Any]:
    started_at = time.perf_counter()

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=False,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "CyberShield-NetworkTrace/2.0"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/json;q=0.9,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            },
        )

        duration_ms = round(
            (time.perf_counter() - started_at) * 1000,
            2,
        )

        parsed = urlparse(url)

        redirect_chain = [
            {
                "status": historical_response.status_code,
                "location": historical_response.headers.get(
                    "Location",
                    "",
                ),
                "url": historical_response.url,
            }
            for historical_response in response.history
        ]

        cookies = [
            {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "expires": (
                    str(cookie.expires)
                    if cookie.expires
                    else None
                ),
            }
            for cookie in response.cookies
        ]

        return {
            "status": "captured",
            "url": url,
            "final_url": response.url,
            "response_time_ms": duration_ms,
            "request": {
                "method": "GET",
                "url": url,
                "headers": {
                    "Method": "GET",
                    "Path": parsed.path or "/",
                    "Host": parsed.netloc,
                    "User-Agent": (
                        "CyberShield-NetworkTrace/2.0"
                    ),
                    "Accept": (
                        "text/html,application/xhtml+xml,"
                        "application/json;q=0.9,*/*;q=0.8"
                    ),
                    "Connection": "close",
                },
            },
            "response": {
                "status_code": response.status_code,
                "status_text": response.reason,
                "headers": dict(response.headers),
                "content_length": len(response.content),
                "content_type": response.headers.get(
                    "Content-Type",
                    "Unknown",
                ),
                "encoding": response.encoding,
            },
            "cookies": cookies,
            "redirect_chain": redirect_chain,
            "timing": {
                "total_ms": duration_ms,
            },
        }

    except Exception as error:
        return {
            "status": "failed",
            "url": url,
            "error": str(error),
            "response_time_ms": round(
                (time.perf_counter() - started_at) * 1000,
                2,
            ),
        }


def add_trace_event(
    events: list[dict[str, Any]],
    number: int,
    elapsed_seconds: float,
    source: str,
    destination: str,
    protocol: str,
    info: str,
    length: int | str = "estimated",
    evidence_type: str = "derived",
) -> int:
    events.append(
        {
            "no": number,
            "time": f"{elapsed_seconds:.3f}",
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": length,
            "info": info,
            "evidence_type": evidence_type,
        }
    )

    return number + 1


def build_transaction_trace(
    domain: str,
    dns_result: dict[str, Any],
    tls_result: dict[str, Any],
    http_result: dict[str, Any],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    sequence = 1
    elapsed = 0.0

    selected_address = (
        dns_result.get("selected_address")
        or "Remote server"
    )

    if dns_result.get("status") == "resolved":
        sequence = add_trace_event(
            events,
            sequence,
            elapsed,
            "Client",
            "System DNS resolver",
            "DNS",
            f"Resolve A and AAAA records for {domain}",
            evidence_type="observed_operation",
        )

        elapsed += (
            float(
                dns_result.get(
                    "response_time_ms",
                    0,
                )
            )
            / 1000
        )

        addresses = dns_result.get(
            "resolved_ips",
            [],
        )

        sequence = add_trace_event(
            events,
            sequence,
            elapsed,
            "System DNS resolver",
            "Client",
            "DNS",
            (
                "Resolved "
                + ", ".join(addresses[:4])
                if addresses
                else "No addresses returned"
            ),
            evidence_type="observed_result",
        )

    if tls_result.get("status") == "success":
        elapsed += 0.001

        sequence = add_trace_event(
            events,
            sequence,
            elapsed,
            "Client",
            selected_address,
            "TCP",
            f"Open TCP connection to {domain}:443",
            evidence_type="derived",
        )

        elapsed += 0.01

        sequence = add_trace_event(
            events,
            sequence,
            elapsed,
            selected_address,
            "Client",
            "TCP",
            "TCP connection established",
            evidence_type="derived",
        )

        for handshake_step in tls_result.get(
            "handshake_steps",
            [],
        ):
            elapsed += 0.012

            direction = handshake_step.get(
                "direction",
                "both",
            )

            if direction == "client_to_server":
                source = "Client"
                destination = selected_address
            elif direction == "server_to_client":
                source = selected_address
                destination = "Client"
            else:
                source = "Both peers"
                destination = "Encrypted channel"

            sequence = add_trace_event(
                events,
                sequence,
                elapsed,
                source,
                destination,
                tls_result.get(
                    "tls_version",
                    "TLS",
                ),
                handshake_step.get(
                    "message",
                    "TLS handshake event",
                ),
                evidence_type="modelled_stage",
            )

    if http_result.get("status") == "captured":
        elapsed += 0.015

        request = http_result.get(
            "request",
            {},
        )

        response = http_result.get(
            "response",
            {},
        )

        sequence = add_trace_event(
            events,
            sequence,
            elapsed,
            "Client",
            selected_address,
            "HTTPS",
            (
                f'{request.get("method", "GET")} '
                f'{request.get("headers", {}).get("Path", "/")}'
            ),
            evidence_type="observed_operation",
        )

        elapsed += (
            float(
                http_result.get(
                    "response_time_ms",
                    0,
                )
            )
            / 1000
        )

        add_trace_event(
            events,
            sequence,
            elapsed,
            selected_address,
            "Client",
            "HTTPS",
            (
                f'{response.get("status_code", "Unknown")} '
                f'{response.get("status_text", "")} — '
                f'{response.get("content_length", 0)} bytes'
            ),
            evidence_type="observed_result",
        )

    return events


def full_network_capture(target: str) -> dict[str, Any]:
    try:
        domain, url = normalise_target(target)
    except ValueError as error:
        return {
            "error": str(error),
            "status": "failed",
        }

    started_at = time.perf_counter()

    dns_result = capture_dns_resolution(domain)
    tls_result = capture_tls_handshake(domain)
    http_result = capture_http_exchange(url)

    total_duration_ms = round(
        (time.perf_counter() - started_at) * 1000,
        2,
    )

    transaction_trace = build_transaction_trace(
        domain=domain,
        dns_result=dns_result,
        tls_result=tls_result,
        http_result=http_result,
    )

    warnings: list[str] = []

    if dns_result.get("status") != "resolved":
        warnings.append(
            "DNS resolution was unsuccessful."
        )

    if tls_result.get("status") != "success":
        warnings.append(
            "TLS inspection was unsuccessful or unavailable."
        )

    if http_result.get("status") != "captured":
        warnings.append(
            "HTTP transaction inspection was unsuccessful."
        )

    return {
        "status": "completed",
        "trace_type": "application_generated",
        "raw_pcap": False,
        "disclaimer": (
            "This is an application-generated network transaction trace. "
            "It is not a raw PCAP capture and does not replace Wireshark "
            "or tcpdump evidence."
        ),
        "target": target,
        "domain": domain,
        "url": url,
        "total_packets": len(transaction_trace),
        "total_events": len(transaction_trace),
        "total_duration_ms": total_duration_ms,
        "packet_table": transaction_trace,
        "transaction_trace": transaction_trace,
        "dns": dns_result,
        "tls": tls_result,
        "http": http_result,
        "warnings": warnings,
    }