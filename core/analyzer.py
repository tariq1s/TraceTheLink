from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup


DEFAULT_TIMEOUT = 7
DEFAULT_MAX_REDIRECTS = 10
DEFAULT_USER_AGENT = "TraceTheLink/1.0 (+defensive-url-triage)"
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}
BLOCKED_HOST_SUFFIXES = (".internal", ".local", ".home.arpa")
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]
BLOCKED_IP_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}

STATUS_EXPLANATIONS = {
    200: "OK - Final content delivered.",
    301: "Moved Permanently - Common infrastructure redirect.",
    302: "Found - Frequently used for tracking and routing.",
    303: "See Other - Redirect to a different resource.",
    307: "Temporary Redirect - Method preserved.",
    308: "Permanent Redirect - Method preserved.",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "is.gd",
}
SUSPICIOUS_TLDS = {"zip", "xyz", "click", "loan", "top", "gq", "work", "country"}
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "secure",
    "wallet",
    "bank",
    "invoice",
    "mfa",
    "reset",
    "update",
    "gift",
    "bonus",
}
JS_REDIRECT_PATTERNS = [
    re.compile(r"window\.location(?:\.href)?\s*=\s*['\"](.*?)['\"]", re.IGNORECASE),
    re.compile(r"location\.replace\(\s*['\"](.*?)['\"]\s*\)", re.IGNORECASE),
]


@dataclass
class AnalysisOptions:
    timeout: int = DEFAULT_TIMEOUT
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    allow_private: bool = False


def explain_status(code: int | None) -> str:
    if code is None:
        return "No HTTP status available."
    return STATUS_EXPLANATIONS.get(code, "Status observed during link triage.")


def read_url_file(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            urls.append(candidate)
    return urls


def analyze_batch(
    urls: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private: bool = False,
) -> list[dict[str, Any]]:
    return [
        analyze_url(url, timeout=timeout, max_redirects=max_redirects, allow_private=allow_private)
        for url in urls
    ]


def analyze_url(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private: bool = False,
) -> dict[str, Any]:
    original_url = normalize_url(url)
    validate_runtime_options(timeout=timeout, max_redirects=max_redirects)
    enforce_target_safety(original_url, allow_private=allow_private)
    analyzed_at = datetime.now(timezone.utc).isoformat()
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    hops: list[dict[str, Any]] = []
    visited: set[str] = set()
    current_url = original_url
    static_findings: dict[str, Any] = {}
    error_message: str | None = None

    for depth in range(max_redirects + 1):
        if not current_url:
            break

        if current_url in visited:
            hops.append(
                {
                    "hop": len(hops) + 1,
                    "url": current_url,
                    "status_code": None,
                    "status_text": "LOOP",
                    "reason": "Redirect loop detected.",
                    "redirect_type": "loop",
                    "location": None,
                    "domain": extract_registered_domain(current_url),
                }
            )
            error_message = "Redirect loop detected."
            break

        visited.add(current_url)

        try:
            response = session.get(current_url, allow_redirects=False, timeout=timeout)
        except requests.Timeout:
            message = f"Request timed out after {timeout} seconds."
            hops.append(
                {
                    "hop": len(hops) + 1,
                    "url": current_url,
                    "status_code": None,
                    "status_text": "TIMEOUT",
                    "reason": message,
                    "redirect_type": "error",
                    "location": None,
                    "domain": extract_registered_domain(current_url),
                }
            )
            error_message = message
            break
        except requests.ConnectionError as exc:
            message = f"Connection error: {exc}"
            hops.append(
                {
                    "hop": len(hops) + 1,
                    "url": current_url,
                    "status_code": None,
                    "status_text": "CONNECTION_ERROR",
                    "reason": message,
                    "redirect_type": "error",
                    "location": None,
                    "domain": extract_registered_domain(current_url),
                }
            )
            error_message = message
            break
        except requests.RequestException as exc:
            hops.append(
                {
                    "hop": len(hops) + 1,
                    "url": current_url,
                    "status_code": None,
                    "status_text": "ERROR",
                    "reason": str(exc),
                    "redirect_type": "error",
                    "location": None,
                    "domain": extract_registered_domain(current_url),
                }
            )
            error_message = str(exc)
            break

        next_url, redirect_type, static_findings = inspect_response_for_redirect(response)
        resolved_next = urljoin(response.url, next_url) if next_url else None

        hops.append(
            {
                "hop": len(hops) + 1,
                "url": response.url,
                "status_code": response.status_code,
                "status_text": explain_status(response.status_code),
                "reason": explain_status(response.status_code),
                "redirect_type": redirect_type,
                "location": resolved_next,
                "domain": extract_registered_domain(response.url),
                "headers": summarize_headers(response.headers),
            }
        )

        if not resolved_next:
            break

        if depth >= max_redirects:
            error_message = f"Too many redirects: maximum redirect depth reached ({max_redirects})."
            break

        enforce_target_safety(resolved_next, allow_private=allow_private)
        current_url = resolved_next

    session.close()

    final_hop = hops[-1] if hops else None
    final_url = final_hop["url"] if final_hop else original_url
    domain_changes = build_domain_changes(hops)
    suspicious_indicators = collect_suspicious_indicators(original_url, hops, static_findings, error_message, max_redirects)
    risk_score, risk_level, risk_reasoning, recommended_action = score_analysis(
        original_url=original_url,
        hops=hops,
        static_findings=static_findings,
        indicators=suspicious_indicators,
    )

    return {
        "original_url": original_url,
        "analyzed_at": analyzed_at,
        "redirect_chain": hops,
        "final_url": final_url,
        "final_status_code": final_hop["status_code"] if final_hop else None,
        "final_status_text": final_hop["status_text"] if final_hop else "No response",
        "domain_changes": domain_changes,
        "title": static_findings.get("title"),
        "metadata": static_findings.get("metadata", {}),
        "suspicious_indicators": suspicious_indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasoning": risk_reasoning,
        "recommended_action": recommended_action,
        "error": error_message,
        "options": {
            "timeout": timeout,
            "max_redirect_depth": max_redirects,
            "allow_private": allow_private,
        },
    }


def normalize_url(url: str) -> str:
    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("URL is empty.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported scheme: {parsed.scheme}. Only http and https are supported.")
    if not parsed.netloc:
        raise ValueError("Invalid URL: hostname is missing.")
    if not parsed.hostname:
        raise ValueError("Invalid URL: unable to determine hostname.")
    return candidate


def validate_runtime_options(timeout: int, max_redirects: int) -> None:
    if timeout <= 0:
        raise ValueError("Timeout must be a positive integer.")
    if max_redirects <= 0:
        raise ValueError("Max redirect depth must be a positive integer.")


def enforce_target_safety(url: str, allow_private: bool) -> None:
    if allow_private:
        return

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host:
        raise ValueError("Invalid URL: unable to determine hostname.")
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise ValueError(f"Private/internal target blocked by default: {host}")

    if is_ip_address(host):
        ip = ipaddress.ip_address(host)
        if is_blocked_ip(ip):
            raise ValueError(f"Private/internal target blocked by default: {host}")
        return

    try:
        addrinfo = socket.getaddrinfo(host, parsed.port or default_port_for_scheme(parsed.scheme), type=socket.SOCK_STREAM)
    except socket.gaierror:
        return

    for item in addrinfo:
        resolved_host = item[4][0]
        try:
            ip = ipaddress.ip_address(resolved_host)
        except ValueError:
            continue
        if is_blocked_ip(ip):
            raise ValueError(
                f"Private/internal target blocked by default: {host} resolved to {resolved_host}"
            )


def default_port_for_scheme(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    if ip in BLOCKED_IP_ADDRESSES:
        return True
    return any(ip in network for network in BLOCKED_IP_NETWORKS)


def inspect_response_for_redirect(response: requests.Response) -> tuple[str | None, str | None, dict[str, Any]]:
    html = response.text or ""
    soup = BeautifulSoup(html, "lxml")

    title = soup.title.get_text(strip=True) if soup.title else None
    metadata = {
        "meta_description": meta_content(soup, "description"),
        "meta_refresh": None,
        "javascript_redirect": None,
        "content_type": response.headers.get("Content-Type"),
        "server": response.headers.get("Server"),
    }

    location = response.headers.get("Location")
    if response.status_code in (301, 302, 303, 307, 308) and location:
        metadata["meta_refresh"] = extract_meta_refresh(soup)
        metadata["javascript_redirect"] = extract_js_redirect(html)
        return location, "http_redirect", {"title": title, "metadata": metadata}

    meta_refresh = extract_meta_refresh(soup)
    if meta_refresh:
        metadata["meta_refresh"] = meta_refresh
        metadata["javascript_redirect"] = extract_js_redirect(html)
        return meta_refresh, "meta_refresh", {"title": title, "metadata": metadata}

    js_redirect = extract_js_redirect(html)
    if js_redirect:
        metadata["javascript_redirect"] = js_redirect
        return js_redirect, "javascript_redirect", {"title": title, "metadata": metadata}

    return None, None, {"title": title, "metadata": metadata}


def meta_content(soup: BeautifulSoup, name: str) -> str | None:
    meta = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.IGNORECASE)})
    if meta:
        return meta.get("content")
    return None


def extract_meta_refresh(soup: BeautifulSoup) -> str | None:
    meta = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.IGNORECASE)})
    if not meta:
        return None

    content = meta.get("content", "")
    match = re.search(r"url\s*=\s*(.+)$", content, re.IGNORECASE)
    return match.group(1).strip(" '\"") if match else None


def extract_js_redirect(html: str) -> str | None:
    for pattern in JS_REDIRECT_PATTERNS:
        match = pattern.search(html)
        if match:
            return match.group(1).strip()
    return None


def summarize_headers(headers: Any) -> dict[str, str]:
    keep = [
        "Location",
        "Content-Type",
        "Server",
        "X-Frame-Options",
        "Content-Security-Policy",
    ]
    summary: dict[str, str] = {}
    for name, value in headers.items():
        if name not in keep:
            continue
        if len(value) > 180:
            summary[name] = f"{value[:177]}..."
        else:
            summary[name] = value
    return summary


def extract_registered_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    extracted = tldextract.extract(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def build_domain_changes(hops: list[dict[str, Any]]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    previous = None
    for hop in hops:
        domain = hop.get("domain")
        if not domain:
            continue
        if previous and previous != domain:
            changes.append({"from": previous, "to": domain})
        previous = domain
    return changes


def collect_suspicious_indicators(
    original_url: str,
    hops: list[dict[str, Any]],
    static_findings: dict[str, Any],
    error_message: str | None,
    max_redirects: int,
) -> list[str]:
    indicators: list[str] = []
    parsed = urlparse(original_url)
    host = parsed.hostname or ""
    registered = extract_registered_domain(original_url)
    suffix = tldextract.extract(host).suffix

    if registered in SHORTENERS:
        indicators.append("Known URL shortener domain.")
    if suffix in SUSPICIOUS_TLDS:
        indicators.append(f"Suspicious top-level domain observed: .{suffix}.")
    if any(keyword in original_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
        indicators.append("URL contains terms commonly used in phishing themes.")
    if host.startswith("xn--"):
        indicators.append("Punycode hostname detected.")
    if is_ip_address(host):
        indicators.append("Direct IP address used instead of a domain name.")
    if len(hops) > 4:
        indicators.append("Long redirect chain may indicate tracking or obfuscation.")
    if len(build_domain_changes(hops)) >= 2:
        indicators.append("Multiple domain changes observed across the redirect chain.")
    if static_findings.get("metadata", {}).get("meta_refresh"):
        indicators.append("Meta refresh redirect detected.")
    if static_findings.get("metadata", {}).get("javascript_redirect"):
        indicators.append("Static JavaScript redirect pattern detected.")
    if error_message and "Maximum redirect depth reached" in error_message:
        indicators.append(f"Redirect chain exceeded configured depth of {max_redirects}.")
    if error_message and "loop" in error_message.lower():
        indicators.append("Redirect loop detected.")

    return indicators


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def score_analysis(
    original_url: str,
    hops: list[dict[str, Any]],
    static_findings: dict[str, Any],
    indicators: list[str],
) -> tuple[int, str, list[str], str]:
    score = 0
    reasoning: list[str] = []

    if not hops:
        score += 40
        reasoning.append("No response data was collected, so the destination could not be validated.")

    for indicator in indicators:
        if "shortener" in indicator.lower():
            score += 20
        elif "suspicious top-level domain" in indicator.lower():
            score += 20
        elif "phishing themes" in indicator.lower():
            score += 15
        elif "multiple domain changes" in indicator.lower():
            score += 20
        elif "long redirect chain" in indicator.lower():
            score += 15
        elif "javascript redirect" in indicator.lower():
            score += 10
        elif "meta refresh" in indicator.lower():
            score += 10
        elif "punycode" in indicator.lower() or "ip address" in indicator.lower():
            score += 25
        else:
            score += 10
        reasoning.append(indicator)

    final_status = hops[-1].get("status_code") if hops else None
    if final_status and final_status >= 400:
        score += 10
        reasoning.append(f"Final HTTP status code was {final_status}.")

    title = static_findings.get("title")
    if title and any(word in title.lower() for word in SUSPICIOUS_KEYWORDS):
        score += 10
        reasoning.append("Page title contains credential or lure terminology.")

    score = min(score, 100)
    if score >= 70:
        level = "high"
        action = "Escalate for phishing review, validate the final destination, and block if unsupported by business context."
    elif score >= 35:
        level = "medium"
        action = "Review business context, compare domains against known-good infrastructure, and inspect surrounding email or chat artifacts."
    else:
        level = "low"
        action = "Document the redirect behavior and monitor only if the link appears in a suspicious campaign or unusual workflow."

    if not reasoning:
        reasoning.append("No notable redirect or content-based risk indicators were identified from static HTTP analysis.")

    return score, level, reasoning, action
