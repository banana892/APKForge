"""Network inspector — URL, domain, and IP address extraction.

Extracts URLs, domain names, and IP addresses from DEX strings, resources,
assets, manifest data, and native library strings.

Security invariant:
- Does NOT connect to discovered URLs/IPs.
- Does NOT perform reputation lookups.
- Does NOT resolve domain names.
- Static extraction only.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    DomainReference,
    EvidenceSource,
    IPAddressReference,
    NetworkInspection,
    URLReference,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import (
        NativeStringReference,
        StringReference,
    )

__all__ = ["NetworkInspector"]

_log = get_logger(__name__)

# URL pattern — matches http(s) and common protocol schemes
_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\)\]\}\\]{4,256}",
    re.IGNORECASE,
)

# Domain pattern — basic domain name extraction
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|org|net|edu|gov|mil|int|io|co|app|dev|xyz|info|biz|"
    r"me|tv|cc|us|uk|de|fr|jp|cn|ru|br|in|au|ca|nl|it|es|se|no|"
    r"fi|dk|pl|cz|sk|at|ch|be|ie|pt|gr|hu|ro|bg|hr|si|lt|lv|ee|"
    r"cloud|online|site|tech|store|top|pro)\b",
    re.IGNORECASE,
)

# IPv4 pattern
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# IPv6 pattern (simplified — catches common forms)
_IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{1,4}\b",
    re.IGNORECASE,
)

# Domains to exclude (too common / noise)
_EXCLUDED_DOMAINS = frozenset(
    {
        "schemas.android.com",
        "www.w3.org",
        "xmlpull.org",
        "xml.org",
        "ns.adobe.com",
        "purl.org",
        "example.com",
        "localhost",
    }
)

# IP addresses to exclude
_EXCLUDED_IPS = frozenset(
    {
        "0.0.0.0",  # noqa: S104
        "127.0.0.1",
        "255.255.255.255",
    }
)


class NetworkInspector:
    """Extracts URLs, domains, and IP addresses from APK content.

    Processes DEX strings, native strings, and any additional string
    sources to build a network-related inventory.
    """

    def inspect(
        self,
        dex_strings: list[StringReference] | None = None,
        native_strings: list[NativeStringReference] | None = None,
        manifest_strings: list[str] | None = None,
    ) -> tuple[NetworkInspection, list[str]]:
        """Extract network-related data from string sources.

        Args:
            dex_strings: Strings extracted from DEX files.
            native_strings: Strings extracted from native libraries.
            manifest_strings: Relevant strings from the manifest.

        Returns:
            Tuple of (NetworkInspection, warnings).
        """
        warnings: list[str] = []
        result = NetworkInspection()

        url_set: dict[str, URLReference] = {}
        domain_map: dict[str, list[EvidenceSource]] = {}
        ip_map: dict[str, tuple[int, list[EvidenceSource]]] = {}

        # Process DEX strings
        if dex_strings:
            for s in dex_strings:
                source = EvidenceSource(
                    file=s.dex_file,
                    class_name=s.class_name,
                    method_name=s.method_name,
                )
                self._extract_from_string(s.value, source, url_set, domain_map, ip_map)

        # Process native strings
        if native_strings:
            for s in native_strings:
                source = EvidenceSource(
                    file=s.library,
                    offset=s.offset,
                )
                self._extract_from_string(s.value, source, url_set, domain_map, ip_map)

        # Process manifest strings
        if manifest_strings:
            for s in manifest_strings:
                source = EvidenceSource(file="AndroidManifest.xml")
                self._extract_from_string(s, source, url_set, domain_map, ip_map)

        result.urls = list(url_set.values())
        result.domains = [
            DomainReference(domain=d, sources=srcs) for d, srcs in sorted(domain_map.items())
        ]
        result.ip_addresses = [
            IPAddressReference(address=ip, version=ver, sources=srcs)
            for ip, (ver, srcs) in sorted(ip_map.items())
        ]

        return result, warnings

    def _extract_from_string(
        self,
        value: str,
        source: EvidenceSource,
        url_set: dict[str, URLReference],
        domain_map: dict[str, list[EvidenceSource]],
        ip_map: dict[str, tuple[int, list[EvidenceSource]]],
    ) -> None:
        """Extract URLs, domains, and IPs from a single string."""
        # URLs
        for match in _URL_PATTERN.finditer(value):
            url = match.group(0).rstrip(".,;:)")
            normalized = url.lower()
            if normalized not in url_set:
                url_set[normalized] = URLReference(url=url, source=source)

        # Domains
        for match in _DOMAIN_PATTERN.finditer(value):
            domain = match.group(0).lower()
            if domain not in _EXCLUDED_DOMAINS and len(domain) > 3:
                if domain not in domain_map:
                    domain_map[domain] = []
                # Limit sources per domain
                if len(domain_map[domain]) < 10:
                    domain_map[domain].append(source)

        # IPv4
        for match in _IPV4_PATTERN.finditer(value):
            ip = match.group(0)
            if ip not in _EXCLUDED_IPS:
                if ip not in ip_map:
                    ip_map[ip] = (4, [])
                if len(ip_map[ip][1]) < 10:
                    ip_map[ip][1].append(source)

        # IPv6
        for match in _IPV6_PATTERN.finditer(value):
            ip = match.group(0).lower()
            if ip not in ("::1", "::"):
                if ip not in ip_map:
                    ip_map[ip] = (6, [])
                if len(ip_map[ip][1]) < 10:
                    ip_map[ip][1].append(source)
