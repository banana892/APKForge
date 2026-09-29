"""Unit tests for NetworkInspector."""

from __future__ import annotations

from apkforge.inspection.models import EvidenceSource, NativeStringReference, StringReference
from apkforge.inspection.network import NetworkInspector


def test_network_inspector_url_and_domain_extraction() -> None:
    src1 = EvidenceSource(file="classes.dex", class_name="com.example.NetClient")

    dex_strings = [
        StringReference(
            value="https://api.service.io/v1/auth",
            dex_file="classes.dex",
            source=src1,
        ),
        StringReference(
            value="http://backend.internal.org/health",
            dex_file="classes.dex",
            source=src1,
        ),
        # Noise / standard Android schema — should be excluded from domains
        StringReference(
            value="http://schemas.android.com/apk/res/android",
            dex_file="classes.dex",
            source=src1,
        ),
        # Duplicate URL
        StringReference(
            value="https://api.service.io/v1/auth",
            dex_file="classes.dex",
            source=src1,
        ),
    ]

    native_strings = [
        NativeStringReference(
            library="libnative.so",
            value="https://telemetry.analytics.net/event",
            offset=42,
        ),
    ]

    manifest_strings = [
        "deep-link.example.com",
    ]

    inspector = NetworkInspector()
    result, _warnings = inspector.inspect(
        dex_strings=dex_strings,
        native_strings=native_strings,
        manifest_strings=manifest_strings,
    )

    extracted_urls = [u.url for u in result.urls]
    assert "https://api.service.io/v1/auth" in extracted_urls
    assert "http://backend.internal.org/health" in extracted_urls
    assert "https://telemetry.analytics.net/event" in extracted_urls
    # Verify deduplication
    assert extracted_urls.count("https://api.service.io/v1/auth") == 1

    extracted_domains = [d.domain for d in result.domains]
    assert "api.service.io" in extracted_domains
    assert "backend.internal.org" in extracted_domains
    assert "telemetry.analytics.net" in extracted_domains
    assert "deep-link.example.com" in extracted_domains
    assert "schemas.android.com" not in extracted_domains  # Filtered out


def test_network_inspector_ip_extraction() -> None:
    dex_strings = [
        StringReference(
            value="Connect to 198.51.100.25 on port 8080",
            dex_file="classes.dex",
        ),
        StringReference(
            value="Ignored loopback 127.0.0.1",
            dex_file="classes.dex",
        ),
        StringReference(
            value="IPv6 host 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            dex_file="classes.dex",
        ),
    ]

    inspector = NetworkInspector()
    result, _warnings = inspector.inspect(dex_strings=dex_strings)

    ips = {ip.address: ip.version for ip in result.ip_addresses}
    assert "198.51.100.25" in ips
    assert ips["198.51.100.25"] == 4
    assert "127.0.0.1" not in ips  # Filtered out loopback
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in ips
    assert ips["2001:0db8:85a3:0000:0000:8a2e:0370:7334"] == 6
