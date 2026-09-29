"""Surveillance capability analyzer: audio, camera, location, and overlay."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.security.models import SecurityFinding

if TYPE_CHECKING:
    from apkforge.security.rules import SecurityEvidenceIndex

_log = logging.getLogger(__name__)


class SurveillanceAnalyzer:
    """Analyzes audio, camera, physical location, and overlay surveillance capabilities."""

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Correlate permissions, APIs, components, and endpoints for surveillance capabilities."""
        findings: list[SecurityFinding] = []

        has_services = index.has_component(component_type="service")
        has_endpoints = bool(index.domains or index.urls)

        # 1. Microphone Surveillance Correlation
        has_mic_perm = index.has_permission("RECORD_AUDIO")
        has_mic_api = index.has_api("android.media.AudioRecord") or index.has_api(
            "android.media.MediaRecorder"
        )

        if has_mic_perm and has_mic_api:
            ev: list[Evidence] = [
                Evidence(
                    description="Declared permission: android.permission.RECORD_AUDIO",
                    location="permission:android.permission.RECORD_AUDIO",
                    snippet="RECORD_AUDIO",
                ),
                Evidence(
                    description="Audio recording API referenced: AudioRecord/MediaRecorder",
                    location="api:android.media",
                    snippet="Audio recording framework API",
                ),
            ]
            if has_services:
                svc_names = [
                    s.get("name", "") if isinstance(s, dict) else getattr(s, "name", "")
                    for s in index.services
                ]
                valid_names = [n for n in svc_names if n]
                name_str = f" ({', '.join(valid_names[:3])})" if valid_names else ""
                ev.append(
                    Evidence(
                        description=f"Background Service components declared in manifest{name_str}",
                        location="manifest:service",
                        snippet="Background service present",
                    )
                )
            if has_endpoints:
                ev.append(
                    Evidence(
                        description="External network communication endpoints present",
                        location="network:endpoints",
                        snippet="Network endpoints present",
                    )
                )

            sev = Severity.HIGH if (has_services and has_endpoints) else Severity.MEDIUM
            conf = Confidence.HIGH if has_services else Confidence.MEDIUM

            findings.append(
                SecurityFinding(
                    id="SEC-SPY-AUDIO-SURVEILLANCE",
                    category="surveillance",
                    title="Audio Surveillance & Recording Capability",
                    description=(
                        "Application combines audio recording permission (RECORD_AUDIO) with"
                        "framework recording APIs,"
                        + (
                            "background services, and external network endpoints."
                            if (has_services and has_endpoints)
                            else "and framework APIs."
                        )
                    ),
                    severity=sev,
                    confidence=conf,
                    evidence=ev,
                    assessment=(
                        "The APK possesses the technical capability for audio capture"
                        + (
                            " from background services with network egress capability."
                            if (has_services and has_endpoints)
                            else "."
                        )
                    ),
                    limitations=[
                        "Static analysis cannot establish that audio recording occurs during"
                        "normal runtime execution."
                    ],
                    references=["CWE-359: Exposure of Private Personal Information"],
                    tags=["surveillance", "audio", "spyware"],
                )
            )

        # 2. Camera Surveillance Correlation
        has_cam_perm = index.has_permission("CAMERA")
        has_cam_api = index.has_api("android.hardware.Camera") or index.has_api(
            "android.hardware.camera2.CameraManager"
        )

        if has_cam_perm and has_cam_api:
            ev = [
                Evidence(
                    description="Declared permission: android.permission.CAMERA",
                    location="permission:android.permission.CAMERA",
                    snippet="CAMERA",
                ),
                Evidence(
                    description="Camera capture framework API referenced",
                    location="api:android.hardware.camera2",
                    snippet="CameraManager API",
                ),
            ]
            if has_services:
                ev.append(
                    Evidence(
                        description="Background service components declared in manifest",
                        location="manifest:service",
                        snippet="Background service present",
                    )
                )

            sev = Severity.HIGH if has_services else Severity.MEDIUM
            conf = Confidence.HIGH if has_services else Confidence.MEDIUM

            findings.append(
                SecurityFinding(
                    id="SEC-SPY-CAMERA-SURVEILLANCE",
                    category="surveillance",
                    title="Camera Capture & Video Capability",
                    description=(
                        "Application combines camera permissions with camera framework APIs."
                    ),
                    severity=sev,
                    confidence=conf,
                    evidence=ev,
                    assessment=(
                        "The APK contains static capabilities to capture photos or stream camera"
                        "video."
                    ),
                    limitations=[
                        "Camera capture in Android typically requires active foreground display"
                        "or explicit user interaction."
                    ],
                    references=["CWE-359: Exposure of Private Personal Information"],
                    tags=["surveillance", "camera", "spyware"],
                )
            )

        # 3. Location Tracking & Exfiltration Correlation
        has_loc_perm = index.has_permission("ACCESS_FINE_LOCATION") or index.has_permission(
            "ACCESS_COARSE_LOCATION"
        )
        has_loc_api = index.has_api("android.location.LocationManager") or index.has_api(
            "com.google.android.gms.location.FusedLocationProviderClient"
        )

        if has_loc_perm and has_loc_api:
            ev = [
                Evidence(
                    description=(
                        "Declared location permission: ACCESS_FINE_LOCATION /ACCESS_COARSE_LOCATION"
                    ),
                    location="permission:location",
                    snippet="Location permission declared",
                ),
                Evidence(
                    description="Location provider framework API referenced: LocationManager",
                    location="api:android.location.LocationManager",
                    snippet="Location API",
                ),
            ]
            if has_services:
                ev.append(
                    Evidence(
                        description="Background service components declared",
                        location="manifest:service",
                        snippet="Background service present",
                    )
                )

            findings.append(
                SecurityFinding(
                    id="SEC-SPY-LOCATION-TRACKING",
                    category="surveillance",
                    title="Physical Location Tracking Capability",
                    description=(
                        "Application declares location permissions and references location"
                        "provider APIs."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    assessment=(
                        "The APK possesses the technical capability to query precise GPS or"
                        "coarse network location coordinates."
                    ),
                    limitations=[
                        "Static analysis cannot establish whether location updates are"
                        "continuously tracked or transmitted."
                    ],
                    references=["CWE-359: Exposure of Private Personal Information"],
                    tags=["surveillance", "location", "tracking"],
                )
            )

        # 4. Multi-Vector Surveillance Suite
        active_vectors = []
        if has_mic_perm and has_mic_api:
            active_vectors.append("Microphone")
        if has_cam_perm and has_cam_api:
            active_vectors.append("Camera")
        if has_loc_perm and has_loc_api:
            active_vectors.append("Location")
        if index.has_permission("READ_CONTACTS"):
            active_vectors.append("Contacts")
        if index.has_permission("READ_SMS") or index.has_permission("RECEIVE_SMS"):
            active_vectors.append("SMS")

        if len(active_vectors) >= 3:
            ev = [
                Evidence(
                    description=f"Surveillance channel available: {v}",
                    location=f"capability:{v.lower()}",
                    snippet=f"Channel: {v}",
                )
                for v in active_vectors
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-SPY-MULTI-SURVEILLANCE",
                    category="surveillance",
                    title=f"Multi-Vector Surveillance Capability ({len(active_vectors)} Channels)",
                    description=(
                        f"The application bundles multiple concurrent surveillance capabilities: "
                        f"{', '.join(active_vectors)}."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        f"The APK combines {len(active_vectors)} distinct sensitive sensory "
                        f"and personal data channels. This multi-capability profile is "
                        f"characteristic of extensive monitoring tools or surveillance frameworks."
                    ),
                    limitations=[
                        "Social media, communication suites, and enterprise management tools"
                        "legitimately require multiple permissions."
                    ],
                    references=["CWE-359: Exposure of Private Personal Information"],
                    tags=["surveillance", "multi_vector", "spyware"],
                )
            )

        return sorted(findings, key=lambda f: f.id)
