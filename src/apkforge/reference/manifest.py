"""Manifest references (Phase H.1).

Consumes the existing manifest machinery: the decoded ``AndroidManifest.xml`` is
flattened with :func:`apkforge.diff.manifest_tree.parse_manifest_xml` (the same
element keys the Phase E manifest tree diff uses), so no new manifest parser exists.

Structural references: component ``android:name`` (activity, service, receiver, provider,
instrumentation), ``activity-alias`` ``android:targetActivity``, application-level
class-valued attributes and ``parentActivityName``, plus provider authorities. Any other
attribute whose value equals a class defined in the APK is recorded as a *textual*
``EXACT_VALUE`` match (e.g. a ``<meta-data android:value>`` naming a class).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from apkforge.diff.manifest_tree import parse_manifest_xml
from apkforge.reference.models import (
    AnalysisIssue,
    AnalysisState,
    Evidence,
    MatchBasis,
    ReferenceKind,
)

__all__ = ["ManifestAnalysis", "analyze_manifest", "resolve_component_name"]

MANIFEST_PATH = "AndroidManifest.xml"

#: tag -> class-valued attributes (structural references)
_CLASS_ATTRS: dict[str, tuple[str, ...]] = {
    "application": (
        "android:name",
        "android:backupAgent",
        "android:appComponentFactory",
        "android:manageSpaceActivity",
    ),
    "activity": ("android:name", "android:parentActivityName"),
    "activity-alias": ("android:targetActivity", "android:parentActivityName"),
    "service": ("android:name",),
    "receiver": ("android:name",),
    "provider": ("android:name",),
    "instrumentation": ("android:name",),
}


def resolve_component_name(package: str | None, name: str) -> str:
    """Android rules: ``.X`` and dot-less ``X`` are relative to the manifest package."""
    if package and name.startswith("."):
        return package + name
    if package and "." not in name:
        return f"{package}.{name}"
    return name


@dataclass
class ManifestAnalysis:
    state: AnalysisState
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    issues: list[AnalysisIssue] = field(default_factory=list)
    authorities: dict[str, str] = field(default_factory=dict)  # authority -> provider class


def analyze_manifest(text: str | None, defined_classes: set[str]) -> ManifestAnalysis:
    """Index class/authority references of a decoded (text) manifest."""
    if text is None:
        return ManifestAnalysis(
            state=AnalysisState.UNKNOWN,
            issues=[
                AnalysisIssue(
                    code="MISSING_INPUT",
                    location=MANIFEST_PATH,
                    message="decoded AndroidManifest.xml not found",
                )
            ],
        )
    try:
        tree = parse_manifest_xml(text)
    except Exception as exc:  # ParseError and anything the XML layer raises
        return ManifestAnalysis(
            state=AnalysisState.UNKNOWN,
            issues=[
                AnalysisIssue(
                    code="XML_PARSE_ERROR",
                    location=MANIFEST_PATH,
                    message=f"manifest could not be parsed: {exc}",
                )
            ],
        )
    root = tree.elements.get("manifest", {}).get("attributes", {})
    out = ManifestAnalysis(
        state=AnalysisState.COMPLETE,
        package=root.get("package"),
        version_name=root.get("android:versionName"),
        version_code=root.get("android:versionCode"),
    )

    def add(key: str, tag: str, attr: str, value: str, target: str, **kw: object) -> None:
        out.evidence.append(
            Evidence(
                kind=ReferenceKind.MANIFEST_REFERENCE,
                source_file=MANIFEST_PATH,
                instruction=tag,
                context=attr,
                xml_location=key,
                matched_value=value,
                target=target,
                **kw,  # type: ignore[arg-type]
            ).finalize_id()
        )

    for key in sorted(tree.elements):
        el = tree.elements[key]
        tag: str = el["tag"]
        attrs: dict[str, str] = el["attributes"]
        class_attrs = _CLASS_ATTRS.get(tag, ())
        if tag == "provider" and attrs.get("android:authorities"):
            provider = attrs.get("android:name")
            provider_cls = resolve_component_name(out.package, provider) if provider else None
            for authority in attrs["android:authorities"].split(";"):
                authority = authority.strip()
                if not authority:
                    continue
                if provider_cls:
                    out.authorities.setdefault(authority, provider_cls)
                add(
                    key,
                    tag,
                    "android:authorities",
                    authority,
                    authority,
                    target_class=provider_cls,
                    match_basis=MatchBasis.PROVIDER_AUTHORITY,
                    confidence_basis="provider authority declared in the manifest",
                )
        for attr in sorted(attrs):
            value = attrs[attr]
            if attr in class_attrs:
                if value.startswith("@"):
                    out.issues.append(
                        AnalysisIssue(
                            code="UNRESOLVED_RESOURCE_VALUE",
                            location=f"{MANIFEST_PATH}#{key}@{attr}",
                            message=f"class-valued attribute is a resource reference: {value}",
                        )
                    )
                    continue
                cls = resolve_component_name(out.package, value)
                add(
                    key,
                    tag,
                    attr,
                    value,
                    cls,
                    target_class=cls,
                    match_basis=MatchBasis.CLASS_ATTRIBUTE,
                    confidence_basis=f"<{tag} {attr}> names a class",
                )
            elif attr not in ("android:authorities", "package"):
                cls = resolve_component_name(out.package, value) if value.startswith(".") else value
                if cls in defined_classes:
                    add(
                        key,
                        tag,
                        attr,
                        value,
                        cls,
                        target_class=cls,
                        match_basis=MatchBasis.EXACT_VALUE,
                        confidence_basis=(
                            f"<{tag} {attr}> value equals a class defined in this APK; "
                            "textual match, not a structural class reference"
                        ),
                    )
    if out.issues:
        out.state = AnalysisState.PARTIAL
        for ev in out.evidence:
            ev.analysis_state = AnalysisState.PARTIAL
    return out
