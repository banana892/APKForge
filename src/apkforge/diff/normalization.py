"""Content-aware rebuild-noise normalisation (Phase E2).

Phase C.5 established *path rules* (:data:`apkforge.diff.expectations.NOISE_RULES`):
"``res/`` file modified at the same path" is rebuild noise, "``classesN.dex``
modified" is rebuild noise, and so on. A path rule says nothing about *content*: any
change to a matching path passes, including a deliberate one.

Phase E keeps the path rules as the way a no-op rebuild's differences are *explained*,
but accepts noise in a later comparison only by **exact content identity** with what
the no-op rebuild of the same APK produced, with the same toolchain:

1. A no-op rebuild of the APK is classified with the path rules (``verify_expectations``
   with no expected changes). Every accepted difference is recorded in a
   :class:`NoiseFingerprint` together with the content on both sides (SHA-256 of the
   entry before and after, the certificate fingerprints, or the exact detail).
2. When a modification is verified, an observation is rebuild noise only if the
   fingerprint holds the same difference with the same content. A path match with
   different content is *not* noise.

Evidence for this design (``artifacts/phase-e/``): two no-op rebuilds of the same APK
with the same toolchain and signing key produce byte-identical entry content for every
entry, including the v1 signature files; only ZIP timestamps differ.

Content policies:

- ``exact``: before and after content must equal the fingerprint (files, residue,
  strings, manifest attributes)
- ``signer``: certificate; the original certificate must equal the fingerprint's and the
  new one must equal the certificate APKForge signed with (``expected_signer``)
- ``path_only``: v1 signature files (``META-INF/MANIFEST.MF``, ``*.SF``, ``*.RSA``...).
  Their content is a function of every other entry and of the signing key, so it
  necessarily differs whenever anything else differs. They are accepted by exact path
  and change kind only; their correctness is established separately by ``apksigner
  verify`` and the certificate check, never by this rule.

Fingerprints are only valid for the toolchain that produced them
(:class:`ToolchainIdentity`); see :meth:`ToolchainIdentity.differences`.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from apkforge.diff.expectations import ExpectationVerdict, Observation

__all__ = [
    "NORMALIZATION_SCHEMA_VERSION",
    "RULE_POLICIES",
    "SEMANTIC_SCHEMA_VERSION",
    "AcceptedDifference",
    "ContentPolicy",
    "NoiseFingerprint",
    "ToolchainIdentity",
    "archive_entries_for",
]

#: Version of the normalisation rules / fingerprint format. A baseline with another
#: version is not reused.
NORMALIZATION_SCHEMA_VERSION = 1
#: Version of the semantic comparison (observation extraction). Bumped when observe()
#: starts reporting a new kind of difference, since an older fingerprint cannot hold it.
#: 2: manifest_element observations (full manifest tree); 3: resolved references in
#: manifest_element details (rule manifest_reference_inlined).
SEMANTIC_SCHEMA_VERSION = 3

#: Tool versions that identify a toolchain for noise purposes (corpus.TOOLCHAIN_KEYS).
TOOLCHAIN_FIELDS = ("java", "apktool", "zipalign", "apksigner", "build_tools", "android_platform")


class ContentPolicy(StrEnum):
    EXACT = "exact"
    SIGNER = "signer"
    PATH_ONLY = "path_only"


#: noise rule id -> content policy when the rule is recorded in a fingerprint
RULE_POLICIES: dict[str, ContentPolicy] = {
    "signature_replaced": ContentPolicy.PATH_ONLY,
    "certificate_replaced": ContentPolicy.SIGNER,
    "dex_reencoded": ContentPolicy.EXACT,
    "dex_compiler_marker_removed": ContentPolicy.EXACT,
    "manifest_reencoded": ContentPolicy.EXACT,
    "resource_table_reencoded": ContentPolicy.EXACT,
    "resource_reencoded": ContentPolicy.EXACT,
    "resource_path_canonicalized": ContentPolicy.EXACT,
    "manifest_resource_path_canonicalized": ContentPolicy.EXACT,
    "manifest_reference_inlined": ContentPolicy.EXACT,
    "baseline_residue": ContentPolicy.EXACT,
}


class ToolchainIdentity(BaseModel):
    """What must match for a noise fingerprint to be reused."""

    java: str | None = None
    apktool: str | None = None
    zipalign: str | None = None
    apksigner: str | None = None
    build_tools: str | None = None
    android_platform: str | None = None
    normalization_schema: int = NORMALIZATION_SCHEMA_VERSION
    semantic_schema: int = SEMANTIC_SCHEMA_VERSION

    @classmethod
    def from_versions(cls, versions: dict[str, Any]) -> ToolchainIdentity:
        return cls.model_validate({k: versions.get(k) for k in TOOLCHAIN_FIELDS})

    @property
    def known(self) -> bool:
        """True when the tools that shape rebuild output are identified."""
        return all(getattr(self, k) for k in ("apktool", "build_tools", "java"))

    def differences(self, other: ToolchainIdentity) -> list[str]:
        """Human-readable mismatches; empty means compatible.

        Every field must match exactly. No cross-version compatibility rule has been
        validated, so none is assumed.
        """
        out: list[str] = []
        for k in (*TOOLCHAIN_FIELDS, "normalization_schema", "semantic_schema"):
            mine, theirs = getattr(self, k), getattr(other, k)
            if mine != theirs:
                out.append(f"{k}: baseline {mine} vs current {theirs}")
        return out


class AcceptedDifference(BaseModel):
    """One difference a no-op rebuild of this APK produces, with its content."""

    category: str
    kind: str
    identifier: str
    rule: str
    policy: ContentPolicy
    content_before: str | None = None
    content_after: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.category, self.kind, self.identifier)


class NoiseFingerprint(BaseModel):
    """The accepted rebuild differences of one APK (from its no-op baseline entry)."""

    accepted: list[AcceptedDifference] = Field(default_factory=list)

    @classmethod
    def from_verdict(cls, verdict: ExpectationVerdict) -> NoiseFingerprint:
        """Record every REBUILD_NOISE observation of a no-op verdict, with content."""
        from apkforge.diff.expectations import ObservationClass

        accepted = []
        for c in verdict.observations:
            if c.classification != ObservationClass.REBUILD_NOISE or c.rule is None:
                continue
            accepted.append(_accepted(c.observation, c.rule))
        return cls(accepted=sorted(accepted, key=lambda a: a.key()))

    def add_residue(self, observations: list[Observation]) -> None:
        for o in observations:
            self.accepted.append(_accepted(o, "baseline_residue"))
        self.accepted.sort(key=lambda a: a.key())

    def lookup(self, obs: Observation) -> AcceptedDifference | None:
        key = (obs.category, obs.kind, obs.identifier)
        return next((a for a in self.accepted if a.key() == key), None)

    def rule_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.accepted:
            out[a.rule] = out.get(a.rule, 0) + 1
        return dict(sorted(out.items()))


def _accepted(obs: Observation, rule: str) -> AcceptedDifference:
    policy = RULE_POLICIES.get(rule, ContentPolicy.EXACT)
    return AcceptedDifference(
        category=obs.category,
        kind=obs.kind,
        identifier=obs.identifier,
        rule=rule,
        policy=policy,
        content_before=obs.content_before,
        content_after=obs.content_after,
        detail=dict(obs.detail),
    )


def accepts(
    entry: AcceptedDifference, obs: Observation, expected_signer: str | None
) -> tuple[bool, str]:
    """Does *obs* reproduce *entry*? Returns (accepted, reason)."""
    if entry.policy == ContentPolicy.PATH_ONLY:
        return True, "signature file regenerated by signing (path and change kind match)"
    if entry.policy == ContentPolicy.SIGNER:
        if obs.content_before != entry.content_before:
            return False, ("original certificate differs from the baseline's original certificate")
        signer = _norm_fp(expected_signer) if expected_signer else entry.content_after
        if obs.content_after != signer:
            return False, (
                f"new certificate {obs.content_after} is not the signing certificate {signer}"
            )
        return True, "re-signed with the expected signing certificate"
    if entry.category in ("file", "native_library") and (
        entry.content_before is None and entry.content_after is None
    ):
        return False, "baseline entry records no content hash to compare"
    # For other categories (DEX strings, manifest attributes...) the identifier and the
    # detail *are* the content; they are compared exactly below.
    if obs.detail != entry.detail:
        return False, "detail differs from the no-op baseline"
    if (obs.content_before, obs.content_after) != (entry.content_before, entry.content_after):
        return False, "content differs from the no-op rebuild of this APK"
    return True, "identical to the no-op rebuild of this APK (content match)"


def _norm_fp(fp: str) -> str:
    return re.sub(r"[^0-9a-f]", "", fp.lower())


# ---------------------------------------------------------------------------
# Decoded project paths -> archive entries
# ---------------------------------------------------------------------------

_SMALI = re.compile(r"^smali(?:_classes(\d+))?/")
_RES_VALUES = re.compile(r"^res/values[^/]*/")


def archive_entries_for(project_paths: list[str]) -> tuple[set[str], list[str]]:
    """Archive entries that a change to these decoded-project paths can alter.

    Returns (entries, unmapped). ``unmapped`` lists project paths whose effect on the
    archive is not known (e.g. ``apktool.yml``); a caller must not treat archive
    changes as planned when any path is unmapped.
    """
    entries: set[str] = set()
    unmapped: list[str] = []
    for p in project_paths:
        if p == "AndroidManifest.xml":
            entries.add("AndroidManifest.xml")
        elif m := _SMALI.match(p):
            entries.add(f"classes{m.group(1)}.dex" if m.group(1) else "classes.dex")
        elif _RES_VALUES.match(p):
            entries.add("resources.arsc")
        elif p.startswith("res/"):
            entries.update({"resources.arsc", p})
        elif p.startswith(("assets/", "lib/")):
            entries.add(p)
        elif p.startswith("unknown/"):
            entries.add(p[len("unknown/") :])
        else:
            unmapped.append(p)
    return entries, unmapped
