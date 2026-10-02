"""Declarative security rule engine and pre-indexed evidence representation.

Supports complex conditions with ALL, ANY, NONE, and COUNT logical operators
matching permissions, APIs, classes, strings, domains, manifest attributes,
embedded files, native libraries, and diff changes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.security.models import SecurityFinding

_log = logging.getLogger(__name__)


class SecurityEvidenceIndex:
    """Consolidated in-memory evidence index from Phases 1-4 for single-pass rule evaluation."""

    def __init__(
        self,
        *,
        package_name: str | None = None,
        permissions: set[str] | None = None,
        protection_levels: dict[str, str] | None = None,
        apis: set[str] | None = None,
        classes: set[str] | None = None,
        methods: set[str] | None = None,
        strings: set[str] | None = None,
        string_provenance: dict[str, list[str]] | None = None,
        domains: set[str] | None = None,
        urls: set[str] | None = None,
        url_provenance: dict[str, list[str]] | None = None,
        components: dict[str, list[dict[str, Any]]] | None = None,
        manifest_attributes: dict[str, Any] | None = None,
        embedded_files: list[dict[str, Any]] | None = None,
        high_entropy_assets: list[dict[str, Any]] | None = None,
        native_libraries: set[str] | None = None,
        privacy_capabilities: set[str] | None = None,
        detected_sdks: list[str] | None = None,
        diff_changes: set[str] | None = None,
        hashes: dict[str, str] | None = None,
    ) -> None:
        self.package_name = package_name or ""
        self.permissions: set[str] = permissions or set()
        self.protection_levels: dict[str, str] = protection_levels or {}
        self.apis: set[str] = apis or set()
        self.classes: set[str] = classes or set()
        self.methods: set[str] = methods or set()
        self.strings: set[str] = strings or set()
        self.string_provenance: dict[str, list[str]] = string_provenance or {}
        self.domains: set[str] = domains or set()
        self.urls: set[str] = urls or set()
        self.url_provenance: dict[str, list[str]] = url_provenance or {}
        self.components: dict[str, list[dict[str, Any]]] = components or {}
        self.manifest_attributes: dict[str, Any] = manifest_attributes or {}
        self.embedded_files: list[dict[str, Any]] = embedded_files or []
        self.high_entropy_assets: list[dict[str, Any]] = high_entropy_assets or []
        self.native_libraries: set[str] = native_libraries or set()
        self.privacy_capabilities: set[str] = privacy_capabilities or set()
        self.detected_sdks: list[str] = detected_sdks or []
        self.diff_changes: set[str] = diff_changes or set()
        self.hashes: dict[str, str] = hashes or {}

    @property
    def services(self) -> list[Any]:
        return self.components.setdefault("services", [])

    @property
    def receivers(self) -> list[Any]:
        return self.components.setdefault("receivers", [])

    @property
    def providers(self) -> list[Any]:
        return self.components.setdefault("providers", [])

    @property
    def activities(self) -> list[Any]:
        return self.components.setdefault("activities", [])

    def has_permission(self, perm: str) -> bool:
        """Check if permission is declared."""
        norm = perm.strip()
        if norm in self.permissions:
            return True
        return any(p.endswith("." + norm) or norm in p for p in self.permissions)

    def has_api(self, api: str) -> bool:
        """Check if framework API is referenced."""
        norm = api.strip()
        if norm in self.apis:
            return True
        return any(a.startswith(norm) or norm in a for a in self.apis)

    def has_class(self, cls: str) -> bool:
        """Check if class exists."""
        norm = cls.strip()
        if norm.endswith(".*"):
            prefix = norm[:-2]
            return any(c.startswith(prefix + ".") for c in self.classes)
        return norm in self.classes

    def has_string(self, text: str) -> bool:
        """Check if string appears in bytecode or resources."""
        norm = text.strip()
        if norm in self.strings:
            return True
        if len(norm) >= 6:
            return any(norm in s for s in self.strings)
        return False

    def is_string_attributed_to_app(self, text: str) -> bool:
        """Check whether a crypto-related string belongs to the application.

        Suppresses attribution when the string originates exclusively from a
        bundled third-party dependency (e.g. BouncyCastle).
        """
        norm = text.strip()
        prov_classes = self.string_provenance.get(norm) or self.string_provenance.get(text)
        if prov_classes:
            if self.package_name:
                if any(c.startswith(self.package_name) for c in prov_classes):
                    return True
                if any(
                    c.startswith(("org.bouncycastle.", "org.spongycastle."))
                    for c in prov_classes
                ):
                    return False
                return False
            return not all(
                c.startswith(("org.bouncycastle.", "org.spongycastle."))
                for c in prov_classes
            )

        has_bundled_provider = any(
            c.startswith(("org.bouncycastle.", "org.spongycastle."))
            for c in self.classes
        )
        return not (
            has_bundled_provider
            and bool(self.package_name)
            and not self.package_name.startswith(("org.bouncycastle", "org.spongycastle"))
        )

    def has_component_with_names(
        self,
        component_type: str | None = None,
        exported_only: bool = False,
        permission_required: str | None = None,
    ) -> tuple[bool, list[str]]:
        """Check if component matching criteria exists, returning match status and names."""
        if component_type:
            ct = component_type.lower().strip()
            types_to_check = [ct, f"{ct}s", ct.rstrip("s")]
            if ct == "activity":
                types_to_check.append("activities")
        else:
            types_to_check = list(self.components.keys())

        matched_names: list[str] = []
        for ctype in types_to_check:
            comps = self.components.get(ctype, [])
            for c in comps:
                c_exp = (
                    c.get("exported", False)
                    if isinstance(c, dict)
                    else getattr(c, "exported", False)
                )
                if exported_only and not c_exp:
                    continue
                c_perm = (
                    c.get("permission") if isinstance(c, dict) else getattr(c, "permission", None)
                )
                if permission_required and c_perm != permission_required:
                    continue
                name = c.get("name", "") if isinstance(c, dict) else getattr(c, "name", "")
                if name:
                    matched_names.append(name)
        return bool(matched_names), matched_names

    def has_component(
        self,
        component_type: str | None = None,
        exported_only: bool = False,
        permission_required: str | None = None,
    ) -> bool:
        """Check if component matching criteria exists."""
        has_c, _ = self.has_component_with_names(
            component_type=component_type,
            exported_only=exported_only,
            permission_required=permission_required,
        )
        return has_c

    def has_boot_receiver(self) -> bool:
        """Check if a broadcast receiver listens for BOOT_COMPLETED or similar."""
        receivers = self.components.get("receivers", [])
        for r in receivers:
            actions: list[str] = []
            if isinstance(r, dict):
                actions = r.get("actions", [])
            else:
                for f in getattr(r, "intent_filters", []) or []:
                    actions.extend(getattr(f, "actions", []) or [])
            for a in actions:
                if "BOOT_COMPLETED" in a or "QUICKBOOT_POWERON" in a:
                    return True
        return False


class SecurityCondition(BaseModel):
    """Declarative atomic or composite condition for security rules."""

    # Atomic condition fields
    permission: str | None = None
    permission_any: list[str] | None = None
    permission_all: list[str] | None = None

    api: str | None = None
    api_any: list[str] | None = None
    api_all: list[str] | None = None

    class_name: str | None = None
    class_any: list[str] | None = None

    string: str | None = None
    string_any: list[str] | None = None

    domain: str | None = None
    domain_any: list[str] | None = None

    component_type: str | None = None
    component_exported: bool | None = None
    boot_receiver: bool | None = None

    manifest_attribute: str | None = None  # Format: "attr_name=value"
    embedded_file_type: str | None = None  # "dex", "elf", "apk", "script"
    high_entropy_asset: bool | None = None
    privacy_capability: str | None = None
    diff_change: str | None = None

    # Composite logical operators
    all: list[SecurityCondition] | None = None
    any: list[SecurityCondition] | None = None
    none: list[SecurityCondition] | None = None
    min_count: int | None = None

    def evaluate(self, index: SecurityEvidenceIndex) -> tuple[bool, list[Evidence]]:
        """Evaluate this condition against the evidence index."""
        engine = SecurityRuleEngine()
        return engine._evaluate_condition(self, index)


class SecurityRule(BaseModel):
    """Declarative security rule definition."""

    id: str
    title: str
    category: str
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    conditions: SecurityCondition
    assessment: str = ""
    limitations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("references", mode="before")
    @classmethod
    def _normalize_references(cls, v: object) -> list[str]:
        if not v:
            return []
        if isinstance(v, str):
            return [v]
        normalized: list[str] = []
        if isinstance(v, (list, tuple, set)):
            for item in v:
                if isinstance(item, dict):
                    for k, val in item.items():
                        normalized.append(f"{k}: {val}")
                else:
                    normalized.append(str(item))
        return normalized

    @field_validator("limitations", mode="before")
    @classmethod
    def _normalize_limitations(cls, v: object) -> list[str]:
        if not v:
            return []
        if isinstance(v, str):
            return [v]
        normalized: list[str] = []
        if isinstance(v, (list, tuple, set)):
            for item in v:
                if isinstance(item, dict):
                    for k, val in item.items():
                        normalized.append(f"{k}: {val}")
                else:
                    normalized.append(str(item))
        return normalized


class SecurityRuleEngine:
    """Evaluates declarative security rules against the SecurityEvidenceIndex."""

    def __init__(self) -> None:
        self._rules: list[SecurityRule] = []

    @property
    def rules(self) -> list[SecurityRule]:
        return list(self._rules)

    def load_rules(self) -> list[SecurityRule]:
        """Load builtins and return rules list."""
        self.load_builtins()
        return self.rules

    def add_rule(self, rule: SecurityRule) -> None:
        """Add a rule, replacing if an identical ID exists."""
        self._rules = [r for r in self._rules if r.id != rule.id]
        self._rules.append(rule)

    def load_from_dict(self, data: dict[str, Any]) -> None:
        """Load rules from parsed dictionary / list."""
        rules_list = data.get("rules", []) if isinstance(data, dict) else data
        if isinstance(rules_list, list):
            for r in rules_list:
                try:
                    self.add_rule(SecurityRule.model_validate(r))
                except Exception as e:
                    _log.warning("Failed to parse security rule %s: %s", r.get("id"), e)

    def load_from_file(self, path: Path) -> None:
        """Load rules from a YAML or JSON file."""
        if not path.is_file():
            return
        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if data:
                self.load_from_dict(data)
        except Exception as e:
            _log.warning("Failed to load security rules file %s: %s", path, e)

    def load_from_directory(self, dir_path: Path) -> int:
        """Load all .yaml and .json rule files in directory recursively."""
        loaded = 0
        if not dir_path.is_dir():
            return 0
        for p in sorted(dir_path.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json"):
                count_before = len(self._rules)
                self.load_from_file(p)
                loaded += len(self._rules) - count_before
        return loaded

    def load_builtins(self) -> int:
        """Load built-in security rules from package rules_data directory."""
        package_rules_dir = Path(__file__).parent / "rules_data"
        if package_rules_dir.is_dir():
            return self.load_from_directory(package_rules_dir)
        return 0

    def evaluate(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Evaluate all loaded rules against index, producing findings for matches."""
        findings: list[SecurityFinding] = []

        for rule in self._rules:
            is_crypto = (
                rule.id in ("SEC-VULN-WEAK-CIPHER-001", "SEC-VULN-WEAK-HASH-001")
                or rule.category == "crypto"
                or "crypto" in rule.tags
            )
            matched, evidence = self._evaluate_condition(
                rule.conditions, index, is_crypto=is_crypto
            )
            if matched:
                limits = list(rule.limitations)
                if not limits:
                    limits = [
                        "Static analysis cannot establish actual runtime execution or data "
                        "exfiltration."
                    ]
                findings.append(
                    SecurityFinding(
                        id=rule.id,
                        category=rule.category,
                        title=rule.title,
                        description=rule.description or rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        evidence=evidence,
                        assessment=rule.assessment or rule.description,
                        limitations=limits,
                        references=list(rule.references),
                        tags=list(rule.tags),
                    )
                )

        return sorted(findings, key=lambda f: f.id)

    def _evaluate_condition(
        self,
        cond: SecurityCondition,
        index: SecurityEvidenceIndex,
        is_crypto: bool = False,
    ) -> tuple[bool, list[Evidence]]:
        """Recursively evaluate condition against index."""
        evidence: list[Evidence] = []

        # 1. Composite: ALL
        if cond.all is not None:
            for sub in cond.all:
                matched, sub_ev = self._evaluate_condition(
                    sub, index, is_crypto=is_crypto
                )
                if not matched:
                    return False, []
                evidence.extend(sub_ev)
            return True, evidence

        # 2. Composite: ANY
        if cond.any is not None:
            matched_any = False
            for sub in cond.any:
                matched, sub_ev = self._evaluate_condition(
                    sub, index, is_crypto=is_crypto
                )
                if matched:
                    matched_any = True
                    evidence.extend(sub_ev)
            return matched_any, evidence

        # 3. Composite: NONE
        if cond.none is not None:
            for sub in cond.none:
                matched, _ = self._evaluate_condition(
                    sub, index, is_crypto=is_crypto
                )
                if matched:
                    return False, []
            return True, []

        # 4. Atomic: Permission
        if cond.permission:
            if not index.has_permission(cond.permission):
                return False, []
            evidence.append(
                Evidence(
                    description=f"Declared permission: {cond.permission}",
                    location=f"permission:{cond.permission}",
                    snippet=cond.permission,
                )
            )

        if cond.permission_any:
            hits = [p for p in cond.permission_any if index.has_permission(p)]
            if not hits:
                return False, []
            for h in hits:
                evidence.append(
                    Evidence(
                        description=f"Declared permission: {h}",
                        location=f"permission:{h}",
                        snippet=h,
                    )
                )

        if cond.permission_all:
            missing = [p for p in cond.permission_all if not index.has_permission(p)]
            if missing:
                return False, []
            for p in cond.permission_all:
                evidence.append(
                    Evidence(
                        description=f"Declared permission: {p}",
                        location=f"permission:{p}",
                        snippet=p,
                    )
                )

        # 5. Atomic: API
        if cond.api:
            if not index.has_api(cond.api):
                return False, []
            evidence.append(
                Evidence(
                    description=f"Referenced API: {cond.api}",
                    location=f"api:{cond.api}",
                    snippet=cond.api,
                )
            )

        if cond.api_any:
            hits = [a for a in cond.api_any if index.has_api(a)]
            if not hits:
                return False, []
            for h in hits:
                evidence.append(
                    Evidence(
                        description=f"Referenced API: {h}",
                        location=f"api:{h}",
                        snippet=h,
                    )
                )

        if cond.api_all:
            missing = [a for a in cond.api_all if not index.has_api(a)]
            if missing:
                return False, []
            for a in cond.api_all:
                evidence.append(
                    Evidence(
                        description=f"Referenced API: {a}",
                        location=f"api:{a}",
                        snippet=a,
                    )
                )

        # 6. Atomic: Class
        if cond.class_name:
            if not index.has_class(cond.class_name):
                return False, []
            evidence.append(
                Evidence(
                    description=f"DEX class reference: {cond.class_name}",
                    location=f"class:{cond.class_name}",
                    snippet=cond.class_name,
                )
            )

        if cond.class_any:
            hits = [c for c in cond.class_any if index.has_class(c)]
            if not hits:
                return False, []
            for h in hits:
                evidence.append(
                    Evidence(
                        description=f"DEX class reference: {h}",
                        location=f"class:{h}",
                        snippet=h,
                    )
                )

        # 7. Atomic: String
        if cond.string:
            if not index.has_string(cond.string):
                return False, []
            if is_crypto and not index.is_string_attributed_to_app(cond.string):
                return False, []
            prov = index.string_provenance.get(cond.string, [])
            app_prov = [c for c in prov if index.package_name and c.startswith(index.package_name)]
            owner = app_prov[0] if app_prov else (prov[0] if prov else None)
            loc = f"class:{owner}" if owner else "dex:strings"
            desc = (
                f"Discovered string pattern in {owner}: {cond.string}"
                if owner
                else f"Discovered string pattern: {cond.string}"
            )
            evidence.append(
                Evidence(
                    description=desc,
                    location=loc,
                    snippet=cond.string,
                )
            )

        if cond.string_any:
            if is_crypto:
                hits = [
                    s
                    for s in cond.string_any
                    if index.has_string(s) and index.is_string_attributed_to_app(s)
                ]
            else:
                hits = [s for s in cond.string_any if index.has_string(s)]
            if not hits:
                return False, []
            for h in hits:
                prov = index.string_provenance.get(h, [])
                app_prov = [
                    c for c in prov if index.package_name and c.startswith(index.package_name)
                ]
                owner = app_prov[0] if app_prov else (prov[0] if prov else None)
                loc = f"class:{owner}" if owner else "dex:strings"
                desc = (
                    f"Discovered string pattern in {owner}: {h}"
                    if owner
                    else f"Discovered string pattern: {h}"
                )
                evidence.append(
                    Evidence(
                        description=desc,
                        location=loc,
                        snippet=h,
                    )
                )

        # 8. Atomic: Component
        if cond.component_type or cond.component_exported is not None:
            has_comp, comp_names = index.has_component_with_names(
                component_type=cond.component_type,
                exported_only=bool(cond.component_exported),
            )
            if not has_comp:
                return False, []
            names_str = f" ({', '.join(comp_names[:3])})" if comp_names else ""
            desc = f"Observed component: type={cond.component_type or 'any'}{names_str}"
            if cond.component_exported:
                desc += " (exported)"
            evidence.append(
                Evidence(
                    description=desc,
                    location=f"manifest:{cond.component_type or 'component'}",
                    snippet=desc,
                )
            )

        # 9. Atomic: Boot receiver
        if cond.boot_receiver is not None:
            has_boot = index.has_boot_receiver()
            if has_boot != cond.boot_receiver:
                return False, []
            if has_boot:
                evidence.append(
                    Evidence(
                        description=(
                            "Observed broadcast receiver listening for device boot completion"
                        ),
                        location="manifest:receiver:BOOT_COMPLETED",
                        snippet="BOOT_COMPLETED receiver",
                    )
                )

        # 10. Atomic: Manifest attribute
        if cond.manifest_attribute:
            attr_name, _, expected_val = cond.manifest_attribute.partition("=")
            actual_val = str(index.manifest_attributes.get(attr_name.strip(), "")).lower()
            if actual_val != expected_val.strip().lower():
                return False, []
            evidence.append(
                Evidence(
                    description=f"Manifest attribute {attr_name}={actual_val}",
                    location=f"manifest:{attr_name}",
                    snippet=f"{attr_name}={actual_val}",
                )
            )

        # 11. Atomic: Embedded file type
        if cond.embedded_file_type:
            req_type = cond.embedded_file_type.lower()
            matching_files = [
                f for f in index.embedded_files if f.get("type", "").lower() == req_type
            ]
            if not matching_files:
                return False, []
            for f in matching_files[:3]:
                evidence.append(
                    Evidence(
                        description=f"Embedded {req_type} payload file found: {f.get('path')}",
                        location=f"embedded:{f.get('path')}",
                        snippet=f"{req_type} payload ({f.get('size', 0)} bytes)",
                    )
                )

        # 12. Atomic: High-entropy asset
        if cond.high_entropy_asset is not None:
            has_entropy = bool(index.high_entropy_assets)
            if has_entropy != cond.high_entropy_asset:
                return False, []
            if has_entropy:
                sample = index.high_entropy_assets[0]
                evidence.append(
                    Evidence(
                        description=(
                            f"High-entropy asset observed (likely encrypted/encoded): "
                            f"{sample.get('path')} (entropy={sample.get('entropy', 0):.2f})"
                        ),
                        location=f"asset:{sample.get('path')}",
                        snippet=f"Entropy: {sample.get('entropy', 0):.2f}",
                    )
                )

        # 13. Atomic: Privacy capability
        if cond.privacy_capability:
            if cond.privacy_capability.lower() not in index.privacy_capabilities:
                return False, []
            evidence.append(
                Evidence(
                    description=f"Correlated privacy capability: {cond.privacy_capability}",
                    location=f"privacy:{cond.privacy_capability}",
                    snippet=cond.privacy_capability,
                )
            )

        # 14. Atomic: Diff change
        if cond.diff_change:
            req_change = cond.diff_change.lower()
            hit = any(req_change in dc.lower() for dc in index.diff_changes)
            if not hit:
                return False, []
            matching_changes = [dc for dc in index.diff_changes if req_change in dc.lower()]
            for mc in matching_changes[:3]:
                evidence.append(
                    Evidence(
                        description=f"Diff change detected: {mc}",
                        location="diff",
                        snippet=mc,
                    )
                )

        return True, evidence
