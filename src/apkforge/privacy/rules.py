"""Rule definitions, schema, and engine for privacy and tracker detection."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import Confidence, Evidence
from apkforge.privacy.models import EndpointCategory, SDKCategory

_log = logging.getLogger(__name__)

# List of generic strings that must NEVER trigger an SDK detection on their own
GENERIC_STRING_BLOCKLIST = {
    "ad",
    "ads",
    "advert",
    "advertising",
    "analytics",
    "event",
    "events",
    "location",
    "metric",
    "metrics",
    "report",
    "reporting",
    "stat",
    "stats",
    "telemetry",
    "track",
    "tracker",
    "tracking",
    "user",
}


class PrivacyRule(BaseModel):
    """Declarative definition for an SDK, tracker, or network signature."""

    id: str
    name: str
    vendor: str | None = None
    category: SDKCategory
    description: str | None = None
    packages: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    apis: list[str] = Field(default_factory=list)
    min_matches_required: int = 1
    confidence_rules: dict[str, Confidence] = Field(default_factory=dict)
    version_patterns: list[str] = Field(default_factory=list)


class EvidenceIndex:
    """Pre-indexed collections from Phase 1 and Phase 2 inspection for fast rule evaluation."""

    def __init__(
        self,
        classes: set[str] | None = None,
        methods: set[str] | None = None,
        strings: set[str] | None = None,
        domains: set[str] | None = None,
        urls: set[str] | None = None,
        apis: set[str] | None = None,
        permissions: set[str] | None = None,
        package_name: str | None = None,
    ) -> None:
        self.classes: set[str] = classes or set()
        self.methods: set[str] = methods or set()
        self.strings: set[str] = strings or set()
        self.domains: set[str] = domains or set()
        self.urls: set[str] = urls or set()
        self.apis: set[str] = apis or set()
        self.permissions: set[str] = permissions or set()
        self.package_name: str | None = package_name

        # Precompute package prefixes of all classes for O(1) namespace checking
        self.package_prefixes: set[str] = set()
        for c in self.classes:
            parts = c.split(".")
            for i in range(1, len(parts)):
                self.package_prefixes.add(".".join(parts[:i]))


class RuleEngine:
    """Evaluates privacy and tracker rules against an indexed package inspection."""

    def __init__(self, rules: list[PrivacyRule] | None = None) -> None:
        self._rules: list[PrivacyRule] = []
        self._domain_to_rule: dict[str, PrivacyRule] = {}
        if rules:
            for r in rules:
                self.add_rule(r)

    @property
    def rules(self) -> list[PrivacyRule]:
        return list(self._rules)

    def add_rule(self, rule: PrivacyRule) -> None:
        self._rules.append(rule)
        for d in rule.domains:
            norm_d = d.strip().lower()
            self._domain_to_rule[norm_d] = rule

    def load_from_dict(self, data: dict[str, Any]) -> None:
        """Load rules from a parsed dictionary."""
        rules_list = data.get("rules", []) if "rules" in data else [data]
        for r_dict in rules_list:
            if isinstance(r_dict, dict) and "id" in r_dict and "name" in r_dict:
                try:
                    rule = PrivacyRule.model_validate(r_dict)
                    self.add_rule(rule)
                except Exception as exc:
                    _log.warning("Failed to validate privacy rule %s: %s", r_dict.get("id"), exc)

    def load_from_file(self, file_path: Path) -> None:
        """Load rules from a JSON or YAML file."""
        if not file_path.exists():
            return

        text = file_path.read_text(encoding="utf-8")
        if file_path.suffix in (".yaml", ".yml"):
            try:
                import yaml

                parsed = yaml.safe_load(text)
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            self.load_from_dict(item)
                elif isinstance(parsed, dict):
                    self.load_from_dict(parsed)
            except Exception as exc:
                _log.warning("Failed to parse YAML rule file %s: %s", file_path, exc)
        elif file_path.suffix == ".json":
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            self.load_from_dict(item)
                elif isinstance(parsed, dict):
                    self.load_from_dict(parsed)
            except Exception as exc:
                _log.warning("Failed to parse JSON rule file %s: %s", file_path, exc)

    def load_from_directory(self, dir_path: Path) -> None:
        """Load all JSON and YAML rule files from a directory recursively."""
        if not dir_path.is_dir():
            return

        for p in sorted(dir_path.glob("**/*")):
            if p.suffix in (".yaml", ".yml", ".json"):
                self.load_from_file(p)

    def load_builtins(self) -> None:
        """Load all built-in rules packaged with APKForge."""
        builtin_dir = Path(__file__).parent / "rules_data"
        if builtin_dir.is_dir():
            self.load_from_directory(builtin_dir)

        # Also load from repo rules/privacy if available and not redundant
        repo_rules_dir = Path("rules/privacy")
        if repo_rules_dir.is_dir() and repo_rules_dir.resolve() != builtin_dir.resolve():
            self.load_from_directory(repo_rules_dir)

    def match_rule(
        self,
        rule: PrivacyRule,
        index: EvidenceIndex,
    ) -> tuple[bool, Confidence, list[Evidence], dict[str, list[str]]]:
        """Evaluate if a rule matches the index and calculate confidence."""
        matched_packages: list[str] = []
        matched_classes: list[str] = []
        matched_strings: list[str] = []
        matched_endpoints: list[str] = []
        evidence_items: list[Evidence] = []

        # 1. Package prefix matches
        for pkg in rule.packages:
            if pkg in index.package_prefixes or any(c.startswith(pkg + ".") for c in index.classes):
                matched_packages.append(pkg)
                evidence_items.append(
                    Evidence(
                        description=f"Detected package namespace: {pkg}",
                        location=f"package:{pkg}",
                        snippet=f"Detected package namespace: {pkg}",
                    )
                )

        # 2. Class matches
        for cls_name in rule.classes:
            if cls_name.endswith(".*"):
                prefix = cls_name[:-2]
                hits = [c for c in index.classes if c.startswith(prefix + ".")]
                if hits:
                    matched_classes.extend(hits[:5])  # Cap sample to 5
                    evidence_items.append(
                        Evidence(
                            description=f"Matched class namespace {cls_name} ({len(hits)} classes)",
                            location=f"class:{cls_name}",
                            snippet=(
                                f"Matched class namespace {cls_name} "
                                f"({len(hits)} classes: {', '.join(hits[:3])})"
                            ),
                        )
                    )
            elif cls_name in index.classes:
                matched_classes.append(cls_name)
                evidence_items.append(
                    Evidence(
                        description=f"Detected specific class: {cls_name}",
                        location=f"class:{cls_name}",
                        snippet=f"Detected specific class: {cls_name}",
                    )
                )

        # 3. String matches (with false-positive protection)
        for s in rule.strings:
            norm_s = s.strip()
            if not norm_s or norm_s.lower() in GENERIC_STRING_BLOCKLIST:
                continue

            # Check exact match or substring
            hit = False
            if norm_s in index.strings:
                hit = True
            elif len(norm_s) >= 8:
                # Substring scan for unique tokens
                hit = any(norm_s in is_str for is_str in index.strings)

            if hit:
                matched_strings.append(norm_s)
                evidence_items.append(
                    Evidence(
                        description=f"Detected SDK signature string: {norm_s}",
                        location="dex:string",
                        snippet=f"Detected SDK signature string: {norm_s}",
                    )
                )

        # 4. Domain & endpoint matches
        for d in rule.domains:
            norm_d = d.strip().lower()
            if norm_d in index.domains or any(
                id_dom.endswith("." + norm_d) for id_dom in index.domains
            ):
                matched_endpoints.append(norm_d)
                evidence_items.append(
                    Evidence(
                        description=f"Associated domain found: {norm_d}",
                        location=f"domain:{norm_d}",
                        snippet=f"Associated domain found: {norm_d}",
                    )
                )

        # 5. Check match threshold and determine confidence
        # False-positive guard: If only a single string matched and no package/class/domain,
        # require string length >= 12 and not generic
        has_pkg = bool(matched_packages)
        has_cls = bool(matched_classes)
        has_str = bool(matched_strings)
        has_dom = bool(matched_endpoints)

        matches_count = (
            len(matched_packages)
            + len(matched_classes)
            + len(matched_strings)
            + len(matched_endpoints)
        )
        if matches_count < rule.min_matches_required:
            return False, Confidence.LOW, [], {}

        if (
            not has_pkg
            and not has_cls
            and not has_dom
            and has_str
            and all(len(s) < 12 for s in matched_strings)
        ):
            return False, Confidence.LOW, [], {}

        # Calculate confidence
        confidence = Confidence.LOW
        if has_pkg and (has_cls or has_dom or has_str):
            confidence = Confidence.CONFIRMED
        elif has_pkg or has_cls or (has_dom and has_str):
            confidence = Confidence.HIGH
        elif has_dom or has_str:
            confidence = Confidence.MEDIUM

        matches_dict = {
            "packages": matched_packages,
            "classes": matched_classes,
            "strings": matched_strings,
            "endpoints": matched_endpoints,
        }

        return True, confidence, evidence_items, matches_dict

    def classify_domain(self, domain: str) -> tuple[EndpointCategory, str | None, str | None]:
        """Classify a domain against known rule mappings.

        Returns (EndpointCategory, purpose, associated_sdk_name).
        """
        norm_d = domain.strip().lower()

        # Exact match
        if norm_d in self._domain_to_rule:
            rule = self._domain_to_rule[norm_d]
            cat = self._sdk_cat_to_endpoint_cat(rule.category)
            return cat, rule.description or rule.name, rule.name

        # Suffix match (e.g. sub.analytics.google.com -> google.com)
        for d, rule in self._domain_to_rule.items():
            if norm_d.endswith("." + d):
                cat = self._sdk_cat_to_endpoint_cat(rule.category)
                return cat, rule.description or rule.name, rule.name

        return EndpointCategory.UNKNOWN, None, None

    @staticmethod
    def _sdk_cat_to_endpoint_cat(cat: SDKCategory) -> EndpointCategory:
        mapping = {
            SDKCategory.ADVERTISING: EndpointCategory.ADVERTISING,
            SDKCategory.ANALYTICS: EndpointCategory.ANALYTICS,
            SDKCategory.TRACKING: EndpointCategory.TRACKING,
            SDKCategory.TELEMETRY: EndpointCategory.TELEMETRY,
            SDKCategory.ATTRIBUTION: EndpointCategory.ATTRIBUTION,
            SDKCategory.CRASH_REPORTING: EndpointCategory.CRASH_REPORTING,
        }
        return mapping.get(cat, EndpointCategory.UNKNOWN)
