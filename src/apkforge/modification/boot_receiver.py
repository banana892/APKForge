"""C.5 modifier: remove RECEIVE_BOOT_COMPLETED and disable the app's boot receiver.

Deliberately narrow (not the Phase D framework). It works on an Apktool-decoded
``AndroidManifest.xml`` inside a BuildService workspace and has four separate steps:

1. **inspect** (:func:`discover`): find the permission and every ``<receiver>`` whose
   intent filters handle a boot action. Nothing is assumed about names.
2. **plan** (:func:`plan_disable_boot_receiver`): decide whether the change is possible
   and declare, before touching anything, the exact source edits and the semantic
   changes DiffEngine is expected to observe after the rebuild.
3. **apply** (:func:`apply_plan`): make exactly those edits as minimal text edits.
4. **verify** (inside :func:`apply_plan`): re-parse both manifests, compute the
   structural difference and require it to equal the planned edits; otherwise the
   original manifest is restored and the step fails.

Refusals are structured (``PlanStatus``), never exceptions: a missing permission, no
boot receiver, more than one boot receiver (unless one is named explicitly), or a
state the modifier cannot reason about (e.g. ``android:enabled="@bool/x"``).
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from xml.sax.saxutils import escape

from pydantic import BaseModel, Field

from apkforge.diff.expectations import ExpectedChange

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "BOOT_ACTIONS",
    "BOOT_PERMISSION",
    "ApplyResult",
    "BootReceiverCandidate",
    "BootReceiverPlan",
    "BootTargetDiscovery",
    "PlanStatus",
    "Precondition",
    "SourceEdit",
    "apply_plan",
    "discover",
    "manifest_edits",
    "plan_disable_boot_receiver",
]

BOOT_PERMISSION = "android.permission.RECEIVE_BOOT_COMPLETED"
#: Broadcasts delivered at boot. A receiver filtering any of these is a boot receiver.
BOOT_ACTIONS = (
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
    "com.htc.intent.action.QUICKBOOT_POWERON",
)
MODIFIER_ID = "c5.disable_boot_receiver"

_A = "{http://schemas.android.com/apk/res/android}"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fqcn(name: str, package: str) -> str:
    """Resolve a manifest class name (``.Foo``, ``Foo`` or fully qualified)."""
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class BootReceiverCandidate(BaseModel):
    name: str  # fully qualified
    raw_name: str  # as written in the manifest
    enabled_raw: str | None
    exported_raw: str | None
    boot_actions: list[str]
    other_actions: list[str]


class BootTargetDiscovery(BaseModel):
    package: str
    permission_declarations: list[str]  # tags declaring BOOT_PERMISSION
    receivers: list[str]
    boot_receivers: list[BootReceiverCandidate]
    manifest_sha256: str


class PlanStatus(StrEnum):
    READY = "ready"
    TARGET_MISSING = "target_missing"
    AMBIGUOUS_TARGET = "ambiguous_target"
    UNSUPPORTED = "unsupported"


class Precondition(BaseModel):
    name: str
    satisfied: bool
    detail: str = ""


class SourceEdit(BaseModel):
    """One structural edit of the decoded manifest."""

    kind: str  # remove_element | add_element | set_attribute
    element: str  # stable element key, e.g. manifest/receiver[name=a.B]
    attribute: str | None = None
    before: str | None = None
    after: str | None = None


class BootReceiverPlan(BaseModel):
    modifier: str = MODIFIER_ID
    operation: str = (
        "Remove the RECEIVE_BOOT_COMPLETED uses-permission and disable the receiver that "
        "handles the boot broadcast (android:enabled=false)."
    )
    target_apk: str
    target_sha256: str
    package: str
    permission: str = BOOT_PERMISSION
    receiver: str | None = None
    status: PlanStatus
    preconditions: list[Precondition] = Field(default_factory=list)
    source_edits: list[SourceEdit] = Field(default_factory=list)
    expected_changes: list[ExpectedChange] = Field(default_factory=list)
    consequences: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    decoded_manifest_sha256: str

    @property
    def ready(self) -> bool:
        return self.status == PlanStatus.READY


class ApplyResult(BaseModel):
    applied: bool
    observed_edits: list[SourceEdit] = Field(default_factory=list)
    matches_plan: bool = False
    manifest_sha256_before: str | None = None
    manifest_sha256_after: str | None = None
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Inspect
# ---------------------------------------------------------------------------


def discover(manifest_xml: str) -> BootTargetDiscovery:
    """Find the boot permission and boot receivers in a decoded manifest."""
    root = ET.fromstring(manifest_xml)  # noqa: S314 - Apktool output from our workspace
    package = root.get("package", "")
    decls = [
        el.tag
        for el in root
        if el.tag in ("uses-permission", "uses-permission-sdk-23")
        and el.get(f"{_A}name") == BOOT_PERMISSION
    ]
    receivers: list[str] = []
    boot: list[BootReceiverCandidate] = []
    app = root.find("application")
    for rec in app.findall("receiver") if app is not None else []:
        raw = rec.get(f"{_A}name", "")
        receivers.append(_fqcn(raw, package))
        actions = [
            a.get(f"{_A}name", "")
            for f in rec.findall("intent-filter")
            for a in f.findall("action")
        ]
        boot_actions = [a for a in actions if a in BOOT_ACTIONS]
        if boot_actions:
            boot.append(
                BootReceiverCandidate(
                    name=_fqcn(raw, package),
                    raw_name=raw,
                    enabled_raw=rec.get(f"{_A}enabled"),
                    exported_raw=rec.get(f"{_A}exported"),
                    boot_actions=boot_actions,
                    other_actions=[a for a in actions if a not in BOOT_ACTIONS],
                )
            )
    return BootTargetDiscovery(
        package=package,
        permission_declarations=decls,
        receivers=receivers,
        boot_receivers=boot,
        manifest_sha256=_sha256_text(manifest_xml),
    )


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

_ENABLED_VALUES = {None: None, "true": True, "false": False}

_LIMITATIONS = [
    "Manifest-level change only: no DEX/smali code is changed. Code that handles "
    "BOOT_COMPLETED is still present in the APK.",
    "The receiver is disabled for every action it handles, not only for the boot action.",
    "Code can re-enable components at runtime (PackageManager.setComponentEnabledSetting); "
    "static analysis cannot rule that out.",
    "Other components or mechanisms (alarms, WorkManager, other receivers) that start work "
    "at or after boot are not addressed.",
    "Does not establish runtime behaviour: the modified APK is not installed or run.",
]


def _refuse(plan: BootReceiverPlan, status: PlanStatus, problem: str) -> None:
    """Record a problem; the first refusal determines the plan status."""
    if plan.status == PlanStatus.READY:
        plan.status = status
    plan.problems.append(problem)


def plan_disable_boot_receiver(
    discovery: BootTargetDiscovery,
    *,
    target_apk: str,
    target_sha256: str,
    receiver: str | None = None,
) -> BootReceiverPlan:
    """Create the modification plan, or a structured refusal.

    Args:
        discovery: :func:`discover` output for the decoded manifest.
        target_apk / target_sha256: identity of the original APK.
        receiver: explicitly chosen boot receiver (fully qualified). Required when the
            manifest has more than one boot receiver; must be one of them.
    """
    plan = BootReceiverPlan(
        target_apk=target_apk,
        target_sha256=target_sha256,
        package=discovery.package,
        status=PlanStatus.READY,
        decoded_manifest_sha256=discovery.manifest_sha256,
        limitations=list(_LIMITATIONS),
    )
    pre = plan.preconditions

    decls = discovery.permission_declarations
    pre.append(
        Precondition(
            name="permission_declared_once",
            satisfied=decls == ["uses-permission"],
            detail=f"{BOOT_PERMISSION} declarations: {decls or 'none'}",
        )
    )
    if not decls:
        _refuse(plan, PlanStatus.TARGET_MISSING, f"{BOOT_PERMISSION} is not requested by this APK.")
    elif decls != ["uses-permission"]:
        _refuse(
            plan,
            PlanStatus.UNSUPPORTED,
            f"{BOOT_PERMISSION} is declared as {decls}; only a single <uses-permission> "
            "is supported.",
        )

    boot = discovery.boot_receivers
    names = [c.name for c in boot]
    pre.append(
        Precondition(
            name="boot_receiver_identified",
            satisfied=len(boot) == 1 or (receiver is not None and receiver in names),
            detail=f"boot receivers: {names or 'none'}; receivers in manifest: "
            f"{len(discovery.receivers)}; requested: {receiver or '(derive)'}",
        )
    )
    target: BootReceiverCandidate | None = None
    if not boot:
        _refuse(
            plan,
            PlanStatus.TARGET_MISSING,
            f"No <receiver> handles a boot action ({', '.join(BOOT_ACTIONS)}).",
        )
    elif receiver is not None:
        target = next((c for c in boot if c.name == receiver), None)
        if target is None:
            _refuse(
                plan,
                PlanStatus.TARGET_MISSING,
                f"Requested receiver {receiver} does not handle a boot action.",
            )
    elif len(boot) > 1:
        _refuse(
            plan,
            PlanStatus.AMBIGUOUS_TARGET,
            f"{len(boot)} receivers handle boot actions ({', '.join(names)}); name one "
            "explicitly instead of guessing.",
        )
    else:
        target = boot[0]

    if target is not None:
        plan.receiver = target.name
        state = target.enabled_raw
        pre.append(
            Precondition(
                name="receiver_currently_enabled",
                satisfied=state in ("true", None),
                detail=f"android:enabled={state!r}",
            )
        )
        if state not in _ENABLED_VALUES:
            _refuse(
                plan,
                PlanStatus.UNSUPPORTED,
                f"android:enabled={state!r} cannot be evaluated statically.",
            )
        elif state == "false":
            _refuse(
                plan, PlanStatus.UNSUPPORTED, f"{target.name} is already disabled; nothing to do."
            )
        if target.other_actions:
            plan.consequences.append(
                f"{target.name} also handles {', '.join(target.other_actions)}; disabling "
                "the component stops those broadcasts too."
            )

    if not plan.ready or target is None:
        return plan

    plan.source_edits = [
        SourceEdit(
            kind="remove_element", element=f"manifest/uses-permission[name={BOOT_PERMISSION}]"
        ),
        SourceEdit(
            kind="set_attribute",
            element=f"manifest/application[0]/receiver[name={target.raw_name}]",
            attribute="android:enabled",
            before=target.enabled_raw,
            after="false",
        ),
    ]
    plan.expected_changes = [
        ExpectedChange(
            category="uses_permission",
            kind="removed",
            identifier=BOOT_PERMISSION,
            description=f"{BOOT_PERMISSION} removed",
        ),
        ExpectedChange(
            category="component",
            kind="modified",
            identifier=target.name,
            detail={
                "component_type": "receiver",
                "enabled": [_ENABLED_VALUES[target.enabled_raw], False],
            },
            description=f"{target.name} disabled (enabled -> false), nothing else changed",
        ),
    ]
    return plan


# ---------------------------------------------------------------------------
# Apply + verify
# ---------------------------------------------------------------------------


def _element_index(manifest_xml: str) -> dict[str, dict[str, str]]:
    """Map a stable key per element to its attributes (android: prefix restored)."""
    root = ET.fromstring(manifest_xml)  # noqa: S314 - Apktool output from our workspace
    index: dict[str, dict[str, str]] = {}

    def attrs(el: ET.Element) -> dict[str, str]:
        out = {k.replace(_A, "android:"): v for k, v in el.attrib.items()}
        if (el.text or "").strip():
            out["#text"] = (el.text or "").strip()
        return out

    def walk(el: ET.Element, prefix: str) -> None:
        unnamed: dict[str, int] = {}
        for child in el:
            name = child.get(f"{_A}name")
            if name is not None:
                key = f"{prefix}/{child.tag}[name={name}]"
            else:
                n = unnamed.get(child.tag, 0)
                unnamed[child.tag] = n + 1
                key = f"{prefix}/{child.tag}[{n}]"
            while key in index:  # duplicate names: disambiguate deterministically
                key += "+"
            index[key] = attrs(child)
            walk(child, key)

    index[root.tag] = attrs(root)
    walk(root, root.tag)
    return index


def manifest_edits(before_xml: str, after_xml: str) -> list[SourceEdit]:
    """Structural difference between two decoded manifests."""
    a, b = _element_index(before_xml), _element_index(after_xml)
    edits: list[SourceEdit] = []
    for key in sorted(a.keys() - b.keys()):
        edits.append(SourceEdit(kind="remove_element", element=key))
    for key in sorted(b.keys() - a.keys()):
        edits.append(SourceEdit(kind="add_element", element=key))
    for key in sorted(a.keys() & b.keys()):
        for attr in sorted(a[key].keys() | b[key].keys()):
            if a[key].get(attr) != b[key].get(attr):
                edits.append(
                    SourceEdit(
                        kind="set_attribute",
                        element=key,
                        attribute=attr,
                        before=a[key].get(attr),
                        after=b[key].get(attr),
                    )
                )
    return edits


def _edit_text(text: str, plan: BootReceiverPlan) -> str:
    """Apply the plan as minimal text edits; raises ValueError if a target is not unique."""
    perm = re.compile(
        r"^[ \t]*<uses-permission\b[^>]*?\sandroid:name=\""
        + re.escape(escape(BOOT_PERMISSION, {'"': "&quot;"}))
        + r"\"[^>]*?/>[ \t]*\r?\n?",
        re.M,
    )
    text, n = perm.subn("", text)
    if n != 1:
        raise ValueError(f"expected exactly one <uses-permission> for {BOOT_PERMISSION}, found {n}")

    edit = next(e for e in plan.source_edits if e.kind == "set_attribute")
    raw = edit.element.split("[name=", 1)[1][:-1]
    start = re.compile(
        r"<receiver\b[^>]*?\sandroid:name=\""
        + re.escape(escape(raw, {'"': "&quot;"}))
        + r"\"[^>]*>"
    )
    matches = list(start.finditer(text))
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one <receiver> start tag for {raw}, found {len(matches)}"
        )
    m = matches[0]
    tag = m.group(0)
    if re.search(r"\sandroid:enabled=\"[^\"]*\"", tag):
        new_tag = re.sub(r"(\sandroid:enabled=)\"[^\"]*\"", r'\1"false"', tag, count=1)
    else:
        new_tag = tag.replace("<receiver", '<receiver android:enabled="false"', 1)
    return text[: m.start()] + new_tag + text[m.end() :]


def apply_plan(plan: BootReceiverPlan, manifest_path: Path) -> ApplyResult:
    """Apply *plan* to the decoded manifest at *manifest_path* and verify the result.

    The manifest is only left modified when the observed structural edits equal the
    planned edits exactly; otherwise it is restored byte-for-byte.
    """
    if not plan.ready:
        return ApplyResult(
            applied=False, errors=[f"Plan is not ready ({plan.status}); nothing applied."]
        )
    original = manifest_path.read_text(encoding="utf-8")
    result = ApplyResult(applied=False, manifest_sha256_before=_sha256_text(original))
    if result.manifest_sha256_before != plan.decoded_manifest_sha256:
        result.errors.append("Decoded manifest changed since it was inspected; plan is stale.")
        return result
    try:
        modified = _edit_text(original, plan)
        observed = manifest_edits(original, modified)
    except (ValueError, ET.ParseError) as exc:
        result.errors.append(f"Cannot apply plan: {exc}")
        return result

    result.observed_edits = observed
    result.matches_plan = _same_edits(observed, plan.source_edits)
    if not result.matches_plan:
        result.errors.append("Observed manifest edits differ from the planned edits; reverted.")
        return result
    manifest_path.write_text(modified, encoding="utf-8")
    written = manifest_path.read_text(encoding="utf-8")
    result.manifest_sha256_after = _sha256_text(written)
    if written != modified:
        manifest_path.write_text(original, encoding="utf-8")
        result.errors.append("Manifest on disk does not match the edited text; reverted.")
        return result
    result.applied = True
    return result


def _same_edits(a: list[SourceEdit], b: list[SourceEdit]) -> bool:
    def key(e: SourceEdit) -> tuple[Any, ...]:
        return (e.kind, e.element, e.attribute, e.before, e.after)

    return sorted(map(key, a), key=repr) == sorted(map(key, b), key=repr)
