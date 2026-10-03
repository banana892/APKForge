"""Phase H.1 reference-analysis service (read-only).

``ReferenceAnalysisService.analyze(apk)`` decodes the APK with the existing
:class:`~apkforge.builders.BuildService` (Apktool; the APK is copied into a fresh
workspace first, the original is never handed to a tool), indexes the decoded project
and deletes the workspace. The input's SHA-256 is compared before and after.

``ReferenceAnalysisService.analyze_decoded(project)`` indexes an already-decoded Apktool
project without touching any APK.

H.1 never builds, signs, patches or installs anything.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.reference.manifest import MANIFEST_PATH, analyze_manifest
from apkforge.reference.models import (
    AnalysisIssue,
    AnalysisState,
    ApkIdentity,
    Component,
    ComponentAnalysis,
    DefinedClass,
    Evidence,
    NativeResolution,
    ReferenceAnalysisResult,
    ReferenceKind,
    ResolutionStatus,
    StringUse,
    combine_states,
)
from apkforge.reference.resources import analyze_tree
from apkforge.reference.smali import (
    SmaliFileResult,
    dex_name_for_smali_root,
    normalize_class_name,
    parse_smali,
)

if TYPE_CHECKING:
    from apkforge.builders import BuildService

__all__ = ["MAX_ISSUES_PER_COMPONENT", "STATIC_LIMITATIONS", "ReferenceAnalysisService"]

MAX_ISSUES_PER_COMPONENT = 50

STATIC_LIMITATIONS = [
    "Static analysis of decoded smali, manifest and resources only; no code is executed.",
    "Unresolved reflection, dynamic code loading, native code, generated code, encrypted or "
    "obfuscated configuration and server-driven behaviour can reference classes without "
    "any static evidence.",
    "Reflection/loadLibrary targets are traced only to constants in the same basic block.",
    "Native libraries are not disassembled: JNI FindClass/GetMethodID/RegisterNatives "
    "references are not observed.",
    "Resource and asset matches cover classes defined in this APK and declared provider "
    "authorities; textual matches are evidence, not proof of use.",
    "Absence of observed references is never proof of absence unless every relevant "
    "component is COMPLETE, and even then only within this static scope.",
]

_CODE_KINDS = {
    ReferenceKind.CLASS_REFERENCE,
    ReferenceKind.METHOD_REFERENCE,
    ReferenceKind.FIELD_REFERENCE,
    ReferenceKind.TYPE_REFERENCE,
    ReferenceKind.STRING_REFERENCE,
    ReferenceKind.CONSTRUCTOR_REFERENCE,
    ReferenceKind.CONST_CLASS_REFERENCE,
}
_NATIVE_KINDS = {ReferenceKind.NATIVE_METHOD, ReferenceKind.NATIVE_LIBRARY_LOAD}
_DEX_ENTRY = re.compile(r"classes(\d*)\.dex")
_CLASS_SHAPE = re.compile(
    r"(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*|L?(?:[A-Za-z_$][\w$]*/)+[A-Za-z_$][\w$]*;?"
)
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _dex_order(name: str) -> tuple[int, str]:
    m = _DEX_ENTRY.fullmatch(name)
    return (int(m.group(1) or 1), name) if m else (10**6, name)


def _component(
    name: str | Component,
    state: AnalysisState,
    issues: list[AnalysisIssue] | None = None,
    *,
    total: int = 0,
    analyzed: int = 0,
    notes: list[str] | None = None,
    subcomponents: list[ComponentAnalysis] | None = None,
) -> ComponentAnalysis:
    issues = issues or []
    return ComponentAnalysis(
        component=str(name),
        state=state,
        inputs_total=total,
        inputs_analyzed=analyzed,
        issue_count=len(issues),
        issues=issues[:MAX_ISSUES_PER_COMPONENT],
        notes=notes or [],
        subcomponents=subcomponents or [],
    )


def _classify_string(ev: Evidence, defined: set[str]) -> None:
    """Assign a string's interpretation; stronger uses need supporting evidence."""
    if ev.string_use is not None:  # already set by reflection flow
        return
    value = (ev.string_value or "").strip()
    if _CLASS_SHAPE.fullmatch(value):
        cls = normalize_class_name(value)
        if cls in defined:
            ev.string_use = StringUse.POSSIBLE_CLASS_NAME
            ev.target_class = cls
            ev.confidence_basis += "; names a class defined in this APK"
            return
        ev.string_use = StringUse.UNKNOWN_STRING_USE
    elif _IDENTIFIER.fullmatch(value):
        ev.string_use = StringUse.UNKNOWN_STRING_USE
    else:
        ev.string_use = StringUse.STRING_LITERAL


class ReferenceAnalysisService:
    """Read-only reference/evidence analysis of an APK (Phase H.1)."""

    def __init__(
        self, build_service: BuildService | None = None, *, work_dir: Path | None = None
    ) -> None:
        self._build_service = build_service
        self.work_dir = work_dir

    # -- APK entry point -------------------------------------------------------

    def analyze(
        self,
        apk: Path | str,
        *,
        keep_workspace: bool = False,
        include_resources: bool = True,
    ) -> ReferenceAnalysisResult:
        """Decode *apk* into a throwaway workspace and index it. Never modifies *apk*."""
        apk_path = Path(apk).expanduser().resolve()
        before = _sha256(apk_path)
        identity = ApkIdentity(file_name=apk_path.name, sha256=before, size=apk_path.stat().st_size)
        try:
            with zipfile.ZipFile(apk_path) as z:
                entries = z.namelist()
        except (zipfile.BadZipFile, OSError) as exc:
            result = self._failed(identity, f"not a readable APK/ZIP: {exc}")
            result.original_unchanged = _sha256(apk_path) == before
            return result

        svc = self._service()
        ws, prep = svc.prepare_workspace(work_dir=self.work_dir)
        try:
            if ws is None:
                result = self._failed(identity, f"workspace: {prep.failure_cause}")
            else:
                stage = svc.decode(apk_path, ws)
                if not stage.passed:
                    cause = stage.failure_cause or "Apktool decode failed"
                    result = self._failed(identity, f"decode failed: {cause}")
                else:
                    result = self.analyze_decoded(
                        ws.decoded_dir,
                        identity=identity,
                        apk_entries=entries,
                        include_resources=include_resources,
                    )
        finally:
            if ws is not None and not keep_workspace:
                shutil.rmtree(ws.root, ignore_errors=True)
        result.original_unchanged = _sha256(apk_path) == before
        if not result.original_unchanged:
            result.errors.append("input APK changed during analysis (SHA-256 mismatch)")
        return result

    def _service(self) -> BuildService:
        if self._build_service is None:
            from apkforge.builders import BuildService, ToolchainConfig
            from apkforge.core.config import load_default_config

            work = self.work_dir or load_default_config().workspace.base_directory / "references"
            self.work_dir = work
            self._build_service = BuildService(ToolchainConfig.discover(), work_dir=work)
        return self._build_service

    @staticmethod
    def _failed(identity: ApkIdentity, error: str) -> ReferenceAnalysisResult:
        comps = [
            _component(
                c,
                AnalysisState.UNKNOWN,
                [AnalysisIssue(code="NOT_DECODED", location=".", message=error)],
            )
            for c in Component
        ]
        return ReferenceAnalysisResult(
            apk=identity,
            analysis_state=AnalysisState.UNKNOWN,
            components=comps,
            limitations=list(STATIC_LIMITATIONS),
            errors=[error],
        )

    # -- decoded project -------------------------------------------------------

    @staticmethod
    def analyze_decoded(
        project: Path | str,
        *,
        identity: ApkIdentity | None = None,
        apk_entries: list[str] | None = None,
        include_resources: bool = True,
    ) -> ReferenceAnalysisResult:
        """Index an Apktool-decoded project. *apk_entries* (the APK's ZIP entry names), when
        given, lets missing decoded DEX / resources be detected as incomplete input."""
        root = Path(project)
        identity = identity or ApkIdentity()
        limitations = list(STATIC_LIMITATIONS)

        # 1. smali ---------------------------------------------------------------
        files: list[SmaliFileResult] = []
        smali_roots = sorted(
            (p for p in root.iterdir() if p.is_dir() and dex_name_for_smali_root(p.name)),
            key=lambda p: _dex_order(dex_name_for_smali_root(p.name) or ""),
        )
        dex_components: list[ComponentAnalysis] = []
        decoded_dex: set[str] = set()
        for sroot in smali_roots:
            dex = dex_name_for_smali_root(sroot.name)
            assert dex is not None
            decoded_dex.add(dex)
            dex_files: list[SmaliFileResult] = []
            issues: list[AnalysisIssue] = []
            for path in sorted(sroot.rglob("*.smali")):
                rel = path.relative_to(root).as_posix()
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    fr = SmaliFileResult(path=rel, dex=dex)
                    fr.issues.append(
                        AnalysisIssue(code="UNREADABLE_FILE", location=rel, message=str(exc))
                    )
                else:
                    fr = parse_smali(text, rel, dex)
                dex_files.append(fr)
                issues.extend(fr.issues)
            files.extend(dex_files)
            analyzed = sum(1 for f in dex_files if f.analyzed)
            if not dex_files or analyzed == 0:
                state = AnalysisState.UNKNOWN
                if not dex_files:
                    issues.append(
                        AnalysisIssue(
                            code="EMPTY_DECODED_DEX",
                            location=sroot.name,
                            message="decoded smali directory contains no .smali files",
                        )
                    )
            else:
                state = combine_states(f.state for f in dex_files)
            dex_components.append(
                _component(f"dex:{dex}", state, issues, total=len(dex_files), analyzed=analyzed)
            )
        expected_dex = (
            sorted((e for e in apk_entries if _DEX_ENTRY.fullmatch(e)), key=_dex_order)
            if apk_entries is not None
            else []
        )
        for dex in expected_dex:
            if dex not in decoded_dex:
                dex_components.append(
                    _component(
                        f"dex:{dex}",
                        AnalysisState.UNKNOWN,
                        [
                            AnalysisIssue(
                                code="MISSING_DECODED_DEX",
                                location=dex,
                                message=f"{dex} is in the APK but no decoded smali exists",
                            )
                        ],
                    )
                )
        dex_components.sort(key=lambda c: _dex_order(c.component.removeprefix("dex:")))
        if dex_components:
            dex_state = combine_states(c.state for c in dex_components)
            dex_notes: list[str] = []
        elif apk_entries is not None:
            dex_state = AnalysisState.COMPLETE
            dex_notes = ["the APK contains no classes*.dex"]
        else:
            dex_state = AnalysisState.UNKNOWN
            dex_notes = ["no decoded smali directories and no APK entry list to check"]
        dex_comp = _component(
            Component.DEX,
            dex_state,
            total=sum(c.inputs_total for c in dex_components),
            analyzed=sum(c.inputs_analyzed for c in dex_components),
            notes=dex_notes,
            subcomponents=dex_components,
        )
        dex_comp.issue_count = sum(c.issue_count for c in dex_components)

        defined: dict[str, DefinedClass] = {}
        duplicates: list[str] = []
        for f in files:
            if f.class_name is None:
                continue
            if f.class_name in defined:
                duplicates.append(f.class_name)
                defined[f.class_name].duplicate_sources.append(f.path)
                continue
            defined[f.class_name] = DefinedClass(
                name=f.class_name,
                source_file=f.path,
                source_dex=f.dex,
                superclass=f.superclass,
                access_flags=f.access_flags,
                interfaces=f.interfaces,
                annotations=f.annotations,
                methods=f.methods,
                analysis_state=f.state,
            )
        if duplicates:
            dex_comp.notes.append(
                f"{len(duplicates)} class(es) defined more than once; first definition kept"
            )
        defined_names = set(defined)

        code: list[Evidence] = []
        reflection: list[Evidence] = []
        native: list[Evidence] = []
        for f in files:
            for ev in f.evidence:
                if ev.kind is ReferenceKind.STRING_REFERENCE:
                    _classify_string(ev, defined_names)
                if ev.kind in _CODE_KINDS:
                    code.append(ev)
                elif ev.kind in _NATIVE_KINDS:
                    native.append(ev)
                else:
                    reflection.append(ev)

        # 2. reflection / native components ----------------------------------------
        unresolved = [
            e for e in reflection if e.resolution is not ResolutionStatus.TARGET_IDENTIFIED
        ]
        refl_issues = [
            AnalysisIssue(
                code=f"REFLECTION_{e.resolution.value if e.resolution else 'UNKNOWN'}",
                location=f"{e.source_file}:{e.source_line}",
                message=f"{e.reflection_api}: {e.confidence_basis}",
            )
            for e in sorted(unresolved, key=Evidence.sort_key)
        ]
        refl_own = AnalysisState.PARTIAL if unresolved else AnalysisState.COMPLETE
        refl_comp = _component(
            Component.REFLECTION,
            combine_states([dex_state, refl_own]),
            refl_issues,
            total=len(reflection),
            analyzed=len(reflection) - len(unresolved),
            notes=[f"{len(reflection)} reflection indicator(s), {len(unresolved)} unresolved"],
        )

        bundled = sorted(
            p.relative_to(root).as_posix()
            for p in root.rglob("*.so")
            if p.is_file() and not p.is_symlink()
        )
        loads = [e for e in native if e.kind is ReferenceKind.NATIVE_LIBRARY_LOAD]
        natives = [e for e in native if e.kind is ReferenceKind.NATIVE_METHOD]
        for ev in loads:
            if ev.library_name:
                hits = [
                    b
                    for b in bundled
                    if b.rsplit("/", 1)[-1] in (f"lib{ev.library_name}.so", ev.library_name)
                ]
                ev.confidence_basis += (
                    "; bundled as " + ", ".join(hits) if hits else "; no matching bundled .so"
                )
        unresolved_loads = [e for e in loads if e.native_resolution is NativeResolution.UNKNOWN]
        nat_ind_comp = _component(
            Component.NATIVE_INDICATORS,
            combine_states(
                [dex_state, AnalysisState.PARTIAL if unresolved_loads else AnalysisState.COMPLETE]
            ),
            [
                AnalysisIssue(
                    code="NATIVE_LIBRARY_UNKNOWN",
                    location=f"{e.source_file}:{e.source_line}",
                    message=f"{e.reflection_api}: library not statically identifiable",
                )
                for e in sorted(unresolved_loads, key=Evidence.sort_key)
            ],
            total=len(loads),
            analyzed=len(loads) - len(unresolved_loads),
            notes=[
                f"{len(natives)} native method(s), {len(loads)} library load(s), "
                f"{len(bundled)} bundled .so file(s)"
            ],
        )
        if bundled or natives or loads:
            native_code = _component(
                Component.NATIVE_CODE,
                AnalysisState.NOT_ANALYZED,
                notes=[
                    "native code is present but native binaries are not analysed; JNI "
                    "callbacks into Java are not observed"
                ],
                total=len(bundled),
            )
        else:
            native_code = _component(
                Component.NATIVE_CODE,
                combine_states([dex_state]),
                notes=["no native methods, library loads or bundled .so files observed"],
            )

        # 3. manifest -------------------------------------------------------------
        mpath = root / MANIFEST_PATH
        mtext: str | None
        try:
            mtext = mpath.read_text(encoding="utf-8") if mpath.is_file() else None
        except (OSError, UnicodeDecodeError):
            mtext = None
        man = analyze_manifest(mtext, defined_names)
        man_comp = _component(
            Component.MANIFEST,
            man.state,
            man.issues,
            total=1,
            analyzed=1 if man.state is not AnalysisState.UNKNOWN else 0,
        )
        identity.package_name = identity.package_name or man.package
        identity.version_name = identity.version_name or man.version_name
        identity.version_code = identity.version_code or man.version_code

        # 4. resources / assets ---------------------------------------------------
        res_evidence: list[Evidence] = []
        if include_resources:
            res = analyze_tree(
                root,
                ("res",),
                str(Component.RESOURCES),
                package=man.package,
                classes=defined_names,
                authorities=man.authorities,
            )
            assets = analyze_tree(
                root,
                ("assets", "unknown"),
                str(Component.ASSETS),
                package=man.package,
                classes=defined_names,
                authorities=man.authorities,
            )
            if (
                apk_entries is not None
                and "resources.arsc" in apk_entries
                and not (root / "res").is_dir()
            ):
                res.issues.append(
                    AnalysisIssue(
                        code="MISSING_DECODED_RESOURCES",
                        location="res",
                        message="the APK has resources.arsc but no decoded res/ exists",
                    )
                )
                res.state = AnalysisState.PARTIAL
            comps_res = [
                _component(
                    r.component,
                    r.state,
                    r.issues,
                    total=r.files_total,
                    analyzed=r.files_analyzed,
                    notes=r.notes,
                )
                for r in (res, assets)
            ]
            res_evidence = [*res.evidence, *assets.evidence]
        else:
            comps_res = [
                _component(c, AnalysisState.NOT_ANALYZED, notes=["not requested"])
                for c in (Component.RESOURCES, Component.ASSETS)
            ]
            limitations.append("Resource and asset analysis was not requested (NOT_ANALYZED).")

        components = [dex_comp, refl_comp, nat_ind_comp, native_code, man_comp, *comps_res]
        # model_construct: the evidence is built by this module (no re-validation of
        # potentially millions of records)
        return ReferenceAnalysisResult.model_construct(
            apk=identity,
            analysis_state=combine_states(c.state for c in components),
            components=components,
            defined_classes=sorted(defined.values(), key=lambda c: c.name),
            references=sorted(code, key=Evidence.sort_key),
            reflection=sorted(reflection, key=Evidence.sort_key),
            native=sorted(native, key=Evidence.sort_key),
            bundled_native_libraries=bundled,
            manifest=sorted(man.evidence, key=Evidence.sort_key),
            resources=sorted(res_evidence, key=Evidence.sort_key),
            limitations=limitations,
        )
