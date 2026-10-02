"""Failure classification for BuildService stages.

Patterns are deliberately narrow and anchored on messages observed in Phase
C.1/C.1b. Anything unmatched falls back to the stage's generic category with
``classified=False`` rather than being guessed into a specific one.

Note: Apktool always prints ``I: Loading resource table from file: .../framework/1.apk``,
so the bare word "framework" must never be used as a signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apkforge.builders.models import BuildFailureCategory as C
from apkforge.builders.models import BuildStage

if TYPE_CHECKING:
    from apkforge.builders.runner import CommandResult

__all__ = ["FailureDiagnosis", "classify_stage_failure"]


@dataclass(frozen=True)
class FailureDiagnosis:
    category: C
    cause: str
    evidence: str | None = None
    classified: bool = True


_FRAMEWORK = [
    # C.1b config A: android:* attributes missing from an outdated framework
    (
        re.compile(r"\battribute android:\S+ not found"),
        "Android framework lacks an android:* attribute used by the app.",
    ),
    (
        re.compile(r"style attribute '?android:attr/\S+'? not found"),
        "Android framework lacks an android:* style attribute.",
    ),
    (
        re.compile(r"\bresource android:\S+ not found"),
        "Android framework lacks an android:* resource.",
    ),
    (
        re.compile(r"Can(?:'|no)t find framework resources", re.I),
        "Apktool could not find framework resources.",
    ),
    (
        re.compile(r"Could not (?:find|load|decode) framework", re.I),
        "Apktool could not load the framework.",
    ),
    (
        re.compile(r"Framework (?:file|apk) .*(?:not found|does not exist)", re.I),
        "Framework file missing.",
    ),
]

_TOOLCHAIN = [
    (re.compile(r"UnsupportedClassVersionError"), "Java runtime too old for the configured tool."),
    (re.compile(r"could not exec", re.I), "A helper binary (e.g. aapt2) could not be executed."),
    (
        re.compile(r"aapt2?\b.*(?:No such file|cannot execute|Permission denied)", re.I),
        "aapt2 could not be executed.",
    ),
]

_UNSUPPORTED = [
    (
        re.compile(
            r"Unsupported (?:dex|odex|apk|file|resource table|chunk) (?:version|format|type)", re.I
        ),
        "Input uses an unsupported format.",
    ),
]

_RESOURCE_BUILD = [
    # C.1 failures, e.g.:
    #   error: attribute state_swiped (aka eu.siacs.conversations:state_swiped) not found.
    (
        re.compile(r"error: (?:style )?attribute '?\S+'? .*not found"),
        "AAPT2 link failure: attribute referenced but not declared.",
    ),
    (
        re.compile(r"error: resource \S+ .*not found"),
        "AAPT2 link failure: resource referenced but not declared.",
    ),
    (re.compile(r"failed linking (?:references|file resources)"), "AAPT2 resource linking failed."),
    (re.compile(r"failed processing manifest"), "AAPT2 failed to process the manifest."),
    (re.compile(r"\berror: .*\.(?:xml|png|9\.png):"), "AAPT2 failed to compile a resource file."),
]

_RESOURCE_DECODE = [
    (
        re.compile(
            r"(?:ARSCDecoder|ResourcesDecoder|AXmlResourceParser|ResTable|ResXmlPullParser)\S*.*(?:Exception|Error)"
        ),
        "Resource table / binary XML decoding failed.",
    ),
    (re.compile(r"Could not decode arsc", re.I), "resources.arsc could not be decoded."),
    (
        re.compile(r"Invalid resource config", re.I),
        "Invalid resource configuration in resources.arsc.",
    ),
]

_STAGE_DEFAULT = {
    BuildStage.PREPARE: C.CONFIGURATION_FAILURE,
    BuildStage.DECODE: C.DECODE_FAILURE,
    BuildStage.BUILD: C.BUILD_FAILURE,
    BuildStage.ALIGN: C.ALIGNMENT_FAILURE,
    BuildStage.SIGN: C.SIGNING_FAILURE,
    BuildStage.VERIFY: C.VERIFICATION_FAILURE,
}

# JVM warnings that tools emit on every run; never useful as evidence.
_NOISE = re.compile(
    r"^WARNING: (?:A restricted method|java\.lang\.System::"
    r"|Use --enable-native-access|Restricted methods)"
)


def _scan(lines: list[str], table: list[tuple[re.Pattern[str], str]]) -> tuple[str, str] | None:
    for line in lines:
        for pattern, cause in table:
            if pattern.search(line):
                return cause, line.strip()
    return None


def _last_meaningful(lines: list[str]) -> str | None:
    for line in reversed(lines):
        s = line.strip()
        if s and not _NOISE.match(s) and not s.startswith("[CommandRunner]"):
            return s[:500]
    return None


def classify_stage_failure(
    stage: BuildStage, result: CommandResult | None, detail: str = ""
) -> FailureDiagnosis:
    """Map a failed stage's tool output (plus optional detail) to a category."""
    if result is not None and result.timed_out:
        return FailureDiagnosis(
            C.TIMEOUT,
            f"{stage} stage exceeded its timeout after {result.duration_seconds:.0f}s; "
            "process group killed.",
            _last_meaningful((result.stdout + "\n" + result.stderr).splitlines()),
        )
    if result is not None and result.exec_error:
        return FailureDiagnosis(
            C.TOOLCHAIN_FAILURE,
            f"Could not execute {result.argv[0]}: {result.exec_error}",
            result.exec_error,
        )

    text = detail + "\n" + (result.stderr + "\n" + result.stdout if result else "")
    lines = text.splitlines()
    exit_code = result.returncode if result else None

    tables: list[tuple[C, list[tuple[re.Pattern[str], str]]]] = [(C.TOOLCHAIN_FAILURE, _TOOLCHAIN)]
    if stage in (BuildStage.DECODE, BuildStage.BUILD, BuildStage.PREPARE):
        tables += [(C.FRAMEWORK_FAILURE, _FRAMEWORK), (C.UNSUPPORTED, _UNSUPPORTED)]
    if stage == BuildStage.BUILD:
        tables.append((C.RESOURCE_FAILURE, _RESOURCE_BUILD))
    if stage == BuildStage.DECODE:
        tables.append((C.RESOURCE_FAILURE, _RESOURCE_DECODE))

    for category, table in tables:
        hit = _scan(lines, table)
        if hit:
            return FailureDiagnosis(category, hit[0], hit[1])

    generic = _STAGE_DEFAULT.get(stage, C.BUILD_FAILURE)
    cause = (
        detail.strip()
        or f"{stage} stage failed (exit {exit_code}); no known error signature matched."
    )
    # Prefer the tool's stderr; stdout is mostly Apktool "I:" progress chatter.
    evidence = _last_meaningful(result.stderr.splitlines()) if result else None
    evidence = evidence or _last_meaningful(lines)
    return FailureDiagnosis(generic, cause, evidence, classified=False)
