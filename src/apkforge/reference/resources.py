"""Resource / asset references (Phase H.1).

Scans the decoded ``res/`` tree (component ``resources``) and ``assets/`` plus Apktool's
``unknown/`` copy of other archive files (component ``assets``) for explicit mentions of
classes defined in the APK and of provider authorities declared in the manifest.

Match bases:

- structural: ``XML_ELEMENT_NAME`` (``<com.x.CustomView>``), ``CLASS_ATTRIBUTE``
  (``class=``, ``android:name=``, ``android:fragment=``, ``app:layout_behavior=``...),
  ``SERVICE_LOADER_ENTRY`` (``META-INF/services/*`` lines)
- textual: ``EXACT_VALUE`` (a value equals the target), ``EMBEDDED_TOKEN`` (the target
  appears inside a longer value). Textual matches are evidence, not proof of use.

Inputs that cannot be inspected make the component ``PARTIAL``: XML that does not parse,
non-text files that are not a known media/font format, and files over the size limit.
Media/font files are skipped as not reference-bearing.
"""

from __future__ import annotations

import re
import xml.parsers.expat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkforge.reference.manifest import resolve_component_name
from apkforge.reference.models import (
    AnalysisIssue,
    AnalysisState,
    Evidence,
    MatchBasis,
    ReferenceKind,
)

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["MAX_TEXT_BYTES", "ResourceAnalysis", "analyze_tree"]

MAX_TEXT_BYTES = 8 * 1024 * 1024
#: formats that carry no class/authority references (skipped without lowering the state)
_MEDIA_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".ico",
    ".heic",
    ".heif",
    ".avif",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".mp3",
    ".ogg",
    ".oga",
    ".wav",
    ".m4a",
    ".aac",
    ".flac",
    ".mid",
    ".midi",
    ".amr",
    ".opus",
    ".mp4",
    ".webm",
    ".3gp",
    ".mkv",
}
#: local names of attributes whose value Android/AndroidX interpret as a class name
_CLASS_ATTR_LOCAL = {
    "class",
    "name",
    "fragment",
    "layout_behavior",
    "actionViewClass",
    "actionProviderClass",
    "targetClass",
}
_CLASS_TOKEN = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?![\w$])")
_SLASH_TOKEN = re.compile(r"(?<![\w$/])L?[A-Za-z_$][\w$]*(?:/[A-Za-z_$][\w$]*)+;?(?![\w$])")


class _ForbiddenDTD(Exception):
    pass


@dataclass
class ResourceAnalysis:
    component: str
    state: AnalysisState
    files_total: int = 0
    files_analyzed: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    issues: list[AnalysisIssue] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Matcher:
    def __init__(self, package: str | None, classes: set[str], authorities: dict[str, str]) -> None:
        self.package = package
        self.classes = classes
        self.authorities = authorities
        self._auth_re = (
            re.compile(
                r"(?<![\w.-])("
                + "|".join(re.escape(a) for a in sorted(authorities))
                + r")(?![\w-])"
            )
            if authorities
            else None
        )

    def classes_in(self, text: str) -> set[str]:
        found = {t for t in _CLASS_TOKEN.findall(text) if t in self.classes}
        for t in _SLASH_TOKEN.findall(text):
            name = t.removeprefix("L").removesuffix(";").replace("/", ".")
            if name in self.classes:
                found.add(name)
        return found

    def authorities_in(self, text: str) -> set[str]:
        return set(self._auth_re.findall(text)) if self._auth_re else set()

    def class_value(self, value: str) -> str | None:
        v = value.strip()
        cls = resolve_component_name(self.package, v) if v.startswith(".") else v
        return cls if cls in self.classes else None


class _Scanner:
    def __init__(self, root: Path, out: ResourceAnalysis, matcher: _Matcher) -> None:
        self.root = root
        self.out = out
        self.m = matcher

    def issue(self, code: str, location: str, message: str) -> None:
        self.out.issues.append(AnalysisIssue(code=code, location=location, message=message))

    def add(
        self,
        rel: str,
        line: int | None,
        location: str | None,
        value: str,
        target: str,
        basis: MatchBasis,
        context: str,
        target_class: str | None,
        why: str,
    ) -> None:
        self.out.evidence.append(
            Evidence(
                kind=ReferenceKind.RESOURCE_REFERENCE,
                source_file=rel,
                source_line=line,
                xml_location=location,
                matched_value=value[:500],
                target=target,
                target_class=target_class,
                match_basis=basis,
                context=context,
                confidence_basis=why,
            )
        )

    def textual(self, rel: str, line: int | None, location: str | None, value: str) -> None:
        stripped = value.strip()
        for cls in sorted(self.m.classes_in(value)):
            exact = stripped in (cls, f"L{cls.replace('.', '/')};", cls.replace(".", "/"))
            basis = MatchBasis.EXACT_VALUE if exact else MatchBasis.EMBEDDED_TOKEN
            self.add(
                rel,
                line,
                location,
                value,
                cls,
                basis,
                "class-name",
                cls,
                "text equals a class defined in this APK"
                if exact
                else "text contains a class name defined in this APK",
            )
        for auth in sorted(self.m.authorities_in(value)):
            exact = stripped == auth
            self.add(
                rel,
                line,
                location,
                value,
                auth,
                MatchBasis.EXACT_VALUE if exact else MatchBasis.EMBEDDED_TOKEN,
                "provider-authority",
                self.m.authorities.get(auth),
                "text mentions a provider authority declared in the manifest",
            )

    # -- per file ------------------------------------------------------------

    def scan(self, path: Path) -> None:
        rel = path.relative_to(self.root).as_posix()
        self.out.files_total += 1
        try:
            size = path.stat().st_size
            if size > MAX_TEXT_BYTES:
                self.issue("FILE_TOO_LARGE", rel, f"{size} bytes exceeds the scan limit")
                return
            data = path.read_bytes()
        except OSError as exc:
            self.issue("UNREADABLE_FILE", rel, str(exc))
            return
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if path.suffix.lower() in _MEDIA_SUFFIXES:
                self.out.files_analyzed += 1  # not reference-bearing by format
            else:
                self.issue("BINARY_NOT_INSPECTED", rel, "non-text file not inspected")
            return
        if "\x00" in text and path.suffix.lower() not in (".xml",):
            self.issue("BINARY_NOT_INSPECTED", rel, "non-text file not inspected")
            return
        if path.suffix.lower() == ".xml":
            mark = len(self.out.evidence)
            if not self.scan_xml(rel, text):
                del self.out.evidence[mark:]  # drop the half-parsed structure, keep text hits
                self.scan_lines(rel, text)
                return
        elif "/META-INF/services/" in f"/{rel}":
            self.scan_service_loader(rel, text)
        else:
            self.scan_lines(rel, text)
        self.out.files_analyzed += 1

    def scan_lines(self, rel: str, text: str) -> None:
        for n, line in enumerate(text.splitlines(), 1):
            self.textual(rel, n, None, line)

    def scan_service_loader(self, rel: str, text: str) -> None:
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if line and line in self.m.classes:
                self.add(
                    rel,
                    n,
                    None,
                    line,
                    line,
                    MatchBasis.SERVICE_LOADER_ENTRY,
                    "service-provider",
                    line,
                    "java.util.ServiceLoader provider-configuration entry",
                )
            elif line:
                self.textual(rel, n, None, raw)

    def scan_xml(self, rel: str, text: str) -> bool:
        parser = xml.parsers.expat.ParserCreate()
        stack: list[str] = []
        counters: list[dict[str, int]] = [{}]
        chunks: list[tuple[int, str]] = []

        def location() -> str:
            return "/" + "/".join(stack)

        def flush_text() -> None:
            if chunks:
                line = chunks[0][0]
                value = "".join(c for _, c in chunks)
                chunks.clear()
                if value.strip():
                    self.textual(rel, line, location() + "/text()", value)

        def start(tag: str, attrs: dict[str, str]) -> None:
            flush_text()
            line = parser.CurrentLineNumber
            pos = counters[-1].get(tag, 0) + 1
            counters[-1][tag] = pos
            stack.append(f"{tag}[{pos}]")
            counters.append({})
            loc = location()
            if "." in tag and tag in self.m.classes:
                self.add(
                    rel,
                    line,
                    loc,
                    tag,
                    tag,
                    MatchBasis.XML_ELEMENT_NAME,
                    "xml-element",
                    tag,
                    "XML element named by a class defined in this APK (inflated by class name)",
                )
            for attr in sorted(attrs):
                value = attrs[attr]
                local = attr.rsplit(":", 1)[-1]
                cls = self.m.class_value(value) if local in _CLASS_ATTR_LOCAL else None
                if cls is not None:
                    self.add(
                        rel,
                        line,
                        f"{loc}/@{attr}",
                        value,
                        cls,
                        MatchBasis.CLASS_ATTRIBUTE,
                        "class-attribute",
                        cls,
                        f"class-valued attribute {attr}",
                    )
                else:
                    self.textual(rel, line, f"{loc}/@{attr}", value)

        def end(_tag: str) -> None:
            flush_text()
            stack.pop()
            counters.pop()

        def chars(data: str) -> None:
            chunks.append((parser.CurrentLineNumber, data))

        def forbid(*_args: object) -> None:
            raise _ForbiddenDTD("DTD entity declarations are not processed")

        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.CharacterDataHandler = chars
        parser.EntityDeclHandler = forbid
        parser.ExternalEntityRefHandler = forbid  # type: ignore[assignment]
        try:
            parser.Parse(text.encode("utf-8"), True)
        except (xml.parsers.expat.ExpatError, _ForbiddenDTD) as exc:
            self.issue("XML_PARSE_ERROR", rel, f"XML not parsed: {exc}")
            return False
        return True


def analyze_tree(
    project: Path,
    dirs: tuple[str, ...],
    component: str,
    *,
    package: str | None,
    classes: set[str],
    authorities: dict[str, str],
) -> ResourceAnalysis:
    """Scan *dirs* (relative to the decoded *project*) in a deterministic order."""
    out = ResourceAnalysis(component=component, state=AnalysisState.COMPLETE)
    scanner = _Scanner(project, out, _Matcher(package, classes, authorities))
    present = [project / d for d in dirs if (project / d).is_dir()]
    for base in present:
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                scanner.issue(
                    "SYMLINK_SKIPPED", path.relative_to(project).as_posix(), "symlink not followed"
                )
                out.files_total += 1
            elif path.is_file():
                scanner.scan(path)
    if not present:
        out.notes.append(f"no {', '.join(d + '/' for d in dirs)} directory in the project")
    out.evidence = [ev.finalize_id() for ev in out.evidence]
    if out.issues:
        out.state = AnalysisState.PARTIAL
        for ev in out.evidence:
            ev.analysis_state = AnalysisState.PARTIAL
    return out
