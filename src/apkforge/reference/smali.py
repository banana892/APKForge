"""Decoded-smali reference indexing (Phase H.1).

A line-oriented reader for the smali that Apktool's baksmali produces. It is deliberately
conservative: every line it cannot interpret *and* that carries reference syntax (a type
descriptor, ``->`` or a string) is reported as an :class:`AnalysisIssue`, which turns the
file's state into ``PARTIAL``. Lines without reference syntax (arithmetic, branches,
moves...) carry no reference and are skipped.

Reflection and ``System.loadLibrary`` targets are resolved with a tiny per-method register
tracker: a ``const-string`` / ``const-class`` value is associated with a later call only
within the same straight-line block (cleared at every branch-target label and overwritten
by any instruction that writes the register). Anything else is ``TARGET_UNKNOWN``.

This module never executes, modifies or rebuilds anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from sys import intern

from apkforge.reference.models import (
    AnalysisIssue,
    AnalysisState,
    DefinedMethod,
    Evidence,
    FieldAccess,
    InvokeKind,
    NativeResolution,
    ReferenceKind,
    ResolutionStatus,
    StringUse,
)

__all__ = [
    "SmaliFileResult",
    "class_name_from_descriptor",
    "dex_name_for_smali_root",
    "normalize_class_name",
    "parse_smali",
    "split_proto",
]

_PRIMITIVES = {
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "V": "void",
}
_TYPE = r"\[*(?:L[^;\s]+;|[ZBSCIJFD])"
_RET = r"\[*(?:L[^;\s]+;|[ZBSCIJFDV])"
_TYPE_RE = re.compile(_TYPE)
_OBJECT_TYPE_RE = re.compile(r"\[*L[^;\s\"]+;")
_CLASS_HEADER = re.compile(r"\.class\s+(?:[\w-]+\s+)*(?P<type>L[^;\s]+;)")
_FIELD_DECL = re.compile(
    r"\.field\s+(?P<mods>(?:[\w-]+\s+)*)(?P<name>[^\s:]+):(?P<type>" + _TYPE + r")"
    r"(?:\s*=\s*(?P<init>.*))?"
)
_METHOD_DECL = re.compile(
    r"\.method\s+(?P<mods>(?:[\w-]+\s+)*)(?P<name>[^\s(]+)"
    r"(?P<proto>\((?P<params>[^)]*)\)(?P<ret>" + _RET + r"))"
)
_METHOD_REF = re.compile(
    r"(?P<owner>" + _TYPE + r")->(?P<name>[^\s(]+)"
    r"(?P<proto>\((?P<params>[^)]*)\)(?P<ret>" + _RET + r"))"
)
_FIELD_REF = re.compile(r"(?P<owner>L[^;\s]+;)->(?P<name>[^\s:]+):(?P<type>" + _TYPE + r")")
_INVOKE_OP = re.compile(
    r"invoke-(?P<kind>virtual|super|direct|static|interface|polymorphic|custom)(?P<range>/range)?"
)
_FIELD_OP = re.compile(r"(?P<acc>[is](?:get|put))(?:-[a-z]+)*(?:/jumbo)?")
_REG = re.compile(r"[vp]\d+")
_REF_SYNTAX = re.compile(r"->|\"|" + r"\[*L[^;\s]+;")
_TYPE_OPERAND_OPS = {
    "new-instance": "new-instance",
    "check-cast": "check-cast",
    "instance-of": "instance-of",
    "const-class": "const-class",
    "new-array": "new-array",
    "filled-new-array": "filled-new-array",
    "filled-new-array/range": "filled-new-array",
}
_UNSUPPORTED_OPS = {
    "invoke-custom",
    "invoke-custom/range",
    "const-method-handle",
    "const-method-type",
}
#: opcodes that do not write their first register operand
_NO_WRITE_PREFIXES = (
    "invoke-",
    "if-",
    "return",
    "throw",
    "goto",
    "packed-switch",
    "sparse-switch",
    "fill-array-data",
    "monitor-",
    "iput",
    "sput",
    "aput",
    "check-cast",
    "nop",
    "filled-new-array",
)
_SKIP_BLOCKS = {
    ".array-data": ".end array-data",
    ".packed-switch": ".end packed-switch",
    ".sparse-switch": ".end sparse-switch",
}
_IGNORED_DIRECTIVES = {
    ".source",
    ".registers",
    ".locals",
    ".param",
    ".end param",
    ".prologue",
    ".epilogue",
    ".end local",
    ".restart local",
    ".end field",
    ".debug",
}
#: labels that are not branch targets (register values stay valid across them)
_NON_MERGE_LABELS = (":try_start", ":try_end")

# Reflection / dynamic resolution APIs: (owner, name) -> (api, argument role)
#   "class"    a class-name String argument
#   "member"   a member-name String argument (receiver: the Class object)
#   "receiver" the target is the Class receiver itself (no name argument)
#   "none"     the target was chosen elsewhere (reflective object / proxy / loader)
_REFLECTION: dict[tuple[str, str], str] = {
    ("java.lang.Class", "forName"): "class",
    ("java.lang.Class", "getMethod"): "member",
    ("java.lang.Class", "getDeclaredMethod"): "member",
    ("java.lang.Class", "getField"): "member",
    ("java.lang.Class", "getDeclaredField"): "member",
    ("java.lang.Class", "getConstructor"): "receiver",
    ("java.lang.Class", "getDeclaredConstructor"): "receiver",
    ("java.lang.Class", "getMethods"): "receiver",
    ("java.lang.Class", "getDeclaredMethods"): "receiver",
    ("java.lang.Class", "getFields"): "receiver",
    ("java.lang.Class", "getDeclaredFields"): "receiver",
    ("java.lang.Class", "getConstructors"): "receiver",
    ("java.lang.Class", "getDeclaredConstructors"): "receiver",
    ("java.lang.Class", "newInstance"): "receiver",
    ("java.lang.reflect.Method", "invoke"): "none",
    ("java.lang.reflect.Constructor", "newInstance"): "none",
    ("java.lang.reflect.Proxy", "newProxyInstance"): "none",
    ("java.lang.invoke.MethodHandles$Lookup", "findVirtual"): "none",
    ("java.lang.invoke.MethodHandles$Lookup", "findStatic"): "none",
    ("java.lang.invoke.MethodHandles$Lookup", "findSpecial"): "none",
    ("java.lang.invoke.MethodHandles$Lookup", "findConstructor"): "none",
    ("java.lang.invoke.MethodHandles$Lookup", "findClass"): "none",
}
_CLASS_LOADERS = {
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "dalvik.system.BaseDexClassLoader",
    "dalvik.system.DelegateLastClassLoader",
    "java.net.URLClassLoader",
}
_FIELD_REFLECTION = {"get", "set"}  # prefixes on java.lang.reflect.Field
_NATIVE_LOADS = {
    ("java.lang.System", "loadLibrary"),
    ("java.lang.System", "load"),
    ("java.lang.Runtime", "loadLibrary"),
    ("java.lang.Runtime", "load"),
}

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", '"': '"', "'": "'", "\\": "\\"}


def dex_name_for_smali_root(root: str) -> str | None:
    """``smali`` -> ``classes.dex``, ``smali_classes3`` -> ``classes3.dex``."""
    if root == "smali":
        return "classes.dex"
    if root.startswith("smali_"):
        return root[len("smali_") :] + ".dex"
    return None


def class_name_from_descriptor(desc: str) -> tuple[str | None, int]:
    """``[[Lcom/x/A$B;`` -> (``com.x.A$B``, 2); primitives -> (None, dims)."""
    dims = len(desc) - len(desc.lstrip("["))
    base = desc[dims:]
    if base.startswith("L") and base.endswith(";") and len(base) > 2:
        return base[1:-1].replace("/", "."), dims
    return None, dims


def readable_type(desc: str) -> str:
    cls, dims = class_name_from_descriptor(desc)
    base = cls if cls is not None else _PRIMITIVES.get(desc[dims:], desc[dims:])
    return base + "[]" * dims


def normalize_class_name(name: str) -> str:
    """Accept ``com.x.A``, ``com/x/A`` or ``Lcom/x/A;`` and return ``com.x.A``."""
    n = name.strip()
    if n.startswith("L") and n.endswith(";"):
        n = n[1:-1]
    return n.replace("/", ".")


def split_proto(params: str) -> list[str] | None:
    """Split a parameter descriptor list; None when it is not valid."""
    out: list[str] = []
    pos = 0
    while pos < len(params):
        m = _TYPE_RE.match(params, pos)
        if m is None:
            return None
        out.append(m.group(0))
        pos = m.end()
    return out


def _strip_comment(line: str) -> str:
    in_str = False
    esc = False
    for i, ch in enumerate(line):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "#":
            return line[:i].rstrip()
    return line.rstrip()


def _read_string(text: str) -> tuple[str, str] | None:
    """Parse a leading smali string literal: (value, rest) or None if malformed."""
    if not text.startswith('"'):
        return None
    out: list[str] = []
    i = 1
    while i < len(text):
        ch = text[i]
        if ch == '"':
            return _pair_surrogates("".join(out)), text[i + 1 :]
        if ch == "\\":
            if i + 1 >= len(text):
                return None
            nxt = text[i + 1]
            if nxt == "u":
                hexpart = text[i + 2 : i + 6]
                if len(hexpart) != 4 or not all(c in "0123456789abcdefABCDEF" for c in hexpart):
                    return None
                out.append(chr(int(hexpart, 16)))
                i += 6
                continue
            if nxt not in _ESCAPES:
                return None
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        out.append(ch)
        i += 1
    return None


def _pair_surrogates(value: str) -> str:
    """Join ``\\uD83D\\uDE00`` escape pairs; keep lone surrogates as escape text."""
    if not any("\ud800" <= c <= "\udfff" for c in value):
        return value
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        nxt = value[i + 1] if i + 1 < len(value) else ""
        if "\ud800" <= c <= "\udbff" and "\udc00" <= nxt <= "\udfff":
            out.append(chr(0x10000 + ((ord(c) - 0xD800) << 10) + (ord(nxt) - 0xDC00)))
            i += 2
            continue
        out.append(f"\\u{ord(c):04x}" if "\ud800" <= c <= "\udfff" else c)
        i += 1
    return "".join(out)


def _without_strings(text: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def _registers(spec: str) -> list[str] | None:
    spec = spec.strip()
    if not spec:
        return []
    if ".." in spec:
        a, _, b = spec.partition("..")
        a, b = a.strip(), b.strip()
        if not (_REG.fullmatch(a) and _REG.fullmatch(b)) or a[0] != b[0]:
            return None
        return [f"{a[0]}{n}" for n in range(int(a[1:]), int(b[1:]) + 1)]
    regs = [r.strip() for r in spec.split(",")]
    return regs if all(_REG.fullmatch(r) for r in regs) else None


def _jni_symbol(cls: str, name: str) -> str:
    def mangle(s: str) -> str:
        out = []
        for ch in s:
            if ch == ".":
                out.append("_")
            elif ch == "_":
                out.append("_1")
            elif ch == ";":
                out.append("_2")
            elif ch == "[":
                out.append("_3")
            elif ch.isascii() and ch.isalnum():
                out.append(ch)
            else:
                out.append(f"_0{ord(ch):04x}")
        return "".join(out)

    return f"Java_{mangle(cls)}_{mangle(name)}"


@dataclass
class _Value:
    """A statically known register value: a string or a class constant."""

    kind: str  # "string" | "class"
    value: str
    evidence: Evidence | None


@dataclass
class SmaliFileResult:
    path: str
    dex: str | None
    class_name: str | None = None
    superclass: str | None = None
    access_flags: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    methods: list[DefinedMethod] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    issues: list[AnalysisIssue] = field(default_factory=list)
    analyzed: bool = False

    @property
    def state(self) -> AnalysisState:
        if not self.analyzed:
            return AnalysisState.UNKNOWN
        return AnalysisState.PARTIAL if self.issues else AnalysisState.COMPLETE


class _Parser:
    def __init__(self, path: str, dex: str | None) -> None:
        self.res = SmaliFileResult(path=path, dex=dex)
        self.cls: str | None = None
        self.method: str | None = None
        self.method_line = 0
        self.java_line: int | None = None
        self.line_no = 0
        self.skip_until: str | None = None
        self.annotations: list[str] = []  # stack of annotation type names
        self.regs: dict[str, _Value] = {}
        self.pending: _Value | None = None
        self.dedupe: dict[tuple[str, str | None, str, str, str], Evidence] = {}
        self.assoc: dict[int, list[Evidence]] = {}
        #: ``.field`` / ``.param`` whose annotations may follow (not class/method level)
        self.member_ctx: str | None = None
        self.current: DefinedMethod | None = None

    # -- recording -----------------------------------------------------------

    def issue(self, code: str, message: str) -> None:
        self.res.issues.append(
            AnalysisIssue(code=code, location=f"{self.res.path}:{self.line_no}", message=message)
        )

    def add(self, kind: ReferenceKind, target: str, **kw: object) -> Evidence:
        ev = Evidence(
            kind=kind,
            source_file=self.res.path,
            source_dex=self.res.dex,
            source_class=self.cls,
            source_method=self.method,
            source_line=self.line_no,
            java_line=self.java_line,
            target=target,
            **kw,  # type: ignore[arg-type]
        )
        self.res.evidence.append(ev)
        return ev

    def add_deduped(self, kind: ReferenceKind, target: str, **kw: object) -> None:
        """Class/type mentions: one record per (method, target, role); count the rest."""
        key = (kind.value, self.method, target, str(kw.get("context")), str(kw.get("instruction")))
        prior = self.dedupe.get(key)
        if prior is not None:
            prior.occurrences += 1
            return
        self.dedupe[key] = self.add(kind, target, **kw)

    def type_ref(self, desc: str, context: str, instruction: str | None = None) -> str | None:
        cls, dims = class_name_from_descriptor(desc)
        if cls is None:
            return None
        cls = intern(cls)
        self.add_deduped(
            ReferenceKind.TYPE_REFERENCE,
            cls,
            target_class=cls,
            descriptor=intern(desc),
            array_dimensions=dims,
            context=context,
            instruction=instruction,
            confidence_basis=intern(f"type descriptor in {context}"),
        )
        return cls

    def class_ref(self, desc: str, instruction: str, context: str) -> str | None:
        cls, dims = class_name_from_descriptor(desc)
        if cls is None:
            return None
        cls = intern(cls)
        self.add_deduped(
            ReferenceKind.CLASS_REFERENCE,
            cls,
            target_class=cls,
            descriptor=intern(desc),
            array_dimensions=dims,
            instruction=instruction,
            context=context,
            confidence_basis=intern(f"{instruction} operand names the class"),
        )
        return cls

    def string_ref(self, value: str, context: str, instruction: str) -> Evidence:
        return self.add(
            ReferenceKind.STRING_REFERENCE,
            value,
            string_value=value,
            instruction=instruction,
            context=context,
            confidence_basis=intern(f"{instruction} literal"),
        )

    # -- driver --------------------------------------------------------------

    def run(self, text: str) -> SmaliFileResult:
        for raw in text.splitlines():
            self.line_no += 1
            line = _strip_comment(raw).strip()
            if not line:
                continue
            if self.skip_until is not None:
                if line == self.skip_until:
                    self.skip_until = None
                continue
            if self.annotations:
                self.annotation_line(line)
                continue
            if self.cls is None:
                if not line.startswith(".class"):
                    self.issue("MALFORMED_SMALI", "content before the .class header")
                    return self.finish()
                m = _CLASS_HEADER.fullmatch(line)
                if m is None:
                    self.issue("MALFORMED_SMALI", f"unparseable class header: {line[:120]}")
                    return self.finish()
                self.cls = class_name_from_descriptor(m.group("type"))[0]
                self.res.class_name = self.cls
                self.res.access_flags = line.split()[1:-1]
                self.res.analyzed = True
                continue
            if line.startswith("."):
                self.directive(line)
            elif line.startswith(":"):
                self.member_ctx = None
                if not line.startswith(_NON_MERGE_LABELS):
                    self.regs.clear()
                    self.pending = None
            elif self.method is None:
                self.issue("MALFORMED_SMALI", f"instruction outside a method: {line[:120]}")
            else:
                self.member_ctx = None
                self.instruction(line)
        if self.method is not None:
            self.issue("MALFORMED_SMALI", f"unterminated method {self.method}")
        if self.annotations:
            self.issue("MALFORMED_SMALI", "unterminated .annotation block")
        if self.skip_until is not None:
            self.issue("MALFORMED_SMALI", f"unterminated block (expected {self.skip_until})")
        return self.finish()

    def finish(self) -> SmaliFileResult:
        state = self.res.state
        for ev in self.res.evidence:
            ev.analysis_state = state
            ev.finalize_id()
        for ev in self.res.evidence:
            linked = self.assoc.get(id(ev))
            if linked:
                ev.associated_evidence = tuple(sorted({x.evidence_id for x in linked}))
        return self.res

    # -- directives ----------------------------------------------------------

    def directive(self, line: str) -> None:
        word = line.split(None, 1)[0]
        rest = line[len(word) :].strip()
        if word != ".annotation" and not (word == ".end" and rest in ("field", "param")):
            self.member_ctx = None
        if word in (".super", ".implements"):
            if not re.fullmatch(r"L[^;\s]+;", rest):
                self.issue("MALFORMED_SMALI", f"bad {word} operand: {rest[:120]}")
                return
            context = "superclass" if word == ".super" else "interface"
            if word == ".super":
                self.res.superclass = class_name_from_descriptor(rest)[0]
            else:
                iface = class_name_from_descriptor(rest)[0]
                if iface is not None:
                    self.res.interfaces.append(iface)
            self.class_ref(rest, word, context)
            self.type_ref(rest, context, word)
        elif word == ".field":
            self.field_decl(line)
            self.member_ctx = "field"
        elif word == ".param":
            self.member_ctx = "param"
        elif word == ".method":
            self.method_decl(line)
        elif word == ".end":
            if rest == "method":
                if self.method is None:
                    self.issue("MALFORMED_SMALI", ".end method without .method")
                self.method = None
                self.current = None
                self.java_line = None
                self.regs.clear()
                self.pending = None
            elif rest.split(None, 1)[0] in ("field", "param", "local"):
                self.member_ctx = None  # ".end local v2" carries a register operand
            else:
                self.issue("UNSUPPORTED_DIRECTIVE", f"unexpected {line[:120]}")
        elif word == ".line":
            try:
                self.java_line = int(rest, 0)
            except ValueError:
                self.issue("MALFORMED_SMALI", f"bad .line operand: {rest[:40]}")
        elif word == ".annotation":
            self.annotation_start(rest)
        elif word in _SKIP_BLOCKS:
            self.skip_until = _SKIP_BLOCKS[word]
        elif word == ".catch":
            m = re.match(r"(L[^;\s]+;)\s*\{", rest)
            if m is None:
                self.issue("MALFORMED_SMALI", f"bad .catch: {rest[:120]}")
                return
            self.class_ref(m.group(1), ".catch", "exception-handler")
            self.type_ref(m.group(1), "exception-handler", ".catch")
        elif word in (".local", ".restart"):
            for desc in _OBJECT_TYPE_RE.findall(_without_strings(rest)):
                self.type_ref(desc, "local-variable-debug-info", ".local")
        elif word == ".catchall" or word in _IGNORED_DIRECTIVES:
            pass
        else:
            self.issue("UNSUPPORTED_DIRECTIVE", f"directive not interpreted: {word}")
            self.generic_types(rest)

    def field_decl(self, line: str) -> None:
        m = _FIELD_DECL.match(line)
        if m is None:
            self.issue("MALFORMED_SMALI", f"unparseable field: {line[:120]}")
            return
        self.type_ref(m.group("type"), "field-type", ".field")
        init = (m.group("init") or "").strip()
        if init.startswith('"'):
            parsed = _read_string(init)
            if parsed is None:
                self.issue("MALFORMED_SMALI", "unterminated string in field initial value")
            else:
                self.string_ref(parsed[0], "field-initial-value", ".field")
        elif init and _REF_SYNTAX.search(init):
            self.generic_types(init)

    def method_decl(self, line: str) -> None:
        if self.method is not None:
            self.issue("MALFORMED_SMALI", f"method {self.method} not terminated before .method")
        self.current = None
        m = _METHOD_DECL.fullmatch(line)
        if m is None:
            self.issue("MALFORMED_SMALI", f"unparseable method header: {line[:120]}")
            self.method = "<unparseable>"
            return
        params = split_proto(m.group("params"))
        if params is None:
            self.issue("MALFORMED_SMALI", f"invalid parameter descriptor: {m.group('params')}")
            params = []
        self.method = m.group("name") + m.group("proto")
        self.current = DefinedMethod(
            name=intern(m.group("name")),
            descriptor=intern(m.group("proto")),
            access_flags=tuple(intern(f) for f in m.group("mods").split()),
            source_line=self.line_no,
        )
        self.res.methods.append(self.current)
        self.java_line = None
        self.regs.clear()
        self.pending = None
        for p in params:
            self.type_ref(p, "method-parameter", ".method")
        self.type_ref(m.group("ret"), "method-return", ".method")
        if "native" in m.group("mods").split():
            assert self.cls is not None
            name = m.group("name")
            self.add(
                ReferenceKind.NATIVE_METHOD,
                f"{self.cls}.{self.method}",
                target_class=self.cls,
                member_name=name,
                descriptor=m.group("proto"),
                parameter_types=tuple(intern(readable_type(p)) for p in params),
                return_type=readable_type(m.group("ret")),
                instruction=".method native",
                native_resolution=NativeResolution.UNKNOWN,
                confidence_basis=(
                    "method declared with the native modifier; its implementation is "
                    f"expected in a loaded library (JNI symbol {_jni_symbol(self.cls, name)}"
                    " or RegisterNatives) and is not statically associated with one"
                ),
            )

    def annotation_start(self, rest: str) -> None:
        m = re.match(r"(?:\w+\s+)?(L[^;\s]+;)$", rest)
        if m is None:
            self.issue("MALFORMED_SMALI", f"bad .annotation: {rest[:120]}")
            self.annotations.append("?")
            return
        cls = self.type_ref(m.group(1), "annotation", ".annotation")
        if cls is not None and self.member_ctx is None:
            if self.current is not None:
                self.current.annotations = (*self.current.annotations, intern(cls))
            elif self.method is None:
                self.res.annotations.append(cls)
        self.annotations.append(cls or "?")

    def annotation_line(self, line: str) -> None:
        if line == ".end annotation" or line == ".end subannotation":
            self.annotations.pop()
            return
        if ".subannotation" in _without_strings(line):
            m = re.search(r"\.subannotation\s+(L[^;\s]+;)", line)
            cls = self.type_ref(m.group(1), "annotation", ".subannotation") if m else None
            self.annotations.append(cls or "?")
            return
        for desc in _OBJECT_TYPE_RE.findall(_without_strings(line)):
            self.type_ref(desc, "annotation-value", ".annotation")
        if self.annotations[0].startswith("dalvik.annotation."):
            return  # Signature/InnerClass/... strings are compiler metadata, not values
        for lit in re.findall(r'"(?:\\.|[^"\\])*"', line):
            parsed = _read_string(lit)
            if parsed is not None:
                self.string_ref(parsed[0], "annotation-value", ".annotation")

    def generic_types(self, text: str) -> None:
        for desc in _OBJECT_TYPE_RE.findall(_without_strings(text)):
            self.type_ref(desc, "unsupported-operand")

    # -- instructions --------------------------------------------------------

    def instruction(self, line: str) -> None:
        parts = line.split(None, 1)
        op = intern(parts[0])
        rest = parts[1].strip() if len(parts) > 1 else ""
        pending, self.pending = self.pending, None

        if op in _UNSUPPORTED_OPS:
            self.issue("UNSUPPORTED_INSTRUCTION", f"{op} is not interpreted")
            self.generic_types(rest)
            self.write_reg(rest)
            return
        if op.startswith("invoke-"):
            self.invoke(op, rest)
            return
        if op == "move-result-object":
            self.write_reg(rest)
            if pending is not None and _REG.fullmatch(rest):
                self.regs[rest] = pending
            return
        if op == "move-object" or op.startswith("move-object/"):
            regs = [r.strip() for r in rest.split(",")]
            if len(regs) == 2:
                src = self.regs.get(regs[1])
                self.regs.pop(regs[0], None)
                if src is not None:
                    self.regs[regs[0]] = src
            return
        if op in ("const-string", "const-string/jumbo"):
            reg, _, lit = rest.partition(",")
            parsed = _read_string(lit.strip())
            if parsed is None or not _REG.fullmatch(reg.strip()):
                self.issue("MALFORMED_SMALI", f"bad {op} operand")
                self.write_reg(rest)
                return
            ev = self.string_ref(parsed[0], "operand", op)
            self.regs[reg.strip()] = _Value("string", parsed[0], ev)
            return
        if _FIELD_OP.fullmatch(op):
            self.field_op(op, rest)
            return
        if op in _TYPE_OPERAND_OPS:
            self.type_operand(op, rest)
            return
        if _REF_SYNTAX.search(rest):
            self.issue("UNSUPPORTED_INSTRUCTION", f"{op} operand not interpreted: {rest[:120]}")
            self.generic_types(rest)
        if not op.startswith(_NO_WRITE_PREFIXES):
            self.write_reg(rest)

    def write_reg(self, rest: str) -> None:
        first = rest.split(",", 1)[0].strip()
        if _REG.fullmatch(first):
            self.regs.pop(first, None)

    def type_operand(self, op: str, rest: str) -> None:
        name = _TYPE_OPERAND_OPS[op]
        desc = rest.rsplit(",", 1)[-1].strip()
        if not re.fullmatch(_TYPE, desc):
            self.issue("MALFORMED_SMALI", f"bad {op} type operand: {desc[:120]}")
            return
        context = "array-element" if name in ("new-array", "filled-new-array") else "operand"
        cls = self.class_ref(desc, name, context)
        self.type_ref(desc, context, name)
        if op == "const-class" and cls is not None:
            _, dims = class_name_from_descriptor(desc)
            ev = self.add(
                ReferenceKind.CONST_CLASS_REFERENCE,
                cls,
                target_class=cls,
                descriptor=desc,
                array_dimensions=dims,
                instruction="const-class",
                confidence_basis=f"const-class loads the Class object for {desc}",
            )
            reg = rest.split(",", 1)[0].strip()
            self.regs.pop(reg, None)
            if dims == 0:
                self.regs[reg] = _Value("class", cls, ev)
            return
        if op == "new-instance" or op == "new-array" or op == "instance-of":
            self.write_reg(rest)

    def field_op(self, op: str, rest: str) -> None:
        m_acc = _FIELD_OP.fullmatch(op)
        assert m_acc is not None
        ref = rest.rsplit(",", 1)[-1].strip()
        m = _FIELD_REF.fullmatch(ref)
        if m is None:
            if _REF_SYNTAX.search(rest):
                self.issue("MALFORMED_SMALI", f"bad field reference: {ref[:120]}")
                self.generic_types(rest)
            else:
                self.issue("UNSUPPORTED_INSTRUCTION", f"{op} without a symbolic field reference")
            if op.startswith(("iget", "sget")):
                self.write_reg(rest)
            return
        owner, name, ftype = m.group("owner"), m.group("name"), m.group("type")
        cls = class_name_from_descriptor(owner)[0]
        assert cls is not None
        self.add(
            ReferenceKind.FIELD_REFERENCE,
            intern(f"{cls}.{name}:{ftype}"),
            target_class=intern(cls),
            member_name=intern(name),
            descriptor=intern(ftype),
            return_type=intern(readable_type(ftype)),
            access_kind=FieldAccess(m_acc.group("acc")),
            instruction=intern(op),
            confidence_basis=intern(f"{op} instruction names the field"),
        )
        self.class_ref(owner, op, "member-owner")
        self.type_ref(owner, "member-owner", op)
        self.type_ref(ftype, "member-descriptor", op)
        if op.startswith(("iget", "sget")):
            self.write_reg(rest)

    def invoke(self, op: str, rest: str) -> None:
        m_op = _INVOKE_OP.fullmatch(op)
        m_regs = re.match(r"\{(?P<regs>[^}]*)\}\s*,\s*(?P<ref>.+)$", rest)
        if m_op is None or m_regs is None:
            self.issue("UNSUPPORTED_INSTRUCTION", f"{op} not interpreted: {rest[:120]}")
            self.generic_types(rest)
            return
        regs = _registers(m_regs.group("regs"))
        m = _METHOD_REF.match(m_regs.group("ref"))
        if m is None or regs is None:
            self.issue("MALFORMED_SMALI", f"bad method reference: {m_regs.group('ref')[:120]}")
            self.generic_types(rest)
            return
        params = split_proto(m.group("params"))
        if params is None:
            self.issue("MALFORMED_SMALI", f"invalid parameter descriptor: {m.group('params')}")
            params = []
        owner_desc, name, proto = m.group("owner"), m.group("name"), m.group("proto")
        owner, _dims = class_name_from_descriptor(owner_desc)
        owner_label = owner if owner is not None else readable_type(owner_desc)
        kind = InvokeKind(f"invoke-{m_op.group('kind')}")
        is_ctor = name == "<init>"
        self.add(
            ReferenceKind.CONSTRUCTOR_REFERENCE if is_ctor else ReferenceKind.METHOD_REFERENCE,
            intern(f"{owner_label}.{name}{proto}"),
            target_class=intern(owner) if owner is not None else None,
            member_name=intern(name),
            descriptor=intern(proto),
            parameter_types=tuple(intern(readable_type(p)) for p in params),
            return_type=intern(readable_type(m.group("ret"))),
            invoke_kind=kind,
            instruction=intern(op),
            confidence_basis=intern(f"{op} instruction names the method"),
        )
        self.class_ref(owner_desc, op, "member-owner")
        self.type_ref(owner_desc, "member-owner", op)
        for p in params:
            self.type_ref(p, "member-descriptor", op)
        self.type_ref(m.group("ret"), "member-descriptor", op)
        if owner is not None:
            self.dynamic_indicators(op, kind, owner, name, proto, regs)

    # -- reflection / native -------------------------------------------------

    def _arg(self, regs: list[str], kind: InvokeKind, index: int) -> _Value | None:
        pos = index + (0 if kind is InvokeKind.STATIC else 1)
        return self.regs.get(regs[pos]) if pos < len(regs) else None

    def dynamic_indicators(
        self, op: str, kind: InvokeKind, owner: str, name: str, proto: str, regs: list[str]
    ) -> None:
        api = f"{owner}.{name}"
        role = _REFLECTION.get((owner, name))
        if role is None and name == "loadClass" and proto.startswith("(Ljava/lang/String;"):
            role = "class"
        if role is None and owner in _CLASS_LOADERS and name == "<init>":
            role = "loader"
        if (
            role is None
            and owner == "java.lang.reflect.Field"
            and name.startswith(tuple(_FIELD_REFLECTION))
        ):
            role = "none"
        if role is not None:
            self.reflection(op, kind, api, role, regs)
            return
        if (owner, name) in _NATIVE_LOADS and proto.startswith("(Ljava/lang/String;"):
            arg = self._arg(regs, kind, 0)
            lib = arg.value if arg is not None and arg.kind == "string" else None
            ev = self.add(
                ReferenceKind.NATIVE_LIBRARY_LOAD,
                lib if lib is not None else "<unresolved>",
                library_name=lib,
                reflection_api=api,
                native_resolution=(
                    NativeResolution.IDENTIFIED if lib is not None else NativeResolution.UNKNOWN
                ),
                instruction=op,
                confidence_basis=(
                    f"{api} argument traced to const-string {lib!r} in the same basic block"
                    if lib is not None
                    else f"{api} argument is not a constant traceable in the same basic block"
                ),
            )
            if arg is not None and arg.evidence is not None:
                self.assoc[id(ev)] = [arg.evidence]

    def reflection(self, op: str, kind: InvokeKind, api: str, role: str, regs: list[str]) -> None:
        linked: list[Evidence] = []
        target_class: str | None = None
        member: str | None = None
        context: str
        if role == "class":
            context = "class-name-argument"
            arg = self._arg(regs, kind, 0)
            if arg is not None and arg.kind == "string":
                target_class = normalize_class_name(arg.value)
                if arg.evidence is not None:
                    arg.evidence.string_use = StringUse.POSSIBLE_REFLECTION_TARGET
                    linked.append(arg.evidence)
            resolved = target_class is not None
            if resolved:
                assert target_class is not None
                self.pending = _Value("class", target_class, None)
        elif role == "member":
            context = "member-name-argument"
            recv = self.regs.get(regs[0]) if regs else None
            if recv is not None and recv.kind == "class":
                target_class = recv.value
                if recv.evidence is not None:
                    linked.append(recv.evidence)
            arg = self._arg(regs, kind, 0)
            if arg is not None and arg.kind == "string":
                member = arg.value
                if arg.evidence is not None:
                    arg.evidence.string_use = (
                        StringUse.POSSIBLE_METHOD_NAME
                        if "Method" in api
                        else StringUse.POSSIBLE_REFLECTION_TARGET
                    )
                    linked.append(arg.evidence)
            resolved = member is not None
        elif role == "receiver":
            context = "class-receiver"
            recv = self.regs.get(regs[0]) if regs else None
            if recv is not None and recv.kind == "class":
                target_class = recv.value
                if recv.evidence is not None:
                    linked.append(recv.evidence)
            resolved = target_class is not None
        else:
            context = "dynamic-code-loading" if role == "loader" else "reflective-object"
            resolved = False

        if role in ("none", "loader"):
            resolution = ResolutionStatus.NO_TARGET_IDENTIFIED
            target = "<not identified>"
            basis = (
                f"{api} creates a class loader; code it loads is not visible to static analysis"
                if role == "loader"
                else f"{api} acts on a reflective object whose target is chosen elsewhere"
            )
        elif resolved:
            resolution = ResolutionStatus.TARGET_IDENTIFIED
            target = f"{target_class or '?'}.{member}" if member else str(target_class)
            basis = f"{api} argument traced to a constant in the same basic block"
        else:
            resolution = ResolutionStatus.TARGET_UNKNOWN
            target = "<unresolved>"
            basis = f"{api} argument is not a constant traceable in the same basic block"
        ev = self.add(
            ReferenceKind.REFLECTION_INDICATOR,
            target,
            target_class=target_class,
            member_name=member,
            reflection_api=api,
            resolution=resolution,
            instruction=op,
            context=context,
            confidence_basis=basis,
        )
        if linked:
            self.assoc[id(ev)] = linked


def parse_smali(text: str, path: str, dex: str | None = None) -> SmaliFileResult:
    """Index one smali file. *path* is the project-relative path recorded as provenance."""
    return _Parser(path, dex).run(text)
