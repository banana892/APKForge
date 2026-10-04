"""DEX inspector — structural inspection of Dalvik Executable files.

Extracts class inventory, method/field information, API references, and
strings from all DEX files inside the APK.

Does NOT decompile the application, generate Java source code, or attempt
full reverse engineering.  The objective is a structured inventory.

Security invariant: DEX code is never executed.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import struct
import zipfile
from typing import TYPE_CHECKING, Any

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    FieldInfo,
    MethodInfo,
    StringReference,
)
from apkforge.intake.hashing import compute_sha256

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.intake import AndroidPackage

__all__ = ["DEXInspector"]

_log = get_logger(__name__)

# DEX magic: "dex\n" followed by version
_DEX_MAGIC = b"dex\n"

# Regex for DEX file entries (including non-standard locations)
_DEX_PATTERN = re.compile(r"classes\d*\.dex$")

# Well-known Android framework packages for API reference detection
_FRAMEWORK_PREFIXES = (
    "Landroid/",
    "Lcom/google/android/",
    "Ldalvik/",
    "Ljava/",
    "Ljavax/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lorg/w3c/",
)

# Max items to avoid memory issues with huge apps
_MAX_CLASSES = 50_000
_MAX_METHODS = 200_000
_MAX_FIELDS = 200_000
_MAX_STRINGS = 100_000


def _dalvik_to_java(name: str) -> str:
    """Convert a Dalvik descriptor like 'Lcom/example/Foo;' to 'com.example.Foo'."""
    if name.startswith("L") and name.endswith(";"):
        return name[1:-1].replace("/", ".")
    return name.replace("/", ".")


def _parse_dex_version(data: bytes) -> str | None:
    """Extract the DEX version string from header bytes."""
    if len(data) < 8:
        return None
    if data[:4] != _DEX_MAGIC:
        return None
    # Version is at bytes 4-7, zero-terminated (e.g. b"035\x00")
    ver_bytes = data[4:7]
    try:
        return ver_bytes.decode("ascii").strip("\x00")
    except UnicodeDecodeError:
        return None


def _access_flags_str(flags: int) -> str:
    """Convert numeric access flags to a human-readable string."""
    parts = []
    flag_names = [
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0020, "synchronized"),
        (0x0040, "volatile"),  # or bridge for methods
        (0x0080, "transient"),  # or varargs for methods
        (0x0100, "native"),
        (0x0200, "interface"),
        (0x0400, "abstract"),
        (0x0800, "strict"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
    ]
    for flag_val, flag_name in flag_names:
        if flags & flag_val:
            parts.append(flag_name)
    return " ".join(parts) if parts else ""


class DEXInspector:
    """Inspects all DEX files inside an APK.

    Uses Androguard's DalvikVMFormat for structured parsing.  Falls back
    to basic header parsing if Androguard is unavailable.
    """

    def inspect(
        self,
        apk_path: Path,
        package: AndroidPackage | None = None,
    ) -> tuple[DEXInspection, list[str]]:
        """Inspect all DEX files in the APK.

        Args:
            apk_path: Path to the APK file.
            package: Phase 1 AndroidPackage (for reusing DEX file info).

        Returns:
            Tuple of (DEXInspection, warnings).
        """
        warnings: list[str] = []
        result = DEXInspection()

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                dex_entries = [
                    info.filename
                    for info in zf.infolist()
                    if not info.is_dir() and _DEX_PATTERN.search(info.filename)
                ]

                for dex_name in sorted(dex_entries):
                    try:
                        data = zf.read(dex_name)
                        info = zf.getinfo(dex_name)
                        dex_result = self._inspect_single_dex(
                            dex_name, data, info.file_size, result.strings, warnings
                        )
                        result.dex_files.append(dex_result)
                        result.total_classes += dex_result.class_count
                        result.total_methods += dex_result.method_count
                        result.total_fields += dex_result.field_count
                    except Exception as exc:
                        warnings.append(f"Could not inspect DEX '{dex_name}': {exc}")

        except (zipfile.BadZipFile, OSError) as exc:
            warnings.append(f"Could not open APK for DEX inspection: {exc}")

        return result, warnings

    def _inspect_single_dex(
        self,
        dex_name: str,
        data: bytes,
        file_size: int,
        all_strings: list[StringReference],
        warnings: list[str],
    ) -> DEXFileInspection:
        """Inspect a single DEX file."""
        sha256 = compute_sha256(data)
        dex_version = _parse_dex_version(data)

        result = DEXFileInspection(
            path=dex_name,
            size=file_size,
            sha256=sha256,
            dex_version=dex_version,
        )

        # Try Androguard for deep inspection
        try:
            self._inspect_with_androguard(data, dex_name, result, all_strings, warnings)
        except ImportError:
            warnings.append("Androguard not installed; DEX class inventory unavailable.")
            self._inspect_basic(data, dex_name, result, all_strings, warnings)
        except Exception as exc:
            warnings.append(f"Androguard DEX parsing failed for {dex_name}: {exc}")
            self._inspect_basic(data, dex_name, result, all_strings, warnings)

        return result

    def _inspect_with_androguard(
        self,
        data: bytes,
        dex_name: str,
        result: DEXFileInspection,
        all_strings: list[StringReference],
        warnings: list[str],
    ) -> None:
        """Use Androguard to extract detailed class/method/field info."""
        from androguard.core.dex import DEX

        dex = DEX(data)

        classes: list[ClassInfo] = []
        methods: list[MethodInfo] = []
        fields: list[FieldInfo] = []
        api_refs: set[str] = set()
        string_set: set[str] = set()
        seen_string_class: set[tuple[str, str]] = set()

        for cls_def in dex.get_classes():
            if len(classes) >= _MAX_CLASSES:
                warnings.append(f"Class limit ({_MAX_CLASSES}) reached for {dex_name}; truncating.")
                break

            cls_name = _dalvik_to_java(cls_def.get_name())
            superclass = None
            if cls_def.get_superclassname():
                superclass = _dalvik_to_java(cls_def.get_superclassname())

            interfaces = []
            with contextlib.suppress(Exception):
                ifaces = cls_def.get_interfaces()
                if ifaces:
                    interfaces = [_dalvik_to_java(i) for i in ifaces]

            access_flags = _access_flags_str(cls_def.get_access_flags())

            cls_method_count = 0
            cls_field_count = 0

            # Methods
            for method in cls_def.get_methods():
                if len(methods) >= _MAX_METHODS:
                    break
                cls_method_count += 1

                m_name = method.get_name()
                m_class = cls_name
                m_return = ""
                m_params: list[str] = []
                m_flags = ""

                with contextlib.suppress(Exception):
                    m_return = _dalvik_to_java(method.get_descriptor().split(")")[-1])

                with contextlib.suppress(Exception):
                    desc = method.get_descriptor()
                    param_str = desc[1 : desc.index(")")]
                    if param_str:
                        # Simple param parsing
                        m_params = [_dalvik_to_java(p) for p in _parse_params(param_str)]

                with contextlib.suppress(Exception):
                    m_flags = _access_flags_str(method.get_access_flags())

                m_code_hash = None
                code = None
                with contextlib.suppress(Exception):
                    code = method.get_code()
                    if code:
                        m_code_hash = _hash_method_code(code)

                methods.append(
                    MethodInfo(
                        name=m_name,
                        class_name=m_class,
                        return_type=m_return,
                        parameters=m_params,
                        access_flags=m_flags,
                        code_hash=m_code_hash,
                    )
                )

                # API references from method code
                with contextlib.suppress(Exception):
                    if code:
                        bc = code.get_bc()
                        if bc:
                            for inst in bc.get_instructions():
                                output = inst.get_output()
                                if output:
                                    for prefix in _FRAMEWORK_PREFIXES:
                                        if prefix in output:
                                            # Extract the class reference
                                            for part in output.split():
                                                if part.startswith("L") and part.endswith(";"):
                                                    ref = _dalvik_to_java(part)
                                                    api_refs.add(ref)

                                if inst.get_name().startswith("const-string"):
                                    ops = inst.get_operands()
                                    if (
                                        len(ops) > 1
                                        and isinstance(ops[1], tuple)
                                        and len(ops[1]) >= 3
                                    ):
                                        op_entry: tuple[Any, ...] = ops[1]
                                        s_val = op_entry[2]
                                        if (
                                            isinstance(s_val, str)
                                            and len(s_val) >= 4
                                            and s_val.isprintable()
                                            and any(
                                                k in s_val.lower()
                                                for k in (
                                                    "des",
                                                    "blowfish",
                                                    "rc2",
                                                    "rc4",
                                                    "arcfour",
                                                    "pbe",
                                                    "md5",
                                                    "sha-1",
                                                    "sha1",
                                                    "rsa",
                                                    "ec",
                                                    "aes",
                                                    "cipher",
                                                    "secret",
                                                    "private key",
                                                )
                                            )
                                            and (s_val, cls_name) not in seen_string_class
                                        ):
                                            seen_string_class.add((s_val, cls_name))
                                            string_set.add(s_val)
                                            all_strings.append(
                                                StringReference(
                                                    value=s_val,
                                                    dex_file=dex_name,
                                                    class_name=cls_name,
                                                    method_name=m_name,
                                                )
                                            )

            # Fields
            for field in cls_def.get_fields():
                if len(fields) >= _MAX_FIELDS:
                    break
                cls_field_count += 1

                f_name = field.get_name()
                f_class = cls_name
                f_type = ""
                f_flags = ""

                with contextlib.suppress(Exception):
                    f_type = _dalvik_to_java(field.get_descriptor())

                with contextlib.suppress(Exception):
                    f_flags = _access_flags_str(field.get_access_flags())

                fields.append(
                    FieldInfo(
                        name=f_name,
                        class_name=f_class,
                        type=f_type,
                        access_flags=f_flags,
                    )
                )

            classes.append(
                ClassInfo(
                    name=cls_name,
                    superclass=superclass,
                    interfaces=interfaces,
                    access_flags=access_flags,
                    method_count=cls_method_count,
                    field_count=cls_field_count,
                )
            )

        # Strings
        with contextlib.suppress(Exception):
            for s in dex.get_strings():
                if len(string_set) >= _MAX_STRINGS:
                    break
                s_val = s
                if (
                    len(s_val) >= 4
                    and s_val.isprintable()
                    and s_val not in string_set
                ):
                    string_set.add(s_val)
                    all_strings.append(
                        StringReference(
                            value=s_val,
                            dex_file=dex_name,
                        )
                    )

        result.class_count = len(classes)
        result.method_count = len(methods)
        result.field_count = len(fields)
        result.inventory = DEXClassInventory(
            classes=classes,
            methods=methods,
            fields=fields,
        )
        result.api_references = sorted(api_refs)

    def _inspect_basic(
        self,
        data: bytes,
        dex_name: str,
        result: DEXFileInspection,
        all_strings: list[StringReference],
        warnings: list[str],
    ) -> None:
        """Basic DEX inspection from header without Androguard."""
        if len(data) < 112:
            return

        try:
            # Parse DEX header for counts
            # Offsets from DEX format spec
            method_ids_size = struct.unpack_from("<I", data, 88)[0]
            field_ids_size = struct.unpack_from("<I", data, 80)[0]
            class_defs_size = struct.unpack_from("<I", data, 96)[0]

            result.class_count = class_defs_size
            result.method_count = method_ids_size
            result.field_count = field_ids_size

            # Extract printable strings via basic scan
            self._extract_printable_strings(data, dex_name, all_strings)

        except Exception as exc:
            warnings.append(f"Basic DEX header parsing failed for {dex_name}: {exc}")

    def _extract_printable_strings(
        self,
        data: bytes,
        dex_name: str,
        all_strings: list[StringReference],
    ) -> None:
        """Extract printable ASCII strings from raw DEX bytes."""
        min_length = 6
        current: list[int] = []
        count = 0

        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= min_length and count < _MAX_STRINGS:
                    s = bytes(current).decode("ascii")
                    all_strings.append(StringReference(value=s, dex_file=dex_name))
                    count += 1
                current = []

        if len(current) >= min_length and count < _MAX_STRINGS:
            s = bytes(current).decode("ascii")
            all_strings.append(StringReference(value=s, dex_file=dex_name))


def _normalize_operand(op: tuple[Any, ...]) -> tuple[Any, ...]:
    """Normalize a single Androguard instruction operand.

    Androguard represents a pool reference (method/field/type/string/...) as
    a 3-tuple ``(kind_tag, raw_pool_index, resolved_symbol)`` where
    ``resolved_symbol`` is already a fully-qualified symbolic identity (e.g.
    ``"Lcom/example/Foo;->bar(I)V"`` for a method, or the literal string
    content for a string reference) produced by Androguard's own class
    manager. That resolved symbol -- not the raw pool index -- is what we
    hash, since the raw index shifts whenever the DEX's string/type/method/
    field tables are reordered by an unrelated edit (e.g. adding or removing
    a class), while the resolved symbol does not.

    Register operands, literals, raw byte payloads, and branch offsets are
    already table-index-independent and are preserved as-is.
    """
    from androguard.core.dex import Operand

    tag = op[0]
    if tag == Operand.REGISTER:
        return ("reg", op[1])
    if tag == Operand.LITERAL:
        return ("lit", op[1])
    if tag == Operand.OFFSET:
        return ("off", op[1])
    if tag == Operand.RAW:
        return ("raw", op[1])

    # tag is Operand.KIND + Kind.<X> for a pool reference.
    kind_value = int(tag) - int(Operand.KIND)
    resolved = op[2] if len(op) > 2 else None
    if resolved is not None:
        return ("sym", kind_value, resolved)

    # Documented fallback: a small number of Kind values (METH_PROTO,
    # CALL_SITE, VARIES, and the odex-only INLINE_METHOD/VTABLE_OFFSET/
    # FIELD_OFFSET kinds) are not resolved to a symbolic name by Androguard's
    # get_kind(). These are rare in standard (non-odex) classes.dex files
    # (invoke-polymorphic / invoke-custom call sites, primarily). For these
    # only, we fall back to the raw pool index, which is NOT table-index
    # stable -- a documented, narrow limitation rather than a fabricated
    # identity.
    raw_index = op[1] if len(op) > 1 else None
    return ("sym_unresolved", kind_value, raw_index)


def _normalize_instruction(ins: Any) -> tuple[Any, ...]:  # noqa: ANN401 - untyped Androguard instruction
    """Build a deterministic, symbol-resolved representation of one instruction.

    Preserves opcode/instruction identity (the mnemonic), register operands,
    literals, branch targets (already relative, so unaffected by table
    shifts), and resolved string/method/type/field references. Two
    instructions with the same mnemonic and normalized operands are
    considered identical; any genuine difference in opcode, constants,
    references, or branch structure changes the result.
    """
    from androguard.core.dex import FillArrayData, PackedSwitch, SparseSwitch

    name = ins.get_name()

    # packed-switch/sparse-switch/fill-array-data payloads are pseudo-
    # instructions (not Instruction subclasses) carrying inline literal
    # data; they have no pool references to normalize, so we hash their
    # literal content directly via their dedicated accessors.
    if isinstance(ins, PackedSwitch):
        return (name, tuple(ins.get_keys()), tuple(ins.get_targets()))
    if isinstance(ins, SparseSwitch):
        return (name, tuple(ins.get_keys()), tuple(ins.get_targets()))
    if isinstance(ins, FillArrayData):
        return (name, ins.get_data().hex())

    try:
        operands = ins.get_operands(0) or []
        return (name, tuple(_normalize_operand(o) for o in operands))
    except Exception:
        # Documented fallback for any operand shape not handled above: use
        # the textual disassembly. Still opcode-aware and still distinguishes
        # genuinely different instructions, but may retain a raw pool index
        # for exotic/unsupported operand encodings.
        return (name, "fallback_output", ins.get_output(0))


def _build_address_index(instructions: list[Any]) -> dict[int, int]:
    """Map each instruction's bytecode address to its ordinal position.

    DEX addresses are counted in 16-bit code units; ``get_length()`` reports
    bytes. The resulting map lets exception-handler addresses be expressed as
    instruction ordinals, which stay stable when an unrelated instruction
    elsewhere in the method is re-encoded at a different width.
    """
    mapping: dict[int, int] = {}
    addr = 0
    for index, ins in enumerate(instructions):
        mapping[addr] = index
        addr += ins.get_length() // 2
    return mapping


def _resolve_handler_target(
    addr: int, addr_index: dict[int, int], total: int
) -> int | tuple[str, int]:
    """Express a handler/try bytecode address as a semantic instruction ordinal.

    Returns the ordinal of the instruction at *addr*. ``total`` (one past the
    last ordinal) is returned for an address exactly at the end of the code,
    which is how an end-exclusive try range is expressed. Documented
    fallback: an address that does not land on an instruction boundary is
    represented as ``("raw_addr", addr)`` -- deterministic, but not
    re-encoding-stable; this should not occur for well-formed DEX input.
    """
    if addr in addr_index:
        return addr_index[addr]
    if addr == 0 and total == 0:
        return 0
    return ("raw_addr", addr)


def _normalize_exception_handlers(
    code: Any,  # noqa: ANN401 - untyped Androguard code item
    instructions: list[Any],
) -> tuple[Any, ...]:
    """Build a deterministic, semantic representation of a method's try/catch structure.

    Each try block becomes::

        (start_ordinal, end_ordinal_exclusive, typed_handlers, catch_all)

    where ``typed_handlers`` is a tuple of
    ``(resolved_exception_type, handler_ordinal)`` pairs **in DEX order**
    (order is semantically significant -- the runtime tests caught types in
    sequence, so reordering them changes behaviour and must change the hash),
    and ``catch_all`` is the catch-all handler's ordinal or ``None``.

    Deliberately excluded: the raw ``handler_off`` byte offsets into the
    encoded-catch-handler list and the absolute file offsets used to join
    tries to handlers. Those are unstable binary-layout artifacts. What is
    kept is semantic: which instruction range is protected, which exception
    types are caught in which order, and which instruction each handler
    jumps to -- all expressed as resolved type descriptors and instruction
    ordinals rather than pool indexes or byte addresses.

    Returns an empty tuple for methods with no try blocks, and the documented
    marker ``(("unavailable",),)`` if the structure is present but cannot be
    decoded (so an undecodable handler table is never silently treated as
    "no handlers").
    """
    try:
        tries_size = code.get_tries_size()
    except Exception:
        return (("unavailable",),)

    if not tries_size:
        return ()

    try:
        tries = list(code.get_tries())
        handler_list = code.get_handlers()
        handlers = list(handler_list.get_list())
        list_base_off = handler_list.get_off()
        class_manager = code.CM
    except Exception:
        return (("unavailable",),)

    # Join each try block to its handler via offsets, then discard the
    # offsets -- they are layout, not semantics.
    by_offset: dict[int, Any] = {}
    for handler in handlers:
        try:
            by_offset[handler.get_off()] = handler
        except Exception as exc:
            _log.debug("Skipping undecodable exception handler: %s", exc)

    addr_index = _build_address_index(instructions)
    total = len(instructions)
    normalized: list[tuple[Any, ...]] = []

    for try_item in tries:
        try:
            start_addr = try_item.get_start_addr()
            insn_count = try_item.get_insn_count()
            handler = by_offset.get(list_base_off + try_item.get_handler_off())
        except Exception:
            normalized.append(("unavailable",))
            continue

        start_ord = _resolve_handler_target(start_addr, addr_index, total)
        end_ord = _resolve_handler_target(start_addr + insn_count, addr_index, total)

        typed: list[tuple[Any, ...]] = []
        catch_all: int | tuple[str, int] | None = None
        if handler is not None:
            try:
                for pair in handler.get_handlers():
                    type_name = class_manager.get_type(pair.get_type_idx())
                    typed.append(
                        (
                            type_name,
                            _resolve_handler_target(pair.get_addr(), addr_index, total),
                        )
                    )
                # catch_all_addr exists only when the encoded size is non-positive.
                if handler.get_size() <= 0:
                    catch_all = _resolve_handler_target(
                        handler.get_catch_all_addr(), addr_index, total
                    )
            except Exception:
                typed.append(("unavailable", None))

        normalized.append((start_ord, end_ord, tuple(typed), catch_all))

    # Try blocks are required by the DEX spec to be sorted by start address
    # and non-overlapping; sort defensively so the representation is
    # order-independent with respect to the parser's iteration order.
    return tuple(sorted(_coalesce_adjacent_tries(normalized), key=repr))


def _coalesce_adjacent_tries(blocks: list[tuple[Any, ...]]) -> list[tuple[Any, ...]]:
    """Merge try blocks that abut and have identical handlers into one block.

    ``[a, b) -> H`` followed by ``[b, c) -> H`` protects exactly the same instructions
    with exactly the same handlers as ``[a, c) -> H``; smali/Apktool 3 emits the merged
    form on reassembly (observed on AppManager 451 in the C.5 no-op baseline). Only
    blocks whose bounds resolved to plain instruction ordinals are merged; anything
    unresolved is kept verbatim so it can never be hidden.
    """
    resolved = [
        b for b in blocks if len(b) == 4 and isinstance(b[0], int) and isinstance(b[1], int)
    ]
    others = [b for b in blocks if b not in resolved]
    merged: list[tuple[Any, ...]] = []
    for block in sorted(resolved, key=lambda b: (b[0], b[1])):
        if merged and merged[-1][1] == block[0] and merged[-1][2:] == block[2:]:
            merged[-1] = (merged[-1][0], block[1], *block[2:])
        else:
            merged.append(block)
    return merged + others


def _hash_method_code(code: Any) -> str | None:  # noqa: ANN401 - untyped Androguard code item
    """Compute a SHA-256 hash of a method's normalized instruction stream.

    This replaces hashing the method's raw instruction bytes. Raw-byte
    hashing is not robust: DEX instructions reference the string/type/
    method/field pools by numeric index, and those indexes shift whenever
    an unrelated class or method is added or removed elsewhere in the DEX
    (table-index drift), making every method whose encoding touches a
    shifted index appear "changed" even though nothing about it actually
    changed.

    Instead, each instruction is normalized (see ``_normalize_instruction``)
    into a form where pool references are replaced by their resolved
    symbolic identity, then the full ordered sequence is hashed.

    The hash also covers the method's exception-handler structure (see
    ``_normalize_exception_handlers``), so a change to a try/catch range,
    a caught exception type, the order in which types are tested, or a
    handler target is detected even when every instruction is byte-for-byte
    identical.

    Returns ``None`` for methods with no code (abstract, native, and
    interface method declarations) or if the instruction stream cannot be
    decoded.
    """
    try:
        bc = code.get_bc() if hasattr(code, "get_bc") else None
        if bc is None:
            return None
        instructions = list(bc.get_instructions())
    except Exception:
        return None

    try:
        parts = [repr(_normalize_instruction(ins)) for ins in instructions]
    except Exception:
        return None

    parts.append(repr(("exception_handlers", _normalize_exception_handlers(code, instructions))))

    digest_input = "\n".join(parts).encode("utf-8", errors="surrogateescape")
    return hashlib.sha256(digest_input).hexdigest()


def _parse_params(param_str: str) -> list[str]:
    """Parse a DEX parameter descriptor string into individual types.

    Accepts both the compact smali form (``IJLjava/lang/String;``) and androguard's
    ``get_descriptor()`` form, which separates parameter types with spaces
    (``I J Ljava/lang/String;``). Whitespace is never a type: treating it as one produced
    keys like ``f(int, ,long)V`` for multi-parameter methods.
    """
    params: list[str] = []
    i = 0
    while i < len(param_str):
        if param_str[i].isspace():
            i += 1
        elif param_str[i] == "L":
            end = param_str.index(";", i)
            params.append(param_str[i : end + 1])
            i = end + 1
        elif param_str[i] == "[":
            # Array — find the element type
            j = i + 1
            while j < len(param_str) and param_str[j] == "[":
                j += 1
            if j < len(param_str) and param_str[j] == "L":
                end = param_str.index(";", j)
                params.append(param_str[i : end + 1])
                i = end + 1
            elif j < len(param_str):
                params.append(param_str[i : j + 1])
                i = j + 1
            else:
                i = j
        else:
            # Primitive type
            _prim_map = {
                "V": "void",
                "Z": "boolean",
                "B": "byte",
                "S": "short",
                "C": "char",
                "I": "int",
                "J": "long",
                "F": "float",
                "D": "double",
            }
            params.append(_prim_map.get(param_str[i], param_str[i]))
            i += 1
    return params
