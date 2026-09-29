"""DEX inspector — structural inspection of Dalvik Executable files.

Extracts class inventory, method/field information, API references, and
strings from all DEX files inside the APK.

Does NOT decompile the application, generate Java source code, or attempt
full reverse engineering.  The objective is a structured inventory.

Security invariant: DEX code is never executed.
"""

from __future__ import annotations

import contextlib
import re
import struct
import zipfile
from typing import TYPE_CHECKING

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
                    interfaces = [_dalvik_to_java(str(i)) for i in ifaces]

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

                methods.append(
                    MethodInfo(
                        name=m_name,
                        class_name=m_class,
                        return_type=m_return,
                        parameters=m_params,
                        access_flags=m_flags,
                    )
                )

                # API references from method code
                with contextlib.suppress(Exception):
                    code = method.get_code()
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
                s_val = str(s)
                if len(s_val) >= 4 and s_val.isprintable():  # Filter noise
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


def _parse_params(param_str: str) -> list[str]:
    """Parse a DEX parameter descriptor string into individual types."""
    params: list[str] = []
    i = 0
    while i < len(param_str):
        if param_str[i] == "L":
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
