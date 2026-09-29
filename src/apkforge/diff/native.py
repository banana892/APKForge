"""Native differ — compares native shared libraries, ABIs, and symbols."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import ChangeType, NativeDiff, NativeLibraryDiff

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult, NativeLibraryInspection

__all__ = ["NativeDiffer"]


class NativeDiffer:
    """Compares ELF shared libraries (.so) and architecture ABIs."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> NativeDiff:
        """Execute native library comparison between Inspection A and Inspection B."""
        nat_a = insp_a.native
        nat_b = insp_b.native

        libs_a: dict[str, NativeLibraryInspection] = {
            lib.path: lib for lib in (nat_a.libraries if nat_a else [])
        }
        libs_b: dict[str, NativeLibraryInspection] = {
            lib.path: lib for lib in (nat_b.libraries if nat_b else [])
        }

        paths_a = set(libs_a.keys())
        paths_b = set(libs_b.keys())
        all_paths = sorted(paths_a | paths_b)

        added: list[NativeLibraryDiff] = []
        removed: list[NativeLibraryDiff] = []
        modified: list[NativeLibraryDiff] = []
        unchanged: list[str] = []

        for p in all_paths:
            if p in libs_b and p not in libs_a:
                b = libs_b[p]
                added.append(
                    NativeLibraryDiff(
                        path=p,
                        abi=b.abi,
                        change_type=ChangeType.ADDED,
                        size_after=b.size,
                        sha256_after=b.sha256,
                        elf_class_after=b.elf_class,
                        machine_after=b.machine_type,
                        symbols_exported_added=sorted(b.exported_symbols),
                        symbols_imported_added=sorted(b.imported_symbols),
                    )
                )
            elif p in libs_a and p not in libs_b:
                a = libs_a[p]
                removed.append(
                    NativeLibraryDiff(
                        path=p,
                        abi=a.abi,
                        change_type=ChangeType.REMOVED,
                        size_before=a.size,
                        sha256_before=a.sha256,
                        elf_class_before=a.elf_class,
                        machine_before=a.machine_type,
                        symbols_exported_removed=sorted(a.exported_symbols),
                        symbols_imported_removed=sorted(a.imported_symbols),
                    )
                )
            else:
                a = libs_a[p]
                b = libs_b[p]

                exp_a = set(a.exported_symbols)
                exp_b = set(b.exported_symbols)
                imp_a = set(a.imported_symbols)
                imp_b = set(b.imported_symbols)

                exp_added = sorted(exp_b - exp_a)
                exp_removed = sorted(exp_a - exp_b)
                imp_added = sorted(imp_b - imp_a)
                imp_removed = sorted(imp_a - imp_b)

                is_mod = (
                    a.sha256 != b.sha256
                    or a.size != b.size
                    or a.elf_class != b.elf_class
                    or a.machine_type != b.machine_type
                    or bool(exp_added or exp_removed or imp_added or imp_removed)
                )

                if is_mod:
                    modified.append(
                        NativeLibraryDiff(
                            path=p,
                            abi=b.abi,
                            change_type=ChangeType.MODIFIED,
                            size_before=a.size,
                            size_after=b.size,
                            sha256_before=a.sha256,
                            sha256_after=b.sha256,
                            elf_class_before=a.elf_class,
                            elf_class_after=b.elf_class,
                            machine_before=a.machine_type,
                            machine_after=b.machine_type,
                            symbols_exported_added=exp_added,
                            symbols_exported_removed=exp_removed,
                            symbols_imported_added=imp_added,
                            symbols_imported_removed=imp_removed,
                        )
                    )
                else:
                    unchanged.append(p)

        abis_a = set(nat_a.abis_found if nat_a else [])
        abis_b = set(nat_b.abis_found if nat_b else [])

        return NativeDiff(
            libraries_added=added,
            libraries_removed=removed,
            libraries_modified=modified,
            libraries_unchanged=unchanged,
            abis_added=sorted(abis_b - abis_a),
            abis_removed=sorted(abis_a - abis_b),
        )
