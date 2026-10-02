"""DEX differ — compares DEX files, classes, methods, fields, and API references."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import (
    ChangeType,
    ClassDiff,
    DEXDiff,
    FieldDiff,
    MethodDiff,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import (
        ClassInfo,
        FieldInfo,
        InspectionResult,
        MethodInfo,
    )

__all__ = ["DEXDiffer"]


class DEXDiffer:
    """Compares Dalvik Executable bytecode structures."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> DEXDiff:
        """Execute DEX comparison between Inspection A and Inspection B."""
        dex_a = insp_a.dex
        dex_b = insp_b.dex

        # 1. Compare DEX files
        files_a = {df.path: df for df in (dex_a.dex_files if dex_a else [])}
        files_b = {df.path: df for df in (dex_b.dex_files if dex_b else [])}

        all_file_names = sorted(set(files_a.keys()) | set(files_b.keys()))
        dex_added: list[str] = []
        dex_removed: list[str] = []
        dex_modified: list[str] = []
        dex_unchanged: list[str] = []

        for fn in all_file_names:
            if fn in files_b and fn not in files_a:
                dex_added.append(fn)
            elif fn in files_a and fn not in files_b:
                dex_removed.append(fn)
            else:
                fa = files_a[fn]
                fb = files_b[fn]
                is_diff = (fa.sha256 and fb.sha256 and fa.sha256 != fb.sha256) or fa.size != fb.size
                if is_diff:
                    dex_modified.append(fn)
                else:
                    dex_unchanged.append(fn)

        # 2. Compare Classes & Methods & Fields
        classes_a: dict[str, ClassInfo] = {}
        methods_a: dict[str, list[MethodInfo]] = {}
        fields_a: dict[str, list[FieldInfo]] = {}
        apis_a: set[str] = set()
        if dex_a:
            for df in dex_a.dex_files:
                if df.inventory:
                    for c in df.inventory.classes:
                        classes_a[c.name] = c
                    for m in df.inventory.methods:
                        methods_a.setdefault(m.class_name, []).append(m)
                    for f in df.inventory.fields:
                        fields_a.setdefault(f.class_name, []).append(f)
                if df.api_references:
                    apis_a.update(df.api_references)

        classes_b: dict[str, ClassInfo] = {}
        methods_b: dict[str, list[MethodInfo]] = {}
        fields_b: dict[str, list[FieldInfo]] = {}
        apis_b: set[str] = set()
        if dex_b:
            for df in dex_b.dex_files:
                if df.inventory:
                    for c in df.inventory.classes:
                        classes_b[c.name] = c
                    for m in df.inventory.methods:
                        methods_b.setdefault(m.class_name, []).append(m)
                    for f in df.inventory.fields:
                        fields_b.setdefault(f.class_name, []).append(f)
                if df.api_references:
                    apis_b.update(df.api_references)

        all_class_names = sorted(set(classes_a.keys()) | set(classes_b.keys()))

        classes_added: list[str] = []
        classes_removed: list[str] = []
        classes_modified: list[ClassDiff] = []
        classes_unchanged_count = 0

        for cn in all_class_names:
            if cn in classes_b and cn not in classes_a:
                classes_added.append(cn)
            elif cn in classes_a and cn not in classes_b:
                classes_removed.append(cn)
            else:
                # Class in both: compare superclass, methods, and fields
                ca = classes_a[cn]
                cb = classes_b[cn]

                super_changed = ca.superclass != cb.superclass
                m_diffs, m_added, m_removed = self._diff_methods(
                    cn, methods_a.get(cn, []), methods_b.get(cn, [])
                )
                f_diffs, f_added, f_removed = self._diff_fields(
                    cn, fields_a.get(cn, []), fields_b.get(cn, [])
                )

                has_class_diff = bool(
                    super_changed
                    or m_diffs
                    or m_added
                    or m_removed
                    or f_diffs
                    or f_added
                    or f_removed
                )
                if has_class_diff:
                    classes_modified.append(
                        ClassDiff(
                            class_name=cn,
                            change_type=ChangeType.MODIFIED,
                            superclass_before=ca.superclass if super_changed else None,
                            superclass_after=cb.superclass if super_changed else None,
                            methods_added=m_added,
                            methods_removed=m_removed,
                            methods_modified=m_diffs,
                            fields_added=f_added,
                            fields_removed=f_removed,
                            fields_modified=f_diffs,
                        )
                    )
                else:
                    classes_unchanged_count += 1

        # 3. Framework API references
        apis_added = sorted(apis_b - apis_a)
        apis_removed = sorted(apis_a - apis_b)

        return DEXDiff(
            dex_files_added=dex_added,
            dex_files_removed=dex_removed,
            dex_files_modified=dex_modified,
            dex_files_unchanged=dex_unchanged,
            classes_added=classes_added,
            classes_removed=classes_removed,
            classes_modified=classes_modified,
            classes_unchanged_count=classes_unchanged_count,
            api_references_added=apis_added,
            api_references_removed=apis_removed,
        )

    def _diff_methods(
        self,
        class_name: str,
        methods_a: list[MethodInfo],
        methods_b: list[MethodInfo],
    ) -> tuple[list[MethodDiff], list[str], list[str]]:
        def _mkey(m: MethodInfo) -> str:
            params = ",".join(m.parameters)
            return f"{m.name}({params}){m.return_type}"

        map_a = {_mkey(m): m for m in methods_a}
        map_b = {_mkey(m): m for m in methods_b}

        keys_a = set(map_a.keys())
        keys_b = set(map_b.keys())

        added = sorted(keys_b - keys_a)
        removed = sorted(keys_a - keys_b)
        common = sorted(keys_a & keys_b)

        modified: list[MethodDiff] = []
        for k in common:
            ma = map_a[k]
            mb = map_b[k]
            access_changed = ma.access_flags != mb.access_flags
            code_changed = ma.code_hash != mb.code_hash
            if access_changed or code_changed:
                modified.append(
                    MethodDiff(
                        class_name=class_name,
                        method_name=ma.name,
                        change_type=ChangeType.MODIFIED,
                        return_type_before=ma.return_type,
                        return_type_after=mb.return_type,
                        parameters_before=ma.parameters,
                        parameters_after=mb.parameters,
                        access_flags_before=ma.access_flags,
                        access_flags_after=mb.access_flags,
                        code_hash_before=ma.code_hash,
                        code_hash_after=mb.code_hash,
                        code_changed=code_changed,
                    )
                )

        return modified, added, removed

    def _diff_fields(
        self,
        class_name: str,
        fields_a: list[FieldInfo],
        fields_b: list[FieldInfo],
    ) -> tuple[list[FieldDiff], list[str], list[str]]:
        map_a = {f.name: f for f in fields_a}
        map_b = {f.name: f for f in fields_b}

        keys_a = set(map_a.keys())
        keys_b = set(map_b.keys())

        added = sorted(keys_b - keys_a)
        removed = sorted(keys_a - keys_b)
        common = sorted(keys_a & keys_b)

        modified: list[FieldDiff] = []
        for k in common:
            fa = map_a[k]
            fb = map_b[k]
            if fa.type != fb.type or fa.access_flags != fb.access_flags:
                modified.append(
                    FieldDiff(
                        class_name=class_name,
                        field_name=k,
                        change_type=ChangeType.MODIFIED,
                        type_before=fa.type,
                        type_after=fb.type,
                        access_flags_before=fa.access_flags,
                        access_flags_after=fb.access_flags,
                    )
                )

        return modified, added, removed
