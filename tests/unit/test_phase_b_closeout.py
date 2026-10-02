"""Regression tests for the Phase B close-out.

Covers:
1. DEX exception-handler normalization: a method whose instructions are
   byte-for-byte identical but whose try/catch structure changed must be
   detected; semantic identities (resolved exception types, instruction
   ordinals) are used rather than binary table offsets.
2. Component `android:process` inspection, modelling, and semantic diffing.
"""

from __future__ import annotations

import pytest
from androguard.core.dex import Operand

from apkforge.diff.components import ComponentDiffer
from apkforge.diff.models import ChangeType
from apkforge.inspection.dex import (
    _hash_method_code,
    _normalize_exception_handlers,
)
from apkforge.inspection.models import (
    ActivityInfo,
    BroadcastReceiverInfo,
    ContentProviderInfo,
    InspectionResult,
    ManifestInspection,
    ServiceInfo,
)

# ---------------------------------------------------------------------------
# Fakes mirroring Androguard's code-item / try-catch surfaces.
# ---------------------------------------------------------------------------


class _FakeInstruction:
    """One instruction. ``length`` is in bytes (addresses are code units)."""

    def __init__(self, name: str, operands: list[tuple] | None = None, length: int = 2) -> None:
        self._name = name
        self._operands = operands or []
        self._length = length

    def get_name(self) -> str:
        return self._name

    def get_operands(self, idx: int = 0) -> list[tuple]:
        return self._operands

    def get_output(self, idx: int = 0) -> str:
        return self._name

    def get_length(self) -> int:
        return self._length


class _FakeTryItem:
    def __init__(self, start_addr: int, insn_count: int, handler_off: int) -> None:
        self._start = start_addr
        self._count = insn_count
        self._handler_off = handler_off

    def get_start_addr(self) -> int:
        return self._start

    def get_insn_count(self) -> int:
        return self._count

    def get_handler_off(self) -> int:
        return self._handler_off


class _FakeTypeAddrPair:
    def __init__(self, type_idx: int, addr: int) -> None:
        self._type_idx = type_idx
        self._addr = addr

    def get_type_idx(self) -> int:
        return self._type_idx

    def get_addr(self) -> int:
        return self._addr


class _FakeCatchHandler:
    def __init__(self, off: int, pairs: list[_FakeTypeAddrPair], catch_all: int | None = None) -> None:
        self._off = off
        self._pairs = pairs
        self._catch_all = catch_all

    def get_off(self) -> int:
        return self._off

    def get_size(self) -> int:
        # DEX encoding: positive size == typed handlers only; non-positive
        # size == typed handlers plus a catch-all.
        return len(self._pairs) if self._catch_all is None else -len(self._pairs)

    def get_handlers(self) -> list[_FakeTypeAddrPair]:
        return self._pairs

    def get_catch_all_addr(self) -> int:
        assert self._catch_all is not None
        return self._catch_all


class _FakeHandlerList:
    def __init__(self, off: int, handlers: list[_FakeCatchHandler]) -> None:
        self._off = off
        self._handlers = handlers

    def get_off(self) -> int:
        return self._off

    def get_list(self) -> list[_FakeCatchHandler]:
        return self._handlers


class _FakeClassManager:
    """Resolves type-pool indexes to descriptors, as Androguard's does."""

    def __init__(self, types: dict[int, str]) -> None:
        self._types = types

    def get_type(self, idx: int) -> str:
        return self._types[idx]


class _FakeBC:
    def __init__(self, instructions: list) -> None:
        self._instructions = instructions

    def get_instructions(self) -> list:
        return self._instructions


class _FakeCode:
    """A code item with an optional try/catch structure."""

    def __init__(
        self,
        instructions: list,
        tries: list[_FakeTryItem] | None = None,
        handler_list: _FakeHandlerList | None = None,
        types: dict[int, str] | None = None,
    ) -> None:
        self._bc = _FakeBC(instructions)
        self._tries = tries or []
        self._handler_list = handler_list
        self.CM = _FakeClassManager(types or {})

    def get_bc(self) -> _FakeBC:
        return self._bc

    def get_tries_size(self) -> int:
        return len(self._tries)

    def get_tries(self) -> list[_FakeTryItem]:
        return self._tries

    def get_handlers(self) -> _FakeHandlerList | None:
        return self._handler_list


_KIND_METH = 256

# A fixed, shared instruction body: every handler test below keeps these
# instructions byte-for-byte identical and varies only the try/catch data.
def _body() -> list[_FakeInstruction]:
    return [
        _FakeInstruction("invoke-virtual", [(Operand.REGISTER, 0), (_KIND_METH, 7, "Lcom/x/Y;->z()V")]),
        _FakeInstruction("move-result-object", [(Operand.REGISTER, 1)]),
        _FakeInstruction("return-void"),
        _FakeInstruction("move-exception", [(Operand.REGISTER, 2)]),
        _FakeInstruction("return-void"),
    ]


def _code(
    tries: list[_FakeTryItem] | None = None,
    handlers: list[_FakeCatchHandler] | None = None,
    types: dict[int, str] | None = None,
) -> _FakeCode:
    handler_list = _FakeHandlerList(1000, handlers) if handlers is not None else None
    return _FakeCode(_body(), tries=tries, handler_list=handler_list, types=types)


_IO = {5: "Ljava/io/IOException;", 6: "Ljava/lang/IllegalStateException;"}


# ---------------------------------------------------------------------------
# 1. Exception-handler normalization
# ---------------------------------------------------------------------------


class TestExceptionHandlerNormalization:
    # C.5 no-op baseline: smali (Apktool 3) merges abutting try ranges that share a handler.
    def test_split_adjacent_tries_with_same_handler_equal_merged(self) -> None:
        merged = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        split = _code(
            tries=[_FakeTryItem(0, 1, 1), _FakeTryItem(1, 2, 5)],
            handlers=[
                _FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)]),
                _FakeCatchHandler(1005, [_FakeTypeAddrPair(5, 3)]),
            ],
            types=_IO,
        )
        assert _hash_method_code(split) == _hash_method_code(merged)

    def test_adjacent_tries_with_different_handlers_not_merged(self) -> None:
        merged = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        split = _code(
            tries=[_FakeTryItem(0, 1, 1), _FakeTryItem(1, 2, 5)],
            handlers=[
                _FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)]),
                _FakeCatchHandler(1005, [_FakeTypeAddrPair(6, 3)]),
            ],
            types=_IO,
        )
        assert _hash_method_code(split) != _hash_method_code(merged)

    def test_tries_with_gap_not_merged(self) -> None:
        merged = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        gapped = _code(
            tries=[_FakeTryItem(0, 1, 1), _FakeTryItem(2, 1, 5)],
            handlers=[
                _FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)]),
                _FakeCatchHandler(1005, [_FakeTypeAddrPair(5, 3)]),
            ],
            types=_IO,
        )
        assert _hash_method_code(gapped) != _hash_method_code(merged)

    def test_identical_handlers_produce_identical_hash(self) -> None:
        """Same instructions + same try/catch == same hash (no false positive)."""

        def build() -> _FakeCode:
            return _code(
                tries=[_FakeTryItem(0, 3, 1)],
                handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
                types=_IO,
            )

        assert _hash_method_code(build()) == _hash_method_code(build())

    def test_handler_only_change_is_detected(self) -> None:
        """Instructions unchanged, a try/catch block added -> hash must change.

        This is the core acceptance condition for the close-out: an
        exception-handler-only modification must not be invisible to the
        verifier.
        """
        without = _code(tries=[], handlers=[])
        with_handler = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        # The instruction streams are identical by construction.
        assert [i.get_name() for i in _body()] == [i.get_name() for i in _body()]
        assert _hash_method_code(without) != _hash_method_code(with_handler)

    def test_caught_exception_type_change_is_detected(self) -> None:
        """Same range and target, different caught type -> hash must change."""
        a = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        b = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(6, 3)])],
            types=_IO,
        )
        assert _hash_method_code(a) != _hash_method_code(b)

    def test_handler_target_change_is_detected(self) -> None:
        """Same caught type, different handler target instruction -> detected."""
        a = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        b = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 4)])],
            types=_IO,
        )
        assert _hash_method_code(a) != _hash_method_code(b)

    def test_protected_range_change_is_detected(self) -> None:
        """Widening the protected instruction range -> detected."""
        a = _code(
            tries=[_FakeTryItem(0, 2, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        b = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        assert _hash_method_code(a) != _hash_method_code(b)

    def test_catch_type_order_change_is_detected(self) -> None:
        """Caught types are tested in order, so reordering changes behaviour."""
        a = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[
                _FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3), _FakeTypeAddrPair(6, 4)])
            ],
            types=_IO,
        )
        b = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[
                _FakeCatchHandler(1001, [_FakeTypeAddrPair(6, 4), _FakeTypeAddrPair(5, 3)])
            ],
            types=_IO,
        )
        assert _hash_method_code(a) != _hash_method_code(b)

    def test_catch_all_addition_is_detected(self) -> None:
        """Adding a catch-all handler to an otherwise identical block -> detected."""
        a = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)])],
            types=_IO,
        )
        b = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)], catch_all=4)],
            types=_IO,
        )
        assert _hash_method_code(a) != _hash_method_code(b)

    def test_representation_uses_semantic_identities_not_offsets(self) -> None:
        """Handlers are expressed as resolved types + instruction ordinals."""
        code = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 3)], catch_all=4)],
            types=_IO,
        )
        rep = _normalize_exception_handlers(code, _body())
        # One try block: instructions 0..3 protected, IOException -> ordinal 3,
        # catch-all -> ordinal 4. Addresses (6, 8 code units) became ordinals.
        assert rep == ((0, 3, (("Ljava/io/IOException;", 3),), 4),)
        # The raw handler_off (1) and absolute list offset (1000/1001) must not
        # appear anywhere in the hashed representation.
        assert "1000" not in repr(rep)
        assert "1001" not in repr(rep)

    def test_address_off_instruction_boundary_uses_documented_fallback(self) -> None:
        """An address that lands on no instruction uses the raw_addr fallback.

        The body is 5 single-code-unit instructions (valid addresses 0-4), so
        address 9 cannot be mapped to an ordinal. The fallback must be
        deterministic rather than silently dropped.
        """
        code = _code(
            tries=[_FakeTryItem(0, 3, 1)],
            handlers=[_FakeCatchHandler(1001, [_FakeTypeAddrPair(5, 9)])],
            types=_IO,
        )
        rep = _normalize_exception_handlers(code, _body())
        assert rep == ((0, 3, (("Ljava/io/IOException;", ("raw_addr", 9)),), None),)
        assert _normalize_exception_handlers(code, _body()) == rep

    def test_method_without_try_blocks_is_empty_not_unavailable(self) -> None:
        """No try blocks is represented distinctly from an undecodable table."""
        assert _normalize_exception_handlers(_code(tries=[], handlers=[]), _body()) == ()

    def test_undecodable_handler_table_is_not_silently_empty(self) -> None:
        """A present-but-undecodable handler table must not look like 'no handlers'."""

        class _Broken(_FakeCode):
            def get_tries(self):  # noqa: ANN201
                raise RuntimeError("corrupt handler table")

        broken = _Broken(_body(), tries=[_FakeTryItem(0, 3, 1)], handler_list=None)
        rep = _normalize_exception_handlers(broken, _body())
        assert rep == (("unavailable",),)
        assert rep != ()


# ---------------------------------------------------------------------------
# 2. android:process inspection + diff
# ---------------------------------------------------------------------------


class TestProcessAttributeDiff:
    @pytest.mark.parametrize(
        ("builder", "bucket"),
        [
            (ActivityInfo, "activities"),
            (ServiceInfo, "services"),
            (BroadcastReceiverInfo, "receivers"),
            (ContentProviderInfo, "providers"),
        ],
    )
    def test_process_change_is_detected(self, builder: type, bucket: str) -> None:
        """Moving a component to a different process is a semantic change."""
        a = builder(name="com.example.C", process=None)
        b = builder(name="com.example.C", process=":remote")
        insp_a = InspectionResult(manifest=ManifestInspection(**{bucket: [a]}))
        insp_b = InspectionResult(manifest=ManifestInspection(**{bucket: [b]}))

        diff = ComponentDiffer().diff(insp_a, insp_b)
        change = getattr(diff, bucket)[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.details["process_before"] is None
        assert change.details["process_after"] == ":remote"

    @pytest.mark.parametrize(
        ("builder", "bucket"),
        [
            (ActivityInfo, "activities"),
            (ServiceInfo, "services"),
            (BroadcastReceiverInfo, "receivers"),
            (ContentProviderInfo, "providers"),
        ],
    )
    def test_same_process_is_unchanged(self, builder: type, bucket: str) -> None:
        """An identical process value produces no modification."""
        a = builder(name="com.example.C", process=":remote")
        b = builder(name="com.example.C", process=":remote")
        insp_a = InspectionResult(manifest=ManifestInspection(**{bucket: [a]}))
        insp_b = InspectionResult(manifest=ManifestInspection(**{bucket: [b]}))

        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert getattr(diff, bucket)[0].change_type == ChangeType.UNCHANGED

    def test_process_absent_on_both_sides_is_unchanged(self) -> None:
        """Components with no android:process declared compare equal."""
        insp_a = InspectionResult(
            manifest=ManifestInspection(services=[ServiceInfo(name="com.example.S")])
        )
        insp_b = InspectionResult(
            manifest=ManifestInspection(services=[ServiceInfo(name="com.example.S")])
        )
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.services[0].change_type == ChangeType.UNCHANGED
        assert "process_before" not in diff.services[0].details
