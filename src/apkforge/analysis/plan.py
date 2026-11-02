"""Analysis-driven modification planning: Inspection -> Privacy -> (Diff) -> Security ->
ModificationPlanner, as one call.

Shared by ``apkforge plan``, ``apkforge modify`` (without ``--plan``) and the Phase 9 GUI.
Only inspection is required: privacy, diff and security failures are logged and the plan
is built from what is available, as the CLI always did.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.inspection import InspectionEngine
from apkforge.modification import ModificationPlanner
from apkforge.privacy.engine import PrivacyEngine
from apkforge.security.engine import SecurityEngine

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.core.config import APKForgeConfig
    from apkforge.diff.models import DiffResult
    from apkforge.modification.models import ModificationPlan
    from apkforge.privacy.models import PrivacyResult
    from apkforge.security.models import SecurityResult

__all__ = ["create_modification_plan"]

_log = logging.getLogger(__name__)


def create_modification_plan(
    apk: Path,
    cfg: APKForgeConfig,
    *,
    diff_apk: Path | None = None,
    keep_workspace: bool = False,
) -> ModificationPlan:
    """Plan for *apk*; *diff_apk* (the original it was derived from) adds diff evidence.

    Raises whatever inspection raises; nothing is modified.
    """
    insp_engine = InspectionEngine(config=cfg)
    insp_result = insp_engine.inspect(apk, keep_workspace=keep_workspace)

    priv_result: PrivacyResult | None = None
    try:
        priv_result = PrivacyEngine(config=cfg).analyze(insp_result, keep_workspace=keep_workspace)
    except Exception as e:
        _log.warning("Privacy engine failed during planning: %s", e)

    diff_result: DiffResult | None = None
    if diff_apk:
        try:
            from apkforge.diff.engine import DiffEngine

            orig_insp = insp_engine.inspect(diff_apk, keep_workspace=keep_workspace)
            diff_result = DiffEngine(config=cfg).diff(
                orig_insp, insp_result, keep_workspace=keep_workspace
            )
        except Exception as e:
            _log.warning("Diff engine failed during planning: %s", e)

    sec_result: SecurityResult | None = None
    try:
        sec_result = SecurityEngine(config=cfg).analyze(
            target=insp_result,
            privacy=priv_result,
            diff=diff_result,
            keep_workspace=keep_workspace,
        )
    except Exception as e:
        _log.warning("Security engine failed during planning: %s", e)

    return ModificationPlanner().create_plan(
        apk_path=apk,
        inspection=insp_result,
        privacy=priv_result,
        security=sec_result,
        diff=diff_result,
    )
