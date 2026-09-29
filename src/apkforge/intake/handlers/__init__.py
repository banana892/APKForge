"""Intake package handlers."""

from __future__ import annotations

from apkforge.intake.handlers.apk import SingleAPKHandler
from apkforge.intake.handlers.apks import APKSHandler
from apkforge.intake.handlers.base import (
    BasePackageHandler,
    classify_split_type,
    inspect_single_apk,
)
from apkforge.intake.handlers.split import SplitAPKHandler
from apkforge.intake.handlers.xapk import XAPKHandler

__all__ = [
    "APKSHandler",
    "BasePackageHandler",
    "SingleAPKHandler",
    "SplitAPKHandler",
    "XAPKHandler",
    "classify_split_type",
    "inspect_single_apk",
]
