"""Serialization and deserialization utilities for ModificationPlan."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from apkforge.modification.models import ModificationPlan


def plan_to_json(plan: ModificationPlan, indent: int = 2) -> str:
    """Serialize a ModificationPlan to a formatted JSON string."""
    return json.dumps(plan.to_serializable_dict(), indent=indent)


def plan_from_json(json_str: str) -> ModificationPlan:
    """Deserialize a ModificationPlan from a JSON string."""
    data = json.loads(json_str)
    return ModificationPlan.model_validate(data)


def plan_to_yaml(plan: ModificationPlan) -> str:
    """Serialize a ModificationPlan to a clean YAML string."""
    return yaml.safe_dump(plan.to_serializable_dict(), sort_keys=False)


def plan_from_yaml(yaml_str: str) -> ModificationPlan:
    """Deserialize a ModificationPlan from a YAML string."""
    data = yaml.safe_load(yaml_str)
    return ModificationPlan.model_validate(data)


def save_plan(plan: ModificationPlan, file_path: Path | str) -> None:
    """Write plan to file in JSON or YAML format based on extension."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() in (".yaml", ".yml"):
        path.write_text(plan_to_yaml(plan), encoding="utf-8")
    else:
        path.write_text(plan_to_json(plan), encoding="utf-8")


def load_plan(file_path: Path | str) -> ModificationPlan:
    """Load a ModificationPlan from a JSON or YAML file."""
    path = Path(file_path)
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        return plan_from_yaml(content)
    return plan_from_json(content)
