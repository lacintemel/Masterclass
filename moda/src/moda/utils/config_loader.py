from __future__ import annotations

import os
import sysconfig
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - optional runtime dependency
    yaml = None

from ..core.exceptions import ConfigurationError

DEFAULT_SCORING_CONFIG: dict[str, Any] = {
    "max_score": 100,
    "severity_weights": {
        "info": 0,
        "low": 5,
        "medium": 15,
        "high": 30,
        "critical": 50,
    },
    "risk_levels": {
        "low": {"min_score": 0, "max_score": 25},
        "medium": {"min_score": 25, "max_score": 50},
        "high": {"min_score": 50, "max_score": 75},
        "critical": {"min_score": 75, "max_score": 100},
    },
    "category_caps": {"yara": 30},
}


def get_project_root() -> Path:
    """Get the absolute path to the project root."""
    # Assuming config_loader.py is in src/moda/utils/
    # So parents[3] should be the project root
    return Path(__file__).resolve().parent.parent.parent.parent


def get_config_dir() -> Path:
    """Get the path to the config directory."""
    override = os.environ.get("MODA_CONFIG_DIR")
    if override:
        return Path(override).expanduser().resolve()
    source_dir = get_project_root() / "config"
    if source_dir.exists():
        return source_dir
    return Path(sysconfig.get_path("data")) / "share" / "moda" / "config"


def get_rules_dir() -> Path:
    """Get the path to the YARA rules directory."""
    override = os.environ.get("MODA_RULES_DIR")
    if override:
        return Path(override).expanduser().resolve()
    source_dir = get_project_root() / "rules"
    if source_dir.exists():
        return source_dir
    return Path(sysconfig.get_path("data")) / "share" / "moda" / "rules"


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Load a YAML configuration file."""
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    if yaml is None:
        if path.name == "scoring.yaml":
            return DEFAULT_SCORING_CONFIG
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
    except Exception as exc:
        raise ConfigurationError(str(exc), path) from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigurationError("top-level YAML value must be a mapping", path)
    return loaded


def load_scoring_config(path: Path | None = None) -> dict[str, Any]:
    """Load the scoring configuration."""
    return load_yaml_config(path or get_config_dir() / "scoring.yaml")


def load_indicators_config() -> dict[str, Any]:
    """Load the indicators configuration."""
    return load_yaml_config(get_config_dir() / "indicators.yaml")
