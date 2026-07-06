from __future__ import annotations

from pathlib import Path
from typing import Dict, Any

try:
    import yaml
except ImportError:  # pragma: no cover - optional runtime dependency
    yaml = None

DEFAULT_SCORING_CONFIG: Dict[str, Any] = {
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
    return get_project_root() / "config"

def get_rules_dir() -> Path:
    """Get the path to the YARA rules directory."""
    return get_project_root() / "rules"

def load_yaml_config(path: Path) -> Dict[str, Any]:
    """Load a YAML configuration file."""
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    if yaml is None:
        if path.name == "scoring.yaml":
            return DEFAULT_SCORING_CONFIG
        return {}
    with path.open('r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def load_scoring_config() -> Dict[str, Any]:
    """Load the scoring configuration."""
    return load_yaml_config(get_config_dir() / "scoring.yaml")

def load_indicators_config() -> Dict[str, Any]:
    """Load the indicators configuration."""
    return load_yaml_config(get_config_dir() / "indicators.yaml")
