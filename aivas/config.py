from pathlib import Path

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

CONFIG_PATH = Path.home() / ".aivas" / "config.yml"

_DEFAULTS: dict = {
    "api_key": None,
    "provider": "groq",
    "lang": "both",
    "default_level": 2,
    "narrate": False,
}


def load() -> dict:
    """Return merged config: file values on top of defaults."""
    cfg = dict(_DEFAULTS)
    if not _HAS_YAML or not CONFIG_PATH.exists():
        return cfg
    try:
        raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        cfg.update({k: v for k, v in raw.items() if v is not None})
    except Exception:
        pass
    return cfg


def save(key: str, value: str) -> None:
    """Persist a single key=value to the config file."""
    if not _HAS_YAML:
        raise RuntimeError("PyYAML is required: pip install pyyaml")
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    cfg = load()
    cfg[key] = value
    CONFIG_PATH.write_text(
        yaml.dump({k: v for k, v in cfg.items() if v is not None},
                  default_flow_style=False)
    )


def valid_keys() -> list[str]:
    return list(_DEFAULTS.keys())
