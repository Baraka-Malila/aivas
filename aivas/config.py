from pathlib import Path
import os

try:
    from dotenv import load_dotenv
    load_dotenv()  # check CWD and parents
    _project_env = Path(__file__).parent.parent / ".env"  # repo root
    if _project_env.exists():
        load_dotenv(_project_env, override=False)
except ImportError:
    # python-dotenv not installed — fall back to manual parse
    _project_env = Path(__file__).parent.parent / ".env"
    if _project_env.exists():
        for _line in _project_env.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

CONFIG_PATH = Path.home() / ".aivas" / "config.yml"

_DEFAULTS: dict = {
    "api_key": None,
    "mistral_api_key": None,
    "shodan_key": None,
    "provider": "groq",
    "lang": "both",
    "default_level": 2,
    "narrate": False,
}


def load() -> dict:
    """Return merged config: file values on top of defaults."""
    cfg = dict(_DEFAULTS)
    if _HAS_YAML and CONFIG_PATH.exists():
        try:
            raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            cfg.update({k: v for k, v in raw.items() if v is not None})
        except Exception:
            pass
    key = cfg.get("api_key") or ""
    if not key or key.startswith("test") or len(key) < 20:
        cfg["api_key"] = os.environ.get("GROQ_API_KEY") or (key if len(key) >= 20 else None)
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
