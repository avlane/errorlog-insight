"""Settings from a config file (TOML or INI) with command line flags on top.

    [report]
    top = 20
    min_severity = "warning"

    [bursts]
    min = 8
    factor = 4.0
    bucket_seconds = 60
    window = 30

Precedence: built-in defaults, then the config file, then flags given on the
command line.
"""
import configparser
from dataclasses import dataclass, field

from .bursts import BurstConfig
from .model import SEVERITIES


class ConfigError(ValueError):
    pass


@dataclass
class Settings:
    top: int = 10
    min_severity: str = "info"
    bursts: BurstConfig = field(default_factory=BurstConfig)


def _read_toml(path):
    try:
        import tomllib
    except ImportError:
        raise ConfigError("TOML config files need Python 3.11 or newer; use an .ini file instead: %s" % path)
    with open(path, "rb") as f:
        try:
            return tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError("%s: %s" % (path, exc))


def _read_ini(path):
    parser = configparser.ConfigParser()
    if not parser.read(path, encoding="utf-8"):
        raise ConfigError("cannot read config file: %s" % path)
    return {section: dict(parser.items(section)) for section in parser.sections()}


def read_config(path):
    """Return the config file as nested dicts."""
    if str(path).lower().endswith(".toml"):
        return _read_toml(path)
    return _read_ini(path)


def _number(section, key, kind, minimum):
    raw = section[key]
    try:
        value = kind(raw)
    except (TypeError, ValueError):
        raise ConfigError("%s must be a number, got %r" % (key, raw))
    if value < minimum:
        raise ConfigError("%s must be at least %s, got %r" % (key, minimum, raw))
    return value


def settings_from_config(data):
    """Build Settings from the nested dicts of a config file; unknown keys are an error."""
    settings = Settings()
    known = {"report": {"top", "min_severity"}, "bursts": {"min", "factor", "bucket_seconds", "window"}}
    for name in data:
        if name not in known:
            raise ConfigError("unknown section [%s]" % name)
        for key in data[name]:
            if key not in known[name]:
                raise ConfigError("unknown key %r in [%s]" % (key, name))
    report = data.get("report", {})
    if "top" in report:
        settings.top = _number(report, "top", int, 0)
    if "min_severity" in report:
        if report["min_severity"] not in SEVERITIES:
            raise ConfigError("min_severity must be one of %s" % ", ".join(SEVERITIES))
        settings.min_severity = report["min_severity"]
    bursts = data.get("bursts", {})
    if "min" in bursts:
        settings.bursts.min_count = _number(bursts, "min", int, 1)
    if "factor" in bursts:
        settings.bursts.factor = _number(bursts, "factor", float, 0.0)
    if "bucket_seconds" in bursts:
        settings.bursts.bucket_seconds = _number(bursts, "bucket_seconds", int, 1)
    if "window" in bursts:
        settings.bursts.window = _number(bursts, "window", int, 1)
    return settings


def load_settings(path=None, top=None, min_severity=None, burst_min=None, burst_factor=None):
    """Defaults, then the config file (if any), then explicit command line values (not None)."""
    settings = settings_from_config(read_config(path)) if path else Settings()
    if top is not None:
        settings.top = top
    if min_severity is not None:
        settings.min_severity = min_severity
    if burst_min is not None:
        settings.bursts.min_count = burst_min
    if burst_factor is not None:
        settings.bursts.factor = burst_factor
    return settings
