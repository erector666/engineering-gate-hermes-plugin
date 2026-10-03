"""Resolve Gate core imports for the two supported adapter package layouts."""
from importlib import import_module
import re


_BASE_NAMESPACE = "hermes_plugins.engineering_gate.adapters.hermes"
_DIRECT_NAMESPACE = "adapters.hermes"
_HASHED_NAMESPACE = re.compile(
    r"hermes_plugins\.engineering_gate__home_[0-9a-f]{12}\.adapters\.hermes"
)


def import_core(module: str):
    """Import a Gate core module only from a recognized adapter namespace."""
    package = __package__
    if package == _DIRECT_NAMESPACE:
        core_package = "engineering_gate_core"
    elif package == _BASE_NAMESPACE:
        core_package = "hermes_plugins.engineering_gate.engineering_gate_core"
    elif package is not None and _HASHED_NAMESPACE.fullmatch(package):
        plugin_root = package.removesuffix(".adapters.hermes")
        core_package = f"{plugin_root}.engineering_gate_core"
    else:
        raise ImportError(f"unsupported Hermes adapter package namespace: {package!r}")
    return import_module(f"{core_package}.{module}")
