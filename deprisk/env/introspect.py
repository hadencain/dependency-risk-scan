import importlib.metadata
import platform
import sys

from packaging.utils import canonicalize_name

from deprisk.models import Component


def introspect_environment() -> list[Component]:
    """Enumerate installed distributions in the running Python environment."""
    seen: dict[str, Component] = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        if not name:
            continue
        key = canonicalize_name(name)
        if key in seen:
            continue
        version = dist.version
        seen[key] = Component(
            ecosystem="pypi",
            name=name,
            version=version,
            purl=f"pkg:pypi/{key}@{version}" if version else f"pkg:pypi/{key}",
            source="live-env",
        )
    return list(seen.values())


def env_descriptor() -> str:
    """Human-readable descriptor of the live environment for audit metadata."""
    v = sys.version_info
    return f"live:python{v.major}.{v.minor}@{platform.node()}"
