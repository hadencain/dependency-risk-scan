from types import SimpleNamespace
from unittest.mock import patch
from deprisk.env.introspect import introspect_environment, env_descriptor


class FakeDist:
    def __init__(self, name, version):
        self._name = name
        self.version = version

    @property
    def metadata(self):
        return {"Name": self._name}


def test_introspect_maps_distributions():
    dists = [FakeDist("Requests", "2.31.0"), FakeDist("flask", "3.0.0")]
    with patch("deprisk.env.introspect.importlib.metadata.distributions",
               return_value=dists):
        comps = introspect_environment()
    names = {c.name for c in comps}
    assert names == {"Requests", "flask"}
    req = next(c for c in comps if c.name == "Requests")
    assert req.ecosystem == "pypi"
    assert req.version == "2.31.0"
    assert req.purl == "pkg:pypi/requests@2.31.0"
    assert req.source == "live-env"


def test_introspect_dedupes_by_canonical_name():
    dists = [FakeDist("Foo_Bar", "1.0"), FakeDist("foo-bar", "1.0")]
    with patch("deprisk.env.introspect.importlib.metadata.distributions",
               return_value=dists):
        comps = introspect_environment()
    assert len(comps) == 1


def test_introspect_skips_nameless():
    dists = [FakeDist(None, "1.0"), FakeDist("ok", "2.0")]
    with patch("deprisk.env.introspect.importlib.metadata.distributions",
               return_value=dists):
        comps = introspect_environment()
    assert [c.name for c in comps] == ["ok"]


def test_env_descriptor_format():
    desc = env_descriptor()
    assert desc.startswith("live:python")
    assert "@" in desc
