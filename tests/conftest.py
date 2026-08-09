# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

The tools resolve configuration into module globals once, at import. That is
the right shape for a script and the wrong shape for a test suite, so almost
everything here exists to give each test a clean, isolated view of that
global state and to put it back afterwards.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import config  # noqa: E402
import discover  # noqa: E402

# Every environment variable the tools read. Cleared before each test so a
# developer's own .env or exported profile cannot change a result -- a suite
# that passes only on the machine that wrote it is worse than no suite.
IAMD_VARS = [config.env_name(k) for k in config.SETTINGS] + [
    "IAMD_ENV_FILE",
    "IAMD_RUN_DIR",
    "IAMD_LOG_LEVEL",
    "IAMD_DEBUG",
]


def pytest_addoption(parser):
    """Register the opt-in flags for the AWS-touching tiers."""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run read-only tests against real AWS (needs credentials)",
    )
    parser.addoption(
        "--integration-destructive",
        action="store_true",
        default=False,
        help="also deploy and delete a minimal real stack; implies "
        "--integration and costs a few minutes of CloudFormation time",
    )


def pytest_configure(config):  # noqa: A002
    """Declare the markers so strict mode does not reject them.

    Args:
        config: pytest's config object. The name is fixed by the hook spec
            and shadows the tools' config module inside this function.
    """
    config.addinivalue_line(
        "markers", "integration: needs real AWS credentials; read-only"
    )
    config.addinivalue_line(
        "markers",
        "destructive: creates and deletes real AWS resources",
    )


def pytest_collection_modifyitems(config, items):  # noqa: A002
    """Skip the AWS tiers unless they were explicitly asked for.

    Default-off is the whole point: `pytest` with no flags must stay fast,
    free, and runnable with no credentials, so CI can gate on it.

    Args:
        config: pytest's own config object, which shadows the tools' config
            module inside this function; the module is not needed here.
        items: Collected tests, modified in place.
    """
    destructive = config.getoption("--integration-destructive")
    live = config.getoption("--integration") or destructive
    skip_live = pytest.mark.skip(reason="needs --integration and credentials")
    skip_destr = pytest.mark.skip(reason="needs --integration-destructive")
    for item in items:
        if "destructive" in item.keywords and not destructive:
            item.add_marker(skip_destr)
        elif "integration" in item.keywords and not live:
            item.add_marker(skip_live)


@pytest.fixture(autouse=True)
def clean_config(monkeypatch, tmp_path):
    """Give each test a pristine, fully defaulted configuration.

    Points IAMD_ENV_FILE at a path that does not exist, so `load_env_file`
    finds nothing and cannot fall back to the repo's real `.env`.
    """
    for var in IAMD_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("IAMD_ENV_FILE", str(tmp_path / "absent.env"))
    config.apply_args(None)
    discover.reconfigure()
    yield
    config.apply_args(None)
    discover.reconfigure()


@pytest.fixture
def resolve():
    """Return a helper that resolves config from flags, as a tool would."""
    import argparse

    def _resolve(*argv):
        parser = argparse.ArgumentParser()
        config.add_arguments(parser)
        config.apply_args(parser.parse_args(list(argv)))
        discover.reconfigure()
        return config

    return _resolve


@pytest.fixture
def granted_isolated():
    """Empty discover's accumulator dicts and restore them afterwards.

    They are module-level and shared; a test that seeds into them would
    otherwise leak grants into whatever runs next.
    """
    saved = (
        dict(discover.granted),
        dict(discover.phases),
        set(discover.rejected),
        discover.POLICY_FILE,
    )
    discover.granted.clear()
    discover.phases.clear()
    discover.rejected.clear()
    yield discover.granted
    discover.granted.clear()
    discover.granted.update(saved[0])
    discover.phases.clear()
    discover.phases.update(saved[1])
    discover.rejected.clear()
    discover.rejected.update(saved[2])
    # Tests that exercise seeding repoint this at a temp file; leaving it
    # there would aim a later run's resume state at a deleted path.
    discover.POLICY_FILE = saved[3]
