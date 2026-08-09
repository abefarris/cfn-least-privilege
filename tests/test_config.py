# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Configuration resolution.

The precedence chain is the whole contract of config.py, and it is the kind
of thing that looks obviously right and silently is not: a flag that loses to
a stale environment variable produces a run against the wrong target that
reports success either way.
"""
import argparse

import pytest

import config
import discover


def write_env(path, text):
    """Write a .env file and point the loader at it.

    Args:
        path: Destination path.
        text: File contents.

    Returns:
        The path, as a string.
    """
    path.write_text(text)
    return str(path)


# --- precedence -----------------------------------------------------------


def test_defaults_apply_with_no_configuration():
    """With nothing set, every setting falls back to its default."""
    assert config.ACCOUNT == ""
    assert config.STACK == ""
    assert config.ROLE == "cfn-deploy-role"
    assert config.MAX_ITERS == 30


def test_env_file_is_read(monkeypatch, tmp_path):
    """A .env file supplies values when the environment does not."""
    monkeypatch.setenv(
        "IAMD_ENV_FILE",
        write_env(
            tmp_path / ".env",
            "IAMD_ACCOUNT=111111111111\nIAMD_STACK=from-file\n",
        ),
    )
    config.apply_args(None)
    assert config.ACCOUNT == "111111111111"
    assert config.STACK == "from-file"


def test_environment_beats_env_file(monkeypatch, tmp_path):
    """An exported variable wins over the file that would shadow it."""
    monkeypatch.setenv(
        "IAMD_ENV_FILE",
        write_env(tmp_path / ".env", "IAMD_STACK=from-file\n"),
    )
    monkeypatch.setenv("IAMD_STACK", "from-env")
    config.apply_args(None)
    assert config.STACK == "from-env"


def test_flag_beats_environment_and_file(monkeypatch, tmp_path, resolve):
    """A command-line flag wins over both."""
    monkeypatch.setenv(
        "IAMD_ENV_FILE",
        write_env(tmp_path / ".env", "IAMD_STACK=from-file\n"),
    )
    monkeypatch.setenv("IAMD_STACK", "from-env")
    resolve("--stack", "from-flag")
    assert config.STACK == "from-flag"


def test_env_file_flag_overrides_default_location(tmp_path, resolve):
    """--env-file reads a file somewhere other than the repo root."""
    path = write_env(tmp_path / "other.env", "IAMD_STACK=elsewhere\n")
    resolve("--env-file", path)
    assert config.STACK == "elsewhere"


# --- .env parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("IAMD_STACK=plain", "plain"),
        ('IAMD_STACK="double quoted"', "double quoted"),
        ("IAMD_STACK='single quoted'", "single quoted"),
        ("export IAMD_STACK=exported", "exported"),
        ("  IAMD_STACK=indented  ", "indented"),
    ],
)
def test_env_file_line_forms(monkeypatch, tmp_path, line, expected):
    """The parser accepts the forms a hand-edited .env actually contains."""
    monkeypatch.setenv(
        "IAMD_ENV_FILE", write_env(tmp_path / ".env", line + "\n")
    )
    config.apply_args(None)
    assert config.STACK == expected


def test_env_file_ignores_comments_and_junk(monkeypatch, tmp_path):
    """Comments, blank lines, and lines with no '=' are skipped."""
    monkeypatch.setenv(
        "IAMD_ENV_FILE",
        write_env(
            tmp_path / ".env",
            "# a comment\n\nnot a setting\nIAMD_STACK=survived\n",
        ),
    )
    config.apply_args(None)
    assert config.STACK == "survived"


def test_missing_env_file_is_not_an_error(tmp_path, monkeypatch):
    """A absent .env leaves the defaults in place rather than raising."""
    monkeypatch.setenv("IAMD_ENV_FILE", str(tmp_path / "nope.env"))
    assert config.load_env_file() is None
    config.apply_args(None)
    assert config.ROLE == "cfn-deploy-role"


# --- coercion and derived values ------------------------------------------


def test_integer_settings_stay_integers(resolve):
    """A limit arriving as text is still usable as a number."""
    resolve("--max-passes", "3")
    assert config.MAX_PASSES == 3
    assert isinstance(config.MAX_PASSES, int)


def test_non_numeric_integer_setting_falls_back(monkeypatch):
    """Garbage in an integer variable falls back instead of crashing.

    range(1, max_passes) with a string raises deep inside the converge loop,
    long after the run has started doing real work.
    """
    monkeypatch.setenv("IAMD_MAX_PASSES", "many")
    config.apply_args(None)
    assert config.MAX_PASSES == 15


def test_role_arns_follow_the_account(resolve):
    """Every derived ARN is rebuilt from the configured account."""
    resolve("--account", "999988887777")
    assert config.ROLE_ARN == ("arn:aws:iam::999988887777:role/cfn-deploy-role")
    assert config.CLEANUP_ROLE_ARN.startswith("arn:aws:iam::999988887777:")
    assert config.ADMIN_ROLE_ARN.startswith("arn:aws:iam::999988887777:")
    assert config.DERIVED_ROLE_ARN.startswith("arn:aws:iam::999988887777:")


def test_role_arn_follows_a_renamed_role(resolve):
    """Renaming a role renames its ARN too."""
    resolve("--account", "123456789012", "--role", "my-role")
    assert config.ROLE_ARN == "arn:aws:iam::123456789012:role/my-role"


def test_project_name_defaults_to_the_stack(resolve):
    """One setting retargets a run, not two that fail apart."""
    resolve("--stack", "my-stack")
    assert config.PROJECT_NAME == "my-stack"


def test_project_name_can_be_set_independently(resolve):
    """An explicit ProjectName still wins."""
    resolve("--stack", "my-stack", "--project-name", "other")
    assert config.PROJECT_NAME == "other"


def test_lookup_regions_include_us_east_1(resolve):
    """Global-service events are only ever in us-east-1."""
    resolve("--region", "ap-south-1")
    assert config.LOOKUP_REGIONS == ["ap-south-1", "us-east-1"]


def test_lookup_regions_do_not_repeat_us_east_1(resolve):
    """Running in us-east-1 must not query it twice."""
    resolve("--region", "us-east-1")
    assert config.LOOKUP_REGIONS == ["us-east-1"]


# --- propagation ----------------------------------------------------------


def test_reconfigure_pushes_into_discover(resolve):
    """Discover's module globals track config after a flag is parsed."""
    resolve(
        "--account", "123456789012", "--stack", "st", "--region", "eu-west-1"
    )
    assert discover.ACCOUNT == "123456789012"
    assert discover.STACK == "st"
    assert discover.REGION == "eu-west-1"
    assert discover.ROLE_ARN == config.ROLE_ARN
    assert discover.PROJECT_NAME == "st"


def test_export_publishes_resolved_values_for_subprocesses(resolve):
    """pipeline.py's children must resolve what the parent resolved.

    Without this a --stack passed to the pipeline would reach the built-in
    stages and not the scripted ones: one run against two stacks.
    """
    resolve("--account", "123456789012", "--stack", "exported-stack")
    exported = config.export()
    assert exported["IAMD_STACK"] == "exported-stack"
    assert exported["IAMD_ACCOUNT"] == "123456789012"
    assert exported["IAMD_PROJECT_NAME"] == "exported-stack"


def test_help_does_not_leak_the_checkout_path():
    """--help must not embed the absolute path of this checkout."""
    parser = argparse.ArgumentParser()
    config.add_arguments(parser)
    assert str(config.ROOT) not in parser.format_help()
    assert "tools/order-pipeline-pruned.yaml" in parser.format_help()
