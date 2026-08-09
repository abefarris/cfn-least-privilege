#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration for every tool in this repo.

These scripts used to carry their target account, region, stack and role
names as module-level constants, which meant reusing them required editing
the source and made the committed artifacts account-specific. Everything
that identifies *where* a run happens now resolves here, in one place, from
four sources in increasing order of precedence:

    1. the defaults below
    2. a `.env` file (repo root, or IAMD_ENV_FILE)
    3. the process environment
    4. command-line flags

Nothing in this module touches AWS or reads credentials, and importing it
with no configuration present must always succeed -- CI imports every tool
without an account, a profile, or a `.env`, and an import that raised would
turn a missing optional setting into a broken build. A missing account is
therefore caught at the point of use by `discover.verify_account()`, which
already refuses to run against the wrong account, rather than at import.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# key -> (default, help text). The key doubles as the CLI flag name (with
# underscores turned into dashes) and, uppercased and prefixed with IAMD_,
# as the environment variable -- so there is exactly one name to document
# per setting instead of three that can drift apart.
SETTINGS = {
    "account": (
        "",
        "target AWS account ID; required for anything that touches AWS",
    ),
    "region": ("us-east-1", "region the stack deploys into"),
    # No default, for the same reason as the account. purge_all() enumerates
    # and deletes every resource whose name contains this string across nine
    # services, so a stack name inherited from someone else's run is a
    # deletion scoped to a string the operator never chose.
    "stack": ("", "CloudFormation stack name; required, and see purge_all()"),
    "role": (
        "cfn-deploy-role",
        "service role the deny-first loop grows from ReadOnlyAccess",
    ),
    "admin_role": (
        "cfn-admin-role",
        "service role holding AdministratorAccess for the admin-first run",
    ),
    "derived_role": (
        "cfn-derived-role",
        "service role the admin-derived policy is converged against",
    ),
    "cleanup_role": (
        "cfn-cleanup-role",
        "admin role used to force teardown of a wedged stack",
    ),
    "policy_name": (
        "discovered-deploy-permissions",
        "name of the managed policy the loop writes its grants into",
    ),
    "template": (
        os.path.join(HERE, "order-pipeline-pruned.yaml"),
        "CloudFormation template to deploy",
    ),
    "project_name": (
        "",
        "ProjectName parameter override; defaults to the stack name",
    ),
    "max_iters": (30, "deny-first passes before the create phase gives up"),
    "max_uninstalls": (3, "uninstalls of a wedged stack before giving up"),
    "max_passes": (15, "converge passes over the admin-derived policy"),
}

# Global-service events (IAM, STS, CloudFront, Route 53) are only ever
# recorded in us-east-1, so a run in any other region has to look in both.
GLOBAL_REGION = "us-east-1"


def env_name(key):
    """Return the environment variable name for a settings key.

    Args:
        key: A key of `SETTINGS`, such as `admin_role`.

    Returns:
        The variable name, such as `IAMD_ADMIN_ROLE`.
    """
    return f"IAMD_{key.upper()}"


def load_env_file(path=None):
    """Read a `.env` file into the process environment.

    Values already present in the environment are left alone, so an
    explicitly exported variable always beats the file it would otherwise
    be shadowed by.

    Args:
        path: File to read. Defaults to `IAMD_ENV_FILE`, then `.env` at the
            repo root.

    Returns:
        The path that was read, or None if there was nothing to read.
    """
    path = path or os.environ.get("IAMD_ENV_FILE") or os.path.join(ROOT, ".env")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # `export FOO=bar` is valid in a file people also source from a
            # shell, and dropping the prefix costs nothing.
            line = line.removeprefix("export ").lstrip()
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = val
    return path


def _resolve(key):
    """Resolve one setting from the environment, falling back to its default.

    Args:
        key: A key of `SETTINGS`.

    Returns:
        The value, coerced to the type of the default so that an integer
        setting stays an integer however it arrived.
    """
    default = SETTINGS[key][0]
    raw = os.environ.get(env_name(key))
    if raw is None or raw == "":
        return default
    if isinstance(default, int):
        try:
            return int(raw)
        except ValueError:
            return default
    return raw


def add_arguments(parser):
    """Add the shared configuration flags to an argument parser.

    Every tool takes the same overrides, so a run can be retargeted without
    touching a file at all.

    Args:
        parser: An `argparse.ArgumentParser` to extend.

    Returns:
        The parser, for chaining.
    """
    group = parser.add_argument_group(
        "target",
        "Overrides the .env file and the environment. Each flag also reads "
        "IAMD_<FLAG>; see .env.example.",
    )
    group.add_argument(
        "--env-file",
        default=None,
        help="path to a .env file; default .env at the repo root",
    )
    for key, (default, helptext) in SETTINGS.items():
        shown = default
        # The template default is an absolute path that depends on where the
        # repo happens to live; showing it in full makes --help output differ
        # per machine and drags the checkout path into anything pasted from it.
        if isinstance(shown, str) and shown.startswith(ROOT + os.sep):
            shown = os.path.relpath(shown, ROOT)
        group.add_argument(
            f"--{key.replace('_', '-')}",
            default=None,
            type=int if isinstance(default, int) else str,
            help=helptext
            + (f" (default: {shown})" if shown != "" else " (required)"),
        )
    return parser


def apply_args(args=None):
    """Resolve every setting and publish the result as module globals.

    Called once per process, before anything reads a value. Flags win over
    the environment, which wins over the `.env` file, which wins over the
    defaults -- implemented by pushing any flag that was actually passed
    into the environment first, so there is only one resolution path to
    reason about instead of two that must agree.

    Args:
        args: A parsed `argparse.Namespace`, or None to use only the
            environment and the `.env` file.

    Returns:
        The dict of resolved values, also available as module attributes.
    """
    load_env_file(getattr(args, "env_file", None))
    if args is not None:
        for key in SETTINGS:
            val = getattr(args, key, None)
            if val is not None:
                os.environ[env_name(key)] = str(val)

    resolved = {key: _resolve(key) for key in SETTINGS}
    # A stack is normally its own ProjectName; keeping them in step by
    # default means retargeting a run takes one setting, not two that fail
    # confusingly when only one is changed.
    resolved["project_name"] = resolved["project_name"] or resolved["stack"]
    resolved["role_arn"] = role_arn(resolved["role"], resolved["account"])
    resolved["admin_role_arn"] = role_arn(
        resolved["admin_role"], resolved["account"]
    )
    resolved["derived_role_arn"] = role_arn(
        resolved["derived_role"], resolved["account"]
    )
    resolved["cleanup_role_arn"] = role_arn(
        resolved["cleanup_role"], resolved["account"]
    )
    resolved["lookup_regions"] = list(
        dict.fromkeys([resolved["region"], GLOBAL_REGION])
    )
    globals().update({k.upper(): v for k, v in resolved.items()})
    return resolved


def export():
    """Publish the resolved settings into the environment for subprocesses.

    pipeline.py runs the tools as child processes. Without this each child
    would re-resolve from the `.env` and the environment and miss any flag
    the parent was given, so a `--stack` on the pipeline would silently
    apply to the built-in stages and not to the scripted ones -- two halves
    of one run against two different stacks.

    Returns:
        The dict of variables that were exported.
    """
    out = {env_name(key): str(_resolve(key)) for key in SETTINGS}
    # Resolved values, not the file: a child that re-read the file could
    # still disagree with the parent about anything a flag overrode.
    out["IAMD_PROJECT_NAME"] = str(PROJECT_NAME)
    os.environ.update(out)
    return out


def role_arn(name, account=None):
    """Build a role ARN from a bare role name.

    Args:
        name: The role name.
        account: Account ID; defaults to the resolved account.

    Returns:
        The full ARN. With no account configured this is still a string
        rather than an error, because import must never fail -- the run
        stops later, in verify_account(), with a message that says why.
    """
    account = ACCOUNT if account is None else account
    return f"arn:aws:iam::{account}:role/{name}"


def describe():
    """Return the resolved target as a one-line summary for logs."""
    return (
        f"account={ACCOUNT or '<unset>'} region={REGION} "
        f"stack={STACK} role={ROLE}"
    )


# Declared before the resolve below so that the names exist for a reader and
# for static analysis; apply_args() overwrites all of them immediately.
ACCOUNT = ""
REGION = GLOBAL_REGION
STACK = ""
ROLE = ""
PROJECT_NAME = ""

# Resolve at import so a tool that never parses arguments -- uninstall.py, or
# anything importing discover purely for its helpers -- still sees real values.
apply_args(None)
