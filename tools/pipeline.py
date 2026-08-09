#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Drive the full discovery workflow end to end, unattended.

The individual tools each do one thing and assume a human sequenced them
correctly. Every failure this project has actually suffered came from that
assumption: a stage started against the wrong account, or against leftovers a
previous run abandoned, or with state a prior stage was supposed to have
cleared. This runs them in order, checks the preconditions each one silently
depends on, and refuses rather than producing a plausible wrong answer.

Stages, in dependency order:

    preflight   credentials, target account, required binaries
    purge       remove leftovers from an abandoned run  (destructive)
    reset       clear the seed policy so a run starts from zero  (destructive)
    deny        tools/discover.py       -- hours
    admin       tools/admin_discover.py -- ~5 minutes  (deploys as admin)
    converge    tools/converge_admin.py -- up to an hour
    compare     tools/compare_policies.py -- seconds, no AWS calls
    teardown    delete the stack and purge what CloudFormation abandons

Nothing destructive runs without --allow-destructive. Every stage writes into
one run directory and the outcome is recorded in pipeline.json, so a scheduler
can act on the result without reading logs.

Exit codes:
    0  every selected stage succeeded
    1  a stage failed
    2  preflight failed -- nothing was run
    3  bad invocation
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import config  # noqa: E402  # pylint: disable=wrong-import-position
import discover as d  # noqa: E402  # pylint: disable=wrong-import-position

# name -> (script or None for built-in, human description, destructive,
#          stop the pipeline on nonzero exit)
STAGES = {
    "preflight": (None, "credentials, account, required binaries", False, True),
    "purge": (None, "remove leftovers from an abandoned run", True, True),
    "reset": (
        None,
        "clear seed policy so discovery starts from zero",
        True,
        True,
    ),
    "deny": ("discover.py", "deny-first discovery (hours)", True, True),
    "admin": (
        "admin_discover.py",
        "admin-first collection (~5 min)",
        True,
        True,
    ),
    # converge_admin.py exits 1 when the admin-derived policy did not become
    # sufficient within MAX_PASSES. That is the measurement, not a failure of
    # the pipeline -- compare and teardown must still run so the shortfall
    # gets written down and the account gets cleaned up either way.
    "converge": (
        "converge_admin.py",
        "measure admin-first shortfall",
        True,
        False,
    ),
    "compare": ("compare_policies.py", "write the comparison", False, True),
    "teardown": (None, "delete the stack and purge orphans", True, True),
}
DEFAULT_ORDER = list(STAGES)


def emit(msg, level=d.L_INFO):
    """Log through discover so pipeline output joins the run log."""
    d.log(msg, level)


def preflight(cfg):
    """Check every precondition the stages silently depend on.

    Args:
        cfg: Parsed arguments.

    Returns:
        A list of failure strings; empty means good to proceed.
    """
    problems = []

    # Report the unconfigured case as itself. Compared against an empty
    # target every account looks like the wrong account, and "credentials
    # are for 1234, tools target " sends the reader hunting for a profile
    # problem that does not exist.
    if not d.ACCOUNT:
        problems.append(
            "no target account configured: set IAMD_ACCOUNT in .env (see "
            ".env.example) or pass --account"
        )
    if not d.STACK:
        problems.append(
            "no target stack configured: set IAMD_STACK in .env (see "
            ".env.example) or pass --stack; purge_all() scopes its deletions "
            "to it"
        )

    r = d.aws(
        "sts", "get-caller-identity", "--query", "Account", "--output", "text"
    )
    if r.returncode != 0:
        problems.append(f"no usable AWS credentials: {r.stderr.strip()[:120]}")
    elif d.ACCOUNT:
        active = (r.stdout or "").strip()
        if active != d.ACCOUNT:
            problems.append(
                f"credentials are for {active}, tools target {d.ACCOUNT}; "
                f"set AWS_PROFILE to a profile in {d.ACCOUNT}"
            )
        else:
            emit(f"  account {active} confirmed")

    for binary in ("aws", "cfn-lint"):
        if (
            subprocess.run(
                ["which", binary], capture_output=True, check=False
            ).returncode
            != 0
        ):
            problems.append(f"{binary} not found on PATH")

    if not os.path.exists(d.TEMPLATE):
        problems.append(f"template missing: {d.TEMPLATE}")

    leftovers = survey()
    if leftovers and "purge" not in cfg.stages and "teardown" not in cfg.stages:
        # This is the condition that wedged a real run for nine iterations.
        # AlreadyExists is not a denial, so the loop cannot learn from it.
        problems.append(
            f"account is not clean ({', '.join(leftovers)}); run with the "
            f"purge stage or clear them first -- orphans surface as "
            f"AlreadyExists, which the discovery loop cannot recover from"
        )
    return problems


def survey():
    """Return a description of every stack resource still present.

    Returns nothing when no stack is configured. Every check below is a
    `contains(name, stack)` filter, and contains() against an empty string
    matches every resource in the account -- so an unconfigured run would
    report the whole account as leftovers from a stack that never existed.
    """
    stack = d.STACK
    if not stack:
        return []
    checks = [
        (
            "stack",
            [
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                stack,
                "--query",
                "length(Stacks)",
            ],
        ),
        (
            "roles",
            [
                "iam",
                "list-roles",
                "--query",
                f"length(Roles[?contains(RoleName,`{stack}`)])",
            ],
        ),
        (
            "buckets",
            [
                "s3api",
                "list-buckets",
                "--query",
                f"length(Buckets[?contains(Name,`{stack}`)])",
            ],
        ),
        (
            "functions",
            [
                "lambda",
                "list-functions",
                "--query",
                f"length(Functions[?contains(FunctionName,`{stack}`)])",
            ],
        ),
        (
            "tables",
            [
                "dynamodb",
                "list-tables",
                "--query",
                f"length(TableNames[?contains(@,`{stack}`)])",
            ],
        ),
        (
            "rules",
            [
                "events",
                "list-rules",
                "--name-prefix",
                stack,
                "--query",
                "length(Rules)",
            ],
        ),
        (
            "mappings",
            [
                "lambda",
                "list-event-source-mappings",
                "--query",
                f"length(EventSourceMappings[?contains("
                f"EventSourceArn,`{stack}`)])",
            ],
        ),
        (
            "statemachines",
            [
                "stepfunctions",
                "list-state-machines",
                "--query",
                f"length(stateMachines[?contains(name,`{stack}`)])",
            ],
        ),
    ]
    found = []
    for label, args in checks:
        r = d.aws(*args, "--output", "text")
        try:
            n = int((r.stdout or "0").strip())
        except ValueError:
            n = 0
        if n:
            found.append(f"{label}={n}")
    return found


def stage_purge(_cfg):
    """Delete the stack if present, then remove what it abandoned."""
    if d.stack_status() is not None:
        emit("  deleting stack with the admin cleanup role")
        d.teardown()
    d.purge_all()
    remaining = survey()
    if remaining:
        emit(f"  !! purge left resources behind: {remaining}", d.L_WARN)
        return 1
    emit("  account clean")
    return 0


def stage_reset(_cfg):
    """Detach the discovered policy and archive the seed.

    Discovery resumes from results/deploy-policy.json and from whatever policy
    is attached to the role. Leaving either in place makes a "from zero" run
    converge in one pass and measure nothing.
    """
    r = d.aws(
        "iam",
        "delete-role-policy",
        "--role-name",
        d.ROLE,
        "--policy-name",
        d.POLICY_NAME,
    )
    emit(
        f"  detached {d.POLICY_NAME}: "
        f"{'ok' if r.returncode == 0 else 'not present'}"
    )
    if os.path.exists(d.POLICY_FILE):
        # Into the run directory, not results/. results/ is tracked and holds
        # curated artifacts; a timestamped backup of superseded state is
        # neither, and dropping one there dirties the tree on every reset.
        dest = os.path.join(
            d.RUNDIR, f"{os.path.basename(d.POLICY_FILE)}.superseded"
        )
        os.makedirs(d.RUNDIR, exist_ok=True)
        os.replace(d.POLICY_FILE, dest)
        emit(f"  archived seed -> {os.path.relpath(dest, ARTIFACTS)}")
    return 0


def stage_teardown(cfg):
    """Tear the stack down and leave the account clean."""
    return stage_purge(cfg)


BUILTINS = {
    "preflight": None,  # handled before the loop
    "purge": stage_purge,
    "reset": stage_reset,
    "teardown": stage_teardown,
}


def run_script(script, rundir, timeout, log_level=None):
    """Run one tool as a subprocess, sharing the pipeline's run directory.

    Args:
        script: Filename under tools/.
        rundir: Directory every stage writes into.
        timeout: Seconds before the stage is killed, or None.
        log_level: Value for IAMD_LOG_LEVEL, or None to inherit the
            environment. discover.debug() is a no-op unless this reaches
            DEBUG or below -- the harvest-merge bug that wedged a real run
            produced no trace at all until a run was made with this set,
            because every debug() call defaults to silent.

    Returns:
        The process exit code; 124 on timeout, matching coreutils.
    """
    env = dict(os.environ, IAMD_RUN_DIR=rundir)
    if log_level:
        env["IAMD_LOG_LEVEL"] = log_level
    try:
        return subprocess.run(
            [sys.executable, os.path.join(HERE, script)],
            env=env,
            timeout=timeout,
            check=False,
        ).returncode
    except subprocess.TimeoutExpired:
        emit(f"  !! {script} exceeded {timeout}s and was killed", d.L_WARN)
        return 124


def write_manifest(rundir, results, failed, problems=None):
    """Record the outcome where a scheduler can read it without parsing logs.

    Args:
        rundir: The pipeline's run directory.
        results: Per-stage exit codes and durations.
        failed: Name of the stage that failed, or None.
        problems: Preflight failures, when preflight is why we stopped.

    Returns:
        The manifest dict that was written.
    """
    manifest = {
        "finished": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "account": d.ACCOUNT,
        "stack": d.STACK,
        "run_dir": rundir,
        "stages": results,
        "failed_stage": failed,
        "problems": problems or [],
        "ok": failed is None,
    }
    with d.open_out(f"{rundir}/pipeline.json", "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    return manifest


def main():
    """Run the selected stages in dependency order.

    Returns:
        A process exit code; see the module docstring.
    """
    ap = argparse.ArgumentParser(description="Drive the discovery workflow.")
    config.add_arguments(ap)
    ap.add_argument(
        "--stages",
        default="preflight,admin,compare",
        help="comma-separated; default preflight,admin,compare",
    )
    ap.add_argument(
        "--all", action="store_true", help="every stage, purge through teardown"
    )
    ap.add_argument(
        "--allow-destructive",
        action="store_true",
        help="required for any stage that changes AWS state",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="per-stage seconds; 0 means no limit",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve and report the plan, run nothing",
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="set IAMD_LOG_LEVEL=DEBUG for every stage subprocess, so the "
        "discard/rewrite/settle trail is captured. Off by default because "
        "debug() is silent otherwise: a real harvest-merge bug produced no "
        "trace at all in a run where this was not set.",
    )
    cfg = ap.parse_args()
    config.apply_args(cfg)
    d.reconfigure()
    # Every stage, in-process or subprocess, resolves the same target.
    config.export()

    if cfg.all:
        cfg.stages = DEFAULT_ORDER
    else:
        cfg.stages = [s.strip() for s in cfg.stages.split(",") if s.strip()]
    unknown = [s for s in cfg.stages if s not in STAGES]
    if unknown:
        print(
            f"unknown stage(s): {unknown}; choose from {DEFAULT_ORDER}",
            file=sys.stderr,
        )
        return 3
    # Always run in dependency order regardless of how they were listed.
    cfg.stages = [s for s in DEFAULT_ORDER if s in cfg.stages]

    destructive = [s for s in cfg.stages if STAGES[s][2]]
    # --dry-run runs nothing, so it must be usable without arming the guard;
    # otherwise the safe way to inspect a plan requires the unsafe flag.
    if destructive and not cfg.allow_destructive and not cfg.dry_run:
        print(
            f"stages {destructive} change AWS state; pass "
            f"--allow-destructive to proceed",
            file=sys.stderr,
        )
        return 3

    rundir = os.environ.get("IAMD_RUN_DIR") or os.path.join(
        ARTIFACTS, "runs", time.strftime("%Y-%m-%dT%H-%M-%S")
    )
    os.environ["IAMD_RUN_DIR"] = rundir
    d.RUNDIR = rundir
    d.LOG_FILE = f"{rundir}/pipeline.md"
    if cfg.debug:
        # Applies to the built-in stages (purge/reset/teardown), which run
        # in-process against the already-imported `discover` module rather
        # than as a subprocess -- setting the env var alone would not affect
        # a module that already read it at import time.
        os.environ["IAMD_LOG_LEVEL"] = "DEBUG"
        d.LOG_LEVEL = d.L_DEBUG
        d.DEBUG = True
    d.DEBUG_FILE = f"{rundir}/debug.log"

    emit(f"\n# pipeline  ({time.strftime('%Y-%m-%d %H:%M:%S')})")
    emit(f"  stages: {', '.join(cfg.stages)}")
    emit(f"  target: {config.describe()}")
    emit(f"  run dir: {rundir}")

    if cfg.dry_run:
        for s in cfg.stages:
            script, why, danger, _ = STAGES[s]
            emit(f"    {s:10} {'[destructive] ' if danger else ''}{why}")
        return 0

    if "preflight" in cfg.stages:
        emit("\n## preflight")
        problems = preflight(cfg)
        if problems:
            for p in problems:
                emit(f"  !! {p}", d.L_ERROR)
            emit("  refusing to run", d.L_ERROR)
            # Still write the manifest. A scheduler that only gets an exit code
            # cannot tell "wrong account" from "expired credentials" from
            # "account not clean", and those need different responses.
            write_manifest(rundir, [], "preflight", problems)
            return 2
        emit("  all checks passed")

    results, failed = [], None
    for name in cfg.stages:
        if name == "preflight":
            results.append({"stage": name, "exit": 0, "seconds": 0})
            continue
        script, why, _, stop_on_fail = STAGES[name]
        emit(f"\n## {name} -- {why}")
        t0 = time.time()
        if script:
            code = run_script(
                script,
                rundir,
                cfg.timeout or None,
                "DEBUG" if cfg.debug else None,
            )
        else:
            code = BUILTINS[name](cfg)
        secs = round(time.time() - t0)
        results.append({"stage": name, "exit": code, "seconds": secs})
        emit(
            f"  {name}: exit={code} elapsed={secs}s",
            d.L_INFO if code == 0 else d.L_WARN,
        )
        if code != 0:
            if failed is None:
                failed = name
            if stop_on_fail:
                emit(f"  !! stopping: {name} failed", d.L_ERROR)
                break
            emit(
                f"  {name} did not fully succeed; continuing "
                f"(non-fatal by design)",
                d.L_WARN,
            )

    write_manifest(rundir, results, failed)
    emit(
        f"\n  {'OK' if failed is None else 'FAILED at ' + failed}"
        f" -> {rundir}/pipeline.json"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
