#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Admin-first permission discovery.

The deny-first loop learns from failures: start read-only, harvest every
AccessDenied, grant it, repeat. This does the opposite - give the role
AdministratorAccess so nothing fails, then read CloudTrail to see what
CloudFormation actually called.

One deploy and one delete instead of a dozen iterations. The interesting
question is what that speed costs, which is what compare_policies.py measures.
"""
import argparse
import json
import os
import subprocess
import sys
import time

# Resolve paths relative to this file so the tools keep working wherever
# the repo is checked out.
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import config  # noqa: E402  # pylint: disable=wrong-import-position
import discover as d  # noqa: E402  # pylint: disable=wrong-import-position

# Filled in by main() once the command line has been parsed. Resolving them
# at import would bind whatever the .env happened to say and silently ignore
# --admin-role, since a flag is not read until argparse runs.
ROLE = ""
ROLE_ARN = ""
RESULTS = d.RESULTS
RUNDIR = d.RUNDIR
RAW = f"{RUNDIR}/admin-cloudtrail-raw.jsonl"

# Actions that only read. Dropped from the "mutating" variant so the comparison
# against the deny-first policy is like-for-like: that role had ReadOnlyAccess
# attached, so it could never have discovered a read.
READ_PREFIXES = (
    "get",
    "list",
    "describe",
    "head",
    "batchget",
    "lookup",
    "search",
    "query",
    "scan",
    "select",
    "validate",
    "estimate",
    "simulate",
    "check",
    "detect",
    "preview",
    "test",
    "view",
)


def log(msg):
    """Print a line and append it to the admin run log."""
    print(msg, flush=True)
    with d.open_out(f"{RUNDIR}/admin-run.md", "a") as fh:
        fh.write(msg + "\n")


def is_read(action):
    """Report whether an action only reads.

    Args:
        action: An IAM action such as `s3:GetObject`.

    Returns:
        True if the verb matches a known read-only prefix.
    """
    verb = action.split(":", 1)[1].lower() if ":" in action else action.lower()
    read = verb.startswith(READ_PREFIXES)
    if not read:
        # The prefix list is a heuristic, and this split produces the read and
        # mutating counts the whole comparison reports. Anything it calls
        # mutating on an unfamiliar verb is worth an eye.
        d.debug("readsplit", f"{action}: verb '{verb}' -> mutating")
    return read


def cloudtrail_calls(start_epoch, settle_secs=420, poll=30):
    """Every SUCCESSFUL call this role made, across both lookup regions.

    Same pagination and dual-region handling as the deny-first collector; the
    filter is inverted - keep events with no errorCode instead of those
    with one.
    """
    seen = {}
    stable, total = 0, 0
    foreign = set()
    # See the matching counter in discover.cloudtrail_denials: a dropped event
    # is a missing permission, so an incomplete harvest must announce itself.
    undecodable = 0
    deadline = time.time() + settle_secs
    while time.time() < deadline:
        total = 0
        undecodable = 0
        for region in d.LOOKUP_REGIONS:
            r = subprocess.run(
                [
                    "aws",
                    "--region",
                    region,
                    "cloudtrail",
                    "lookup-events",
                    "--start-time",
                    str(int(start_epoch)),
                    "--lookup-attributes",
                    "AttributeKey=Username,AttributeValue=AWSCloudFormation",
                    "--query",
                    "Events[].CloudTrailEvent",
                    "--output",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if r.returncode != 0 or not r.stdout.strip():
                if r.returncode != 0:
                    log(
                        f"  !! lookup-events ({region}): "
                        f"{r.stderr.strip()[:140]}"
                    )
                continue
            try:
                blobs = json.loads(r.stdout)
            except json.JSONDecodeError as exc:
                log(
                    f"  !! lookup-events ({region}) returned unparseable "
                    f"JSON, dropping the whole page: {exc}"
                )
                continue
            total += len(blobs)
            for blob in blobs:
                try:
                    e = json.loads(blob)
                except (json.JSONDecodeError, TypeError):
                    undecodable += 1
                    continue
                arn = (e.get("userIdentity") or {}).get("arn", "")
                if ROLE not in arn:
                    if "cfn-" in arn:
                        foreign.add(arn.split("/")[-2] if "/" in arn else arn)
                    continue
                if e.get("errorCode"):  # inverted filter
                    continue
                action = d.ct_action(e)
                if not action:
                    continue
                with d.open_out(RAW, "a") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "eventTime": e.get("eventTime"),
                                "eventSource": e.get("eventSource"),
                                "eventName": e.get("eventName"),
                                "arn": arn,
                                "resources": e.get("resources"),
                            }
                        )
                        + "\n"
                    )
                seen.setdefault(action, set()).add(
                    d.canon_resource(d.ct_resource(e))
                )
        count = sum(len(v) for v in seen.values())
        if count and count == stable:
            break
        stable = count
        time.sleep(poll)
    log(
        f"  streamed {total} event(s); {sum(len(v) for v in seen.values())} "
        f"successful calls by {ROLE}"
    )
    if undecodable:
        log(
            f"  !! {undecodable} event(s) could not be decoded and were "
            f"skipped; this harvest is incomplete"
        )
    if foreign:
        log(
            f"  (ignored events from other roles: {', '.join(sorted(foreign))})"
        )
    return seen


def to_policy(calls):
    """Render observed calls as a policy document.

    Args:
        calls: Action -> set of resource ARNs.

    Returns:
        A policy with one statement per action, resources sorted.
    """
    stmts = []
    for action in sorted(calls, key=str.lower):
        resources = sorted(calls[action])
        if "*" in resources:
            resources = ["*"]
        stmts.append(
            {
                "Effect": "Allow",
                "Action": action,
                "Resource": resources[0] if len(resources) == 1 else resources,
            }
        )
    return {"Version": "2012-10-17", "Statement": stmts}


def write(doc, path, label):
    """Scan, compact, and write a policy to disk.

    Args:
        doc: The policy document to write.
        path: Destination path.
        label: Human-readable name used in the log line.

    Returns:
        The compacted document that was written.

    Raises:
        RuntimeError: If compaction changed what the policy grants.
    """
    scanned, dropped = d.static_scan(doc)
    for a in dropped:
        log(f"  static scan dropped invalid action: {a}")
    compact = d.compact_policy(scanned)
    # Not an assert: `python -O` strips those, and this check is the whole
    # basis for claiming compaction is lossless. Losing it silently would
    # let a widened policy reach IAM unverified.
    if d.expand(compact) != d.expand(scanned):
        raise RuntimeError(
            f"compaction changed semantics for {label}; refusing to write "
            f"{path}"
        )
    with d.open_out(path, "w") as fh:
        json.dump(compact, fh, indent=2)
        fh.write("\n")
    body = json.dumps(compact, separators=(",", ":"))
    log(
        f"  {label}: {len(scanned['Statement'])} actions -> "
        f"{len(compact['Statement'])} statements, {len(body)}b -> {path}"
    )
    return compact


def main():
    """Deploy under admin, delete, then derive a policy from CloudTrail.

    Returns:
        0 on completion.
    """
    global ROLE, ROLE_ARN
    ap = argparse.ArgumentParser(
        description="Admin-first permission collection from CloudTrail."
    )
    config.add_arguments(ap)
    config.apply_args(ap.parse_args())
    d.reconfigure()
    ROLE = config.ADMIN_ROLE
    ROLE_ARN = config.ADMIN_ROLE_ARN

    log(f"\n# Admin-first discovery  ({time.strftime('%Y-%m-%d %H:%M:%S')})")
    log(f"  target: {config.describe()} admin_role={ROLE}")
    d.verify_account()
    for f in (RAW,):
        if os.path.exists(f):
            os.remove(f)

    started = time.time() - 60
    t0 = time.time()

    log("\n## deploy (AdministratorAccess, expect no failures)")
    r = subprocess.run(
        [
            "aws",
            "--region",
            d.REGION,
            "cloudformation",
            "deploy",
            "--stack-name",
            d.STACK,
            "--template-file",
            d.TEMPLATE,
            "--capabilities",
            "CAPABILITY_NAMED_IAM",
            "--parameter-overrides",
            "Environment=dev",
            f"ProjectName={d.PROJECT_NAME}",
            "--role-arn",
            ROLE_ARN,
            "--no-fail-on-empty-changeset",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    d.wait_terminal()
    status = d.stack_status()
    deploy_secs = time.time() - t0
    log(f"  exit={r.returncode} status={status} elapsed={deploy_secs:.0f}s")
    if r.returncode != 0:
        log(f"  !! {(r.stderr or r.stdout).strip()[:300]}")

    log("\n## delete (same role, to collect teardown actions)")
    t1 = time.time()
    d.aws(
        "cloudformation",
        "delete-stack",
        "--stack-name",
        d.STACK,
        "--role-arn",
        ROLE_ARN,
    )
    d.wait_terminal()
    delete_status = d.stack_status()
    delete_secs = time.time() - t1
    log(
        f"  status={delete_status or 'DELETE_COMPLETE'} "
        f"elapsed={delete_secs:.0f}s"
    )

    log("\n## harvest CloudTrail")
    calls = cloudtrail_calls(started)

    mutating = {a: r for a, r in calls.items() if not is_read(a)}
    reads = {a: r for a, r in calls.items() if is_read(a)}
    log(f"  {len(mutating)} mutating action(s), {len(reads)} read action(s)")

    log("\n## artifacts")
    write(to_policy(calls), f"{RESULTS}/admin-policy.json", "all calls")
    write(
        to_policy(mutating), f"{RESULTS}/admin-policy.mutating.json", "mutating"
    )

    with d.open_out(f"{RESULTS}/admin-timing.json", "w") as fh:
        json.dump(
            {
                "deploy_seconds": round(deploy_secs),
                "delete_seconds": round(delete_secs),
                "iterations": 1,
                "mutating_actions": len(mutating),
                "read_actions": len(reads),
            },
            fh,
            indent=2,
        )

    log(
        f"\nDONE: deploy {deploy_secs:.0f}s + delete {delete_secs:.0f}s, "
        f"1 iteration"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
