#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Measure how far the admin-first policy is from actually working.

The admin-derived policy failed on its first deploy. This runs the deny-first
loop against it - deploy, harvest what was refused, grant exactly that, repeat -
and counts the iterations needed. That count is the answer to "is admin-first
sufficient on its own?": the gap it has to close is the gap the method missed.
"""
import argparse
import json
import os
import sys
import time

# Resolve paths relative to this file so the tools keep working wherever
# the repo is checked out.
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import config  # noqa: E402  # pylint: disable=wrong-import-position
import discover as d  # noqa: E402  # pylint: disable=wrong-import-position

RESULTS = d.RESULTS
RUNDIR = d.RUNDIR


def retarget():
    """Point the shared machinery at this role and its own artifacts.

    Runs after the command line is parsed, not at import: d.ROLE_ARN has to
    be built from the account that argparse may have just overridden, and an
    import-time assignment would quietly win against the flag.

    Returns:
        The number of converge passes allowed.
    """
    d.reconfigure()
    d.ROLE = config.DERIVED_ROLE
    d.ROLE_ARN = config.DERIVED_ROLE_ARN
    d.POLICY_NAME = "admin-derived"
    d.POLICY_FILE = f"{RESULTS}/admin-policy.converged.json"
    d.COMPACT_FILE = f"{RESULTS}/admin-policy.converged.compact.json"
    d.LOG_FILE = f"{RUNDIR}/admin-converge.md"
    return config.MAX_PASSES


def main():
    """Run deny-first passes over the admin-derived policy until it deploys.

    Returns:
        0 on completion.
    """
    ap = argparse.ArgumentParser(
        description="Measure the admin-first policy's shortfall."
    )
    config.add_arguments(ap)
    config.apply_args(ap.parse_args())
    max_passes = retarget()
    d.verify_account()
    # Seed from what admin-first derived, so we measure only the shortfall.
    with open(f"{RESULTS}/admin-policy.json", encoding="utf-8") as fh:
        base = json.load(fh)
    for st in base["Statement"]:
        for a in d.as_list(st["Action"]):
            # rehome_account: the committed copy of admin-policy.json is
            # scrubbed for publication, so its ARNs name a placeholder
            # account until they are pointed back at the configured one.
            d.granted.setdefault(a, set()).update(
                d.canon_resource(d.rehome_account(r))
                for r in d.as_list(st["Resource"])
            )
    start_actions = len(d.granted)
    d.log(
        f"\n# Converging the admin-first policy  "
        f"({time.strftime('%Y-%m-%d %H:%M:%S')})"
    )
    d.log(f"  seeded {start_actions} action(s) from admin-policy.json")

    # Push the seed before the first deploy. Seeding only the in-memory dict
    # left the run depending on whatever policy a previous run happened to
    # leave attached to the role: against a bare role, pass 1 measures "no
    # permissions at all" rather than the admin-first shortfall, and reports a
    # plausible pass count either way.
    d.push_policy()
    d.time.sleep(12)

    added = []
    converged = False
    t0 = time.time()
    for i in range(1, max_passes + 1):
        d.log(f"\n## pass {i}")
        d.wait_terminal()
        started = time.time() - 60
        r = d.deploy(disable_rollback=True)
        if r.returncode == 0:
            d.log(f"  ** CREATE COMPLETE after {i} extra pass(es) **")
            converged = True
            break
        status = d.wait_terminal()
        d.log(f"  status {status}")

        before = {(a, res) for a, rs in d.granted.items() for res in rs}
        new = d.record(d.harvest(started, "converge"), "converge")
        after = {(a, res) for a, rs in d.granted.items() for res in rs}
        for pair in sorted(after - before):
            added.append(pair[0])

        if new == 0:
            d.log("  no new permissions; cannot converge further", d.L_WARN)
            if status in (
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
                "DELETE_FAILED",
                "UPDATE_ROLLBACK_FAILED",
            ):
                d.phase_uninstall("wedged while converging")
                continue
            # A stuck-but-not-wedged stall is exactly as much a failure to
            # converge as exhausting max_passes. It must not exit 0: a script
            # reporting success whether or not it actually finished is the
            # exact failure mode this project exists to study.
            break
    else:
        d.log(f"  hit max_passes ({max_passes})", d.L_WARN)

    elapsed = time.time() - t0
    uniq = sorted(set(added))
    d.log(f"\n  extra passes needed: {i}")
    d.log(f"  actions added beyond admin-first: {len(uniq)}")
    for a in uniq:
        d.log(f"    + {a}")
    d.log(f"  converged: {converged}", d.L_INFO if converged else d.L_WARN)
    json.dump(
        {
            "converged": converged,
            "extra_passes": i,
            "seconds": round(elapsed),
            "seeded_actions": start_actions,
            "actions_added": uniq,
        },
        d.open_out(f"{RESULTS}/admin-converge.json", "w"),
        indent=2,
    )
    # A caller -- pipeline.py or a scheduler -- must be able to tell "the
    # admin-derived policy became sufficient" from "it did not, and here is
    # how far short it fell" without parsing the log. That distinction is the
    # entire point of running this measurement.
    return 0 if converged else 1


if __name__ == "__main__":
    sys.exit(main())
