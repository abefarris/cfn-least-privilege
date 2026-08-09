#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Uninstall the test stack using the discovered policy.

Deleting with the test role makes the teardown a discovery pass in its own
right: every denial it hits is a permission a real deploy role needs in order
to unwind a failed deployment.
"""
import argparse
import os
import sys

# Resolve paths relative to this file so the tools keep working wherever
# the repo is checked out.
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import config  # noqa: E402  # pylint: disable=wrong-import-position
import discover as d  # noqa: E402  # pylint: disable=wrong-import-position


def main():
    """Delete the stack with the test role, harvesting what it is refused.

    Returns:
        0 if the stack went away, 1 otherwise.
    """
    ap = argparse.ArgumentParser(
        description="Delete the test stack, harvesting delete permissions."
    )
    config.add_arguments(ap)
    config.apply_args(ap.parse_args())
    d.reconfigure()

    d.verify_account()
    d.seed_from_policy_file()
    if d.granted:
        d.push_policy()
        d.time.sleep(12)
    ok = d.phase_uninstall("requested uninstall")
    d.write_summary()
    d.log(
        f"\nUNINSTALL {'COMPLETE' if ok else 'INCOMPLETE'}: "
        f"{len(d.granted)} distinct actions -> {d.POLICY_FILE}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
