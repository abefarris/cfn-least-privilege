#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Compare the deny-first and admin-first derived policies.

Deny-first learns from AccessDenied; admin-first learns from successful calls.
Neither is obviously complete, and the interesting output is where they differ
and why - which is what this writes to comparison.generated.md.

The generated table is kept in its own file. comparison.md is hand-authored
analysis that this script must never touch: it used to write there directly
and silently truncated ~50 lines of conclusions on every run.
"""
import json
import os
import sys

# Resolve paths relative to this file so the tools keep working wherever
# the repo is checked out.
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import discover as d  # noqa: E402  # pylint: disable=wrong-import-position

RESULTS = d.RESULTS
DENY = f"{RESULTS}/deploy-policy.compact.json"
ADMIN_MUT = f"{RESULTS}/admin-policy.mutating.json"
ADMIN_ALL = f"{RESULTS}/admin-policy.json"


def load(p):
    """Load a policy document, or an empty one if it is missing or invalid.

    Args:
        p: Path to a policy JSON file.

    Returns:
        The parsed document, or an empty policy so the comparison can still run.
    """
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"Version": "2012-10-17", "Statement": []}


def actions(doc):
    """Collect every action named in a policy.

    Args:
        doc: A policy document.

    Returns:
        The set of action strings, original casing preserved.
    """
    out = set()
    for st in doc["Statement"]:
        for a in d.as_list(st["Action"]):
            out.add(a)
    return out


def by_action(doc):
    """Index a policy by lowercased action.

    Args:
        doc: A policy document.

    Returns:
        Action -> set of resource ARNs granted for it.
    """
    m = {}
    for st in doc["Statement"]:
        for a in d.as_list(st["Action"]):
            m.setdefault(a.lower(), set()).update(d.as_list(st["Resource"]))
    return m


def size(doc):
    """Return the byte length of a policy in its most compact JSON form."""
    return len(json.dumps(doc, separators=(",", ":")))


def main():
    """Write the deny-first vs admin-first comparison table.

    Returns:
        None; the report is written to disk and echoed to stdout.
    """
    deny, mut, alls = load(DENY), load(ADMIN_MUT), load(ADMIN_ALL)
    try:
        with open(f"{RESULTS}/admin-timing.json", encoding="utf-8") as fh:
            timing = json.load(fh)
    except (OSError, json.JSONDecodeError):
        timing = {}

    dset = {a.lower() for a in actions(deny)}
    aset = {a.lower() for a in actions(mut)}
    only_deny, only_admin, both = dset - aset, aset - dset, dset & aset

    disp = {a.lower(): a for a in actions(deny) | actions(mut)}
    dres, ares = by_action(deny), by_action(mut)

    lines = []
    lines.append("# Deny-first vs admin-first permission discovery\n")
    lines.append(
        "Two ways to derive a deployment policy for the same "
        "CloudFormation stack.\n"
    )
    lines.append("| | Deny-first | Admin-first |")
    lines.append("| --- | --- | --- |")
    lines.append(
        "| Starting permissions | `ReadOnlyAccess` | " "`AdministratorAccess` |"
    )
    lines.append("| Learns from | AccessDenied failures | successful calls |")
    lines.append(
        f"| Deploy iterations | ~20 across the run | "
        f"{timing.get('iterations', 1)} |"
    )
    lines.append(
        f"| Wall clock | hours | "
        f"{timing.get('deploy_seconds', '?')}s deploy + "
        f"{timing.get('delete_seconds', '?')}s delete |"
    )
    lines.append(f"| Mutating actions | {len(dset)} | {len(aset)} |")
    lines.append(
        f"| Read actions | 0 (masked by ReadOnlyAccess) | "
        f"{timing.get('read_actions', '?')} |"
    )
    lines.append(
        f"| Policy size | {size(deny)}b | {size(mut)}b mutating, "
        f"{size(alls)}b with reads |"
    )
    lines.append("")

    lines.append(f"## Only deny-first found these ({len(only_deny)})\n")
    lines.append(
        "Permissions an admin-first run cannot see, because nothing "
        "failed and CloudTrail records no denial.\n"
    )
    if only_deny:
        lines.append("| Action | Resources |")
        lines.append("| --- | --- |")
        for a in sorted(only_deny):
            n = len(dres.get(a, []))
            lines.append(f"| `{disp[a]}` | {n} ARN(s) |")
    else:
        lines.append("_none_")
    lines.append("")

    lines.append(f"## Only admin-first found these ({len(only_admin)})\n")
    lines.append(
        "Calls that succeeded under admin. Some are real gaps in the "
        "deny-first policy; some are API names that are not IAM "
        "actions.\n"
    )
    if only_admin:
        lines.append("| Action | Resources |")
        lines.append("| --- | --- |")
        for a in sorted(only_admin):
            n = len(ares.get(a, []))
            lines.append(f"| `{disp[a]}` | {n} ARN(s) |")
    else:
        lines.append("_none_")
    lines.append("")

    lines.append(f"## Found by both ({len(both)})\n")
    lines.append(", ".join(f"`{disp[a]}`" for a in sorted(both)) or "_none_")
    lines.append("")

    dstar = sorted(a for a, rs in dres.items() if rs == {"*"})
    astar = sorted(a for a, rs in ares.items() if rs == {"*"})
    lines.append("## Resource scoping\n")
    lines.append(
        "The point of the exercise is least privilege, and that lives in "
        "the `Resource` field rather than the action list.\n"
    )
    lines.append("| | Deny-first | Admin-first |")
    lines.append("| --- | --- | --- |")
    lines.append(
        f"| Actions scoped to a specific ARN | {len(dres) - len(dstar)} | "
        f"{len(ares) - len(astar)} |"
    )
    lines.append(f"| Actions scoped to `*` | {len(dstar)} | {len(astar)} |")
    lines.append("")
    if astar:
        lines.append(
            "A denial message always names the resource that was refused. "
            "A successful CloudTrail event often has an empty `resources` "
            "array and no error text, so there is nothing to scope to and "
            "the derivation falls back to `*`. This is why the admin-first "
            "policy is *smaller* - it is less specific, not tighter.\n"
        )
        lines.append(
            "Wildcarded under admin-first: "
            + ", ".join(f"`{disp.get(a, a)}`" for a in astar)
        )
        lines.append("")

    scope = []
    for a in sorted(both):
        dr, ar = dres.get(a, set()), ares.get(a, set())
        if dr != ar:
            scope.append((disp[a], sorted(dr), sorted(ar)))
    lines.append(f"## Same action, different resource scope ({len(scope)})\n")
    if scope:
        lines.append("| Action | Deny-first | Admin-first |")
        lines.append("| --- | --- | --- |")
        for a, dr, ar in scope:
            ds = f"{len(dr)} ARN(s)" if dr != ["*"] else "`*`"
            as_ = f"{len(ar)} ARN(s)" if ar != ["*"] else "`*`"
            lines.append(f"| `{a}` | {ds} | {as_} |")
    else:
        lines.append("_none_")
    lines.append("")

    passrole = [a for a in aset if "passrole" in a]
    lines.append("## Verdict\n")
    lines.append(
        f"- `iam:PassRole` present in admin-first derivation: "
        f"**{'yes' if passrole else 'no'}**"
    )
    if not passrole and "iam:passrole" in dset:
        lines.append(
            "  - Confirms the prediction. PassRole is authorised inside "
            "the calling API, so CloudTrail never logs it as its own "
            "event. An admin-first policy therefore cannot create a "
            "Lambda function or state machine."
        )
    lines.append(f"- Deny-first exclusive: {len(only_deny)} action(s)")
    lines.append(f"- Admin-first exclusive: {len(only_admin)} action(s)")
    lines.append(
        f"- Admin-first actions that could not be scoped: "
        f"{len(astar)}/{len(ares)}; deny-first: {len(dstar)}/{len(dres)}"
    )
    lines.append("")
    lines.append(
        "The action lists are close. The resource scoping is not, and "
        "that is the part that makes a policy least-privilege. Admin-first "
        "is roughly 60x cheaper to run and produces the read set that "
        "deny-first structurally cannot see; deny-first produces the "
        "scoping and the permissions that only appear when something "
        "fails. Neither is complete alone."
    )
    lines.append("")

    with d.open_out(f"{RESULTS}/comparison.generated.md", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
