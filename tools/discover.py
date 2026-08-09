#!/usr/bin/env python3
# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Least-privilege discovery loop.

Deploy the stack with a read-only CloudFormation service role, read the
AccessDenied failures back out of the stack events, add an Allow for exactly
the action + resource that was denied, and deploy again. Repeat until the
stack reaches CREATE_COMPLETE.
"""
import argparse
import calendar
import collections
import json
import os
import re
import subprocess
import sys
import time

# Resolve paths relative to this file so the tools keep working wherever the
# repo is checked out.
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import config  # noqa: E402  # pylint: disable=wrong-import-position

# Which account, region, stack and roles a run targets is configuration, not
# source: see config.py for where these come from and .env.example for how to
# set them. They stay module-level names because the other tools retarget the
# shared machinery by assigning to them (converge_admin.py points ROLE and
# POLICY_FILE at its own role and artifacts), and reconfigure() re-derives the
# whole set after a tool has parsed its command line.
ACCOUNT = ""
REGION = ""
LOOKUP_REGIONS = []
STACK = ""
ROLE = ""
ROLE_ARN = ""
CLEANUP_ROLE_ARN = ""
POLICY_NAME = ""
TEMPLATE = ""
PROJECT_NAME = ""
MAX_ITERS = 30
# How many times a wedged stack may be uninstalled before we give up.
MAX_UNINSTALLS = 3


def reconfigure():
    """Re-read config.py into this module's target constants.

    Call after `config.apply_args()` so that a flag passed on the command
    line reaches the machinery here. Deliberately does not touch POLICY_FILE
    or the other output paths: those are lifetimes, not targets, and
    converge_admin.py overrides them on purpose.
    """
    global ACCOUNT, REGION, LOOKUP_REGIONS, STACK, ROLE, ROLE_ARN
    global CLEANUP_ROLE_ARN, POLICY_NAME, TEMPLATE, PROJECT_NAME
    global MAX_ITERS, MAX_UNINSTALLS
    ACCOUNT = config.ACCOUNT
    REGION = config.REGION
    # Global-service events (IAM, STS, CloudFront, Route 53) always land in
    # us-east-1, so the harvest has to look there as well as in REGION.
    LOOKUP_REGIONS = config.LOOKUP_REGIONS
    STACK = config.STACK
    ROLE = config.ROLE
    ROLE_ARN = config.ROLE_ARN
    CLEANUP_ROLE_ARN = config.CLEANUP_ROLE_ARN
    POLICY_NAME = config.POLICY_NAME
    TEMPLATE = config.TEMPLATE
    PROJECT_NAME = config.PROJECT_NAME
    MAX_ITERS = config.MAX_ITERS
    MAX_UNINSTALLS = config.MAX_UNINSTALLS


reconfigure()

# Output is split by lifetime, not by producing script.
#
# RESULTS holds the curated artifacts: the derived policies, the summary, and
# the comparison. They are overwritten in place, they are what the README
# cites, and POLICY_FILE doubles as the resume state - so this path must stay
# stable across runs or a restart would rediscover everything.
#
# RUNDIR holds one directory per invocation for the append-mode logs and the
# raw CloudTrail stream. Timestamping them keeps two runs comparable instead of
# concatenated, and keeps a tracked working tree clean.
RESULTS = os.path.join(ARTIFACTS, "results")
# IAMD_RUN_DIR lets an orchestrator put every stage of one pipeline invocation
# into a single directory, instead of each tool minting its own timestamp.
RUNDIR = os.environ.get("IAMD_RUN_DIR") or os.path.join(
    ARTIFACTS, "runs", time.strftime("%Y-%m-%dT%H-%M-%S")
)

POLICY_FILE = f"{RESULTS}/deploy-policy.json"
# Losslessly compacted copy of POLICY_FILE; this is what gets attached to IAM.
COMPACT_FILE = f"{RESULTS}/deploy-policy.compact.json"
LOG_FILE = f"{RUNDIR}/iterations.md"
RAW_FILE = f"{RUNDIR}/cloudtrail-raw.jsonl"

# Log levels. Ordered so a threshold comparison is a plain integer test.
#
# TRACE   every AWS CLI invocation, argv and exit code
# DEBUG   what the filters discarded, and why
# INFO    the evidence trail: phases, grants, purges, milestones
# WARNING recoverable trouble - a lossy harvest, a forced deletion
# ERROR   the run cannot continue and is about to raise
L_TRACE, L_DEBUG, L_INFO, L_WARN, L_ERROR = 5, 10, 20, 30, 40
_LEVEL_NAMES = {
    "TRACE": L_TRACE,
    "DEBUG": L_DEBUG,
    "INFO": L_INFO,
    "WARNING": L_WARN,
    "ERROR": L_ERROR,
}

# IAMD_LOG_LEVEL takes a name or a number; IAMD_DEBUG=1 is kept as a shorthand
# for DEBUG so the flag committed earlier keeps working.
_env = (os.environ.get("IAMD_LOG_LEVEL") or "").strip().upper()
if _env.isdigit():
    LOG_LEVEL = int(_env)
elif _env in _LEVEL_NAMES:
    LOG_LEVEL = _LEVEL_NAMES[_env]
elif os.environ.get("IAMD_DEBUG"):
    LOG_LEVEL = L_DEBUG
else:
    LOG_LEVEL = L_INFO

DEBUG = LOG_LEVEL <= L_DEBUG
DEBUG_FILE = f"{RUNDIR}/debug.log"
_debug_counts = collections.Counter()

# action -> set of resource ARNs
granted = {}
# action -> set of phases ("create", "rollback", "delete") that required it
phases = {}
# Lowercased actions Access Analyzer rejected as INVALID_ACTION. They are inert
# by definition, so re-granting them buys nothing and costs a pass each time.
rejected = set()
# Template variant used to induce a mid-update failure for the rollback test.
BROKEN_TEMPLATE = os.path.join(HERE, "order-pipeline-broken.yaml")


def open_out(path, mode):
    """Open an output file, creating its directory on first write.

    Directories are made lazily so that merely importing this module - which
    compare_policies.py does purely to reuse its helpers - does not litter an
    empty run directory.

    Args:
        path: Destination file path.
        mode: Any text-mode flag accepted by `open`.

    Returns:
        An open text-mode file handle, UTF-8 encoded.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, mode, encoding="utf-8")


def log(msg, level=L_INFO):
    """Print a line and append it to a run log.

    INFO and above always reach `iterations.md` regardless of the console
    threshold, because that file is the evidence trail this project cites --
    filtering the console must never silently thin the record. TRACE and DEBUG
    go to `debug.log` instead, so diagnostics never dilute it.

    Args:
        msg: The line to record, already formatted.
        level: One of L_TRACE, L_DEBUG, L_INFO, L_WARN, L_ERROR.
    """
    if level >= LOG_LEVEL:
        print(msg, flush=True)
    dest = LOG_FILE if level >= L_INFO else DEBUG_FILE
    if level >= L_INFO or level >= LOG_LEVEL:
        with open_out(dest, "a") as fh:
            fh.write(msg + "\n")


def debug(category, msg):
    """Record something a filter discarded, when IAMD_DEBUG is set.

    Every filter in this module is a place a needed permission can vanish
    without trace, and a vanished permission looks exactly like one that was
    never needed. This writes the discard trail to its own file so the run log
    stays readable: the counts alone show whether a harvest is running close to
    the edge. One real example -- events:DescribeRule surfaced as a harvestable
    AccessDenied exactly once against 59 opaque UnknownError events for the
    same call.

    Args:
        category: Which filter dropped it, e.g. "errorcode" or "noaction".
        msg: What was dropped, with enough context to judge relevance.
    """
    if not DEBUG:
        return
    _debug_counts[category] += 1
    with open_out(DEBUG_FILE, "a") as fh:
        fh.write(f"[{category}] {msg}\n")


def debug_summary():
    """Log a per-category tally of everything the filters discarded."""
    if not DEBUG or not _debug_counts:
        return
    log(f"  discarded (see {DEBUG_FILE}):")
    for k, v in sorted(_debug_counts.items(), key=lambda kv: -kv[1]):
        log(f"    {k:22} {v}")


def aws(*args, check=False):
    """Run an `aws` CLI command in the configured region.

    Args:
        *args: Arguments appended after `aws --region REGION`.
        check: Raise RuntimeError on a nonzero exit instead of returning it.

    Returns:
        The completed subprocess result, stdout and stderr captured.

    Raises:
        RuntimeError: If `check` is true and the command exited nonzero.
    """
    r = subprocess.run(
        ["aws", "--region", REGION, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    # Every AWS interaction funnels through here, so this is the one place
    # that can show what was actually asked and what came back. Guarded on the
    # threshold because the message is not free and this runs thousands of
    # times per run.
    if LOG_LEVEL <= L_TRACE:
        detail = f"exit={r.returncode}"
        if r.returncode != 0:
            detail += f" stderr={r.stderr.strip()[:160]}"
        log(f"  $ aws {' '.join(args)}  -> {detail}", L_TRACE)
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r


def verify_account():
    """Abort unless the active credentials belong to the target account.

    Every ARN in this module is built from the ACCOUNT constant, but the CLI
    resolves credentials from the environment. If the two disagree, purge_all()
    would enumerate and delete resources in whichever account the credentials
    point at while every log line claimed otherwise. Call this before anything
    that mutates.

    Raises:
        RuntimeError: If the account is unconfigured, if credentials are
            missing, or if they name a different account.
    """
    # An unset target is caught here rather than at import: config.py has to
    # import cleanly with no configuration at all, so the check belongs at the
    # first point where not knowing the target would actually do damage. Every
    # mutating path reaches this function, which is what makes it the place.
    if not ACCOUNT:
        raise RuntimeError(
            "no target account configured: set IAMD_ACCOUNT in .env (see "
            ".env.example) or pass --account. Every ARN this tool builds, "
            "and every resource purge_all() deletes, is scoped by it."
        )
    if not STACK:
        raise RuntimeError(
            "no target stack configured: set IAMD_STACK in .env (see "
            ".env.example) or pass --stack. purge_all() deletes every "
            "resource whose name contains it across nine services, so "
            "defaulting it would scope a deletion to a string nobody chose."
        )
    r = aws(
        "sts", "get-caller-identity", "--query", "Account", "--output", "text"
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"cannot resolve AWS credentials: {r.stderr.strip()[:200]}"
        )
    active = (r.stdout or "").strip()
    if active != ACCOUNT:
        log(
            f"  !! account mismatch: credentials {active} != target {ACCOUNT}",
            L_ERROR,
        )
        raise RuntimeError(
            f"refusing to run: credentials are for account {active}, but the "
            f"configured target is {ACCOUNT}. Point AWS_PROFILE at a profile "
            f"in {ACCOUNT}, or change IAMD_ACCOUNT, and retry."
        )
    log(f"  verified credentials for account {active}")


# --- parsing -------------------------------------------------------------

DENY_PATTERNS = [
    re.compile(
        r"not authorized to perform:?\s*([A-Za-z0-9_\-]+:[A-Za-z0-9_\-\*]+)"
        r"(?:\s+on\s+resource:?\s*(.+?))?"
        r"(?:\s+because|\s+\(Service|\"|$)"
    ),
    re.compile(r"API:\s*([a-z0-9\-]+:[A-Za-z0-9]+)\s+Access Denied"),
]

IAM_ENTITY = re.compile(r"^(policy|role|user|group|instance profile)\s+(\S+)$")

# A UUID occupying the whole final ARN segment.
GENERATED_ID = re.compile(
    r"(?<=[:/])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
    r"-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)

# Resource types whose identifier is minted fresh on every deploy, so a
# captured one is dead on arrival and widening is the only terminating option.
#
# Matching UUID *shape* alone is not sufficient and was briefly wrong here: a
# KMS key id is also a UUID but is stable for the life of the key, so widening
# it to key/* grants every key in the account instead of one. A debug run
# caught the rule widening 48 KMS ARNs. Add a type here only when a fresh id
# really is minted per deploy.
EPHEMERAL_ID_TYPES = (":event-source-mapping:",)


def canon_resource(arn):
    """Correct ARN forms that AWS reports in errors but won't match in a policy.

    CloudWatch Logs reports log-group denials as
    `...:log-group:NAME:log-stream:`, but log-group-level actions authorize
    against `...:log-group:NAME:*`. Granting the reported string produces a
    statement that silently never matches.

    A generated identifier in the final segment is widened to `*`. The ID does
    not exist until the resource does and a fresh one is minted per deploy, so
    a captured value matches exactly once: the loop grants a dead ARN, hits the
    same denial next pass, grants another, and never terminates. Widening is
    the only terminating option, which is why it is done here rather than left
    as a manual fix.
    """
    if ":log-group:" in arn and arn.endswith(":log-stream:"):
        out = arn[: -len(":log-stream:")] + ":*"
        debug("rewrite", f"log-group form: {arn} -> {out}")
        return out
    m = GENERATED_ID.search(arn)
    if m:
        if any(t in arn for t in EPHEMERAL_ID_TYPES):
            out = arn[: m.start()] + "*"
            debug("rewrite", f"generated id: {arn} -> {out}")
            return out
        debug(
            "keptid",
            f"UUID-shaped but not a known per-deploy type, left scoped: {arn}",
        )
    # Repair a doubled prefix, e.g.
    # arn:aws:iam::123456789012:policy/arn:aws:iam::123456789012:policy/x
    i = arn.find("arn:", 4)
    if i > 0:
        debug("rewrite", f"doubled prefix: {arn} -> {arn[i:]}")
        return arn[i:]
    return arn


# The 12-digit account field of an ARN: arn:<partition>:<service>:<region>:
# <account>: -- anchored on the two colons so it cannot match a 12-digit
# resource name elsewhere in the string.
ARN_ACCOUNT = re.compile(r"(?<=:)\d{12}(?=:)")


def rehome_account(arn):
    """Rewrite the account field of an ARN to the configured account.

    The committed policy in results/ has two jobs: it is the published record
    of what was discovered, and it is the resume state the loop seeds from.
    Those jobs conflict, because publishing it means scrubbing the account ID
    out of it and a seed carrying a foreign account grants permissions on ARNs
    that can never match -- which looks exactly like a permission that was
    never discovered. Rewriting on the way in lets one artifact do both.

    Args:
        arn: A resource string, which may be a bare `*`.

    Returns:
        The ARN with its account field set to ACCOUNT, unchanged if there is
        no account field or no configured account.
    """
    if not ACCOUNT or not arn.startswith("arn:"):
        return arn
    out = ARN_ACCOUNT.sub(ACCOUNT, arn)
    if out != arn:
        debug("rehome", f"account rewritten: {arn} -> {out}")
    return out


def normalize_resource(raw):
    """Turn the resource fragment in an error message into an ARN.

    Args:
        raw: The resource text captured from a denial message, if any.

    Returns:
        An ARN, or `*` when the message named no resource.
    """
    if not raw:
        return "*"
    raw = raw.strip().strip('"').rstrip(".")
    if raw.startswith("arn:"):
        return raw
    m = IAM_ENTITY.match(raw)
    if m:
        kind, name = m.group(1), m.group(2)
        # AWS sometimes phrases this as "policy <full-arn>"; don't re-prefix.
        if name.startswith("arn:"):
            return name
        kind = {"instance profile": "instance-profile"}.get(kind, kind)
        return f"arn:aws:iam::{ACCOUNT}:{kind}/{name.lstrip('/')}"
    return "*"


def parse_denials(reasons):
    """Extract (action, resource) pairs from CloudFormation failure reasons.

    Args:
        reasons: Failure-reason strings, any of which may be empty.

    Returns:
        One (action, resource ARN) tuple per reason that matched a denial
        pattern; reasons that match nothing are dropped.
    """
    found = []
    for reason in reasons:
        if not reason:
            continue
        matched = False
        for pat in DENY_PATTERNS:
            m = pat.search(reason)
            if m:
                matched = True
                action = m.group(1)
                res = m.group(2) if m.lastindex and m.lastindex >= 2 else None
                found.append((action, normalize_resource(res)))
                break
        if not matched:
            debug("unparsed", reason.strip()[:140])
    return found


# --- CloudTrail (authoritative source) -----------------------------------

# eventSource prefix -> IAM action prefix, where they differ.
SOURCE_TO_PREFIX = {
    "monitoring": "cloudwatch",
    "events": "events",
    "logs": "logs",
    "tagging": "tag",
}

# Strip API version suffixes, e.g. GetFunction20150331v2 -> GetFunction
API_VERSION_SUFFIX = re.compile(r"\d{8}(v\d+)?$")

DENIAL_CODES = (
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
    "Forbidden",
)


_raw_ids = set()


def record_raw(event):
    """Append every streamed event to a JSONL file, deduped by eventID."""
    eid = event.get("eventID")
    if not eid or eid in _raw_ids:
        return
    _raw_ids.add(eid)
    with open_out(RAW_FILE, "a") as fh:
        fh.write(
            json.dumps(
                {
                    "eventTime": event.get("eventTime"),
                    "eventSource": event.get("eventSource"),
                    "eventName": event.get("eventName"),
                    "errorCode": event.get("errorCode"),
                    "errorMessage": (event.get("errorMessage") or "")[:400],
                    "arn": (event.get("userIdentity") or {}).get("arn"),
                    "resources": event.get("resources"),
                }
            )
            + "\n"
        )


def ct_action(event):
    """Map a CloudTrail event to its IAM action name.

    Args:
        event: A decoded CloudTrail event.

    Returns:
        An action such as `s3:CreateBucket`, or None if the event carries no
        usable source and name.
    """
    src = event.get("eventSource", "").split(".")[0]
    prefix = SOURCE_TO_PREFIX.get(src, src)
    name = API_VERSION_SUFFIX.sub("", event.get("eventName", ""))
    return f"{prefix}:{name}" if prefix and name else None


def ct_resource(event):
    """Prefer the structured resources field, else parse the error message."""
    for r in event.get("resources") or []:
        arn = r.get("ARN")
        if arn and arn.startswith("arn:"):
            return arn
    msg = event.get("errorMessage") or ""
    for pat in DENY_PATTERNS:
        m = pat.search(msg)
        if m and m.lastindex and m.lastindex >= 2 and m.group(2):
            return normalize_resource(m.group(2))
    return "*"


def cloudtrail_denials(start_epoch, settle_secs=420, poll=30):
    """Poll CloudTrail Event history for denials by our role since start_epoch.

    Management events land in Event history with several minutes of latency, so
    poll until the result set stops growing rather than reading once.
    """
    seen = {}
    stable = 0
    polls = 1
    total_events = 0
    # An event we fail to parse is a permission we may never discover, which
    # surfaces later as an unexplained deploy failure. Count them so a lossy
    # harvest is visible rather than looking like a clean one.
    undecodable = 0
    deadline = time.time() + settle_secs
    while time.time() < deadline:
        # No --max-results: the CLI auto-paginates the whole window. Capping it
        # silently dropped the oldest events, which is where denials collect.
        total_events = 0
        undecodable = 0
        # IAM, STS, CloudFront and Route 53 are global services: their events
        # are logged in us-east-1 regardless of where the stack lives, so a
        # region-pinned lookup cannot see any IAM denial.
        for region in LOOKUP_REGIONS:
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
            if r.returncode != 0:
                log(
                    f"  !! lookup-events ({region}) failed: "
                    f"{r.stderr.strip()[:200]}"
                )
                continue
            if not r.stdout.strip():
                continue
            try:
                blobs = json.loads(r.stdout)
            except json.JSONDecodeError as e:
                log(
                    f"  !! lookup-events ({region}) returned unparseable "
                    f"JSON, dropping the whole page: {e}"
                )
                blobs = []
            total_events += len(blobs)
            for blob in blobs:
                try:
                    e = json.loads(blob)
                except (json.JSONDecodeError, TypeError):
                    undecodable += 1
                    continue
                record_raw(e)
                code = e.get("errorCode")
                if code not in DENIAL_CODES:
                    if code:
                        debug(
                            "errorcode",
                            f"{code} on {ct_action(e)} -- not a denial code, "
                            f"dropped: {(e.get('errorMessage') or '')[:90]}",
                        )
                    continue
                arn = (e.get("userIdentity") or {}).get("arn", "")
                if ROLE not in arn:
                    debug("foreignrole", f"{ct_action(e)} by {arn[-70:]}")
                    continue
                action = ct_action(e)
                if not action:
                    debug(
                        "noaction",
                        f"source={e.get('eventSource')} "
                        f"name={e.get('eventName')} -- no IAM action derived",
                    )
                    continue
                res = ct_resource(e)
                if res == "*":
                    debug(
                        "unscoped",
                        f"{action} -- no resource in event, falling back to *",
                    )
                seen.setdefault(action, set()).add(res)
        count = sum(len(v) for v in seen.values())
        if count and count == stable:
            debug(
                "settle",
                f"stopping after {polls} poll(s): count held at {count} for "
                f"one interval. Management events land with minutes of "
                f"latency, so a denial arriving later than {poll}s is lost.",
            )
            break  # result set has settled
        if count != stable:
            debug("settle", f"poll {polls}: {stable} -> {count} grant(s)")
        stable = count
        polls += 1
        time.sleep(poll)
    else:
        debug(
            "settle", f"hit the {settle_secs}s deadline after {polls} poll(s)"
        )
    log(f"  streamed {total_events} CloudTrail event(s) in window")
    if undecodable:
        log(
            f"  !! {undecodable} event(s) could not be decoded and were "
            f"skipped; this harvest is incomplete"
        )
    # sorted(): `seen` maps to sets, whose iteration order varies per process.
    # Grant order drives the iteration log, so leave nothing to hash seeding.
    return [(a, r) for a in sorted(seen) for r in sorted(seen[a])]


# --- policy --------------------------------------------------------------


def seed_from_policy_file():
    """Resume from a previous run instead of rediscovering everything."""
    if not os.path.exists(POLICY_FILE):
        return
    try:
        doc = json.load(open(POLICY_FILE, encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log(f"  !! cannot read resume state {POLICY_FILE}: {e}", L_ERROR)
        # Returning quietly here looks identical to "no prior run": the loop
        # restarts from zero and re-derives everything, or pushes an empty
        # policy over a good one. A resume that cannot read its own state is
        # a failure, not a fresh start.
        raise RuntimeError(
            f"cannot seed from {POLICY_FILE}: {e}. Move or repair the file "
            f"to start a genuinely fresh run."
        ) from e
    for stmt in doc.get("Statement", []):
        actions = stmt.get("Action")
        actions = [actions] if isinstance(actions, str) else actions or []
        resources = stmt.get("Resource")
        resources = (
            [resources] if isinstance(resources, str) else resources or []
        )
        for a in actions:
            granted.setdefault(a, set()).update(
                canon_resource(rehome_account(r)) for r in resources
            )
    log(f"  seeded {len(granted)} action(s) from {POLICY_FILE}")


def build_policy():
    """Render the accumulated grants as one statement per action.

    Returns:
        A policy document with a generated Sid per statement. This is the
        record of what was observed; `compact_policy` produces what is pushed.
    """
    stmts = []
    for action in sorted(granted):
        resources = sorted(granted[action])
        if "*" in resources:
            if len(resources) > 1:
                debug(
                    "widened",
                    f"{action}: '*' present, discarding "
                    f"{len(resources) - 1} specific ARN(s) -- the scoping for "
                    f"this action is lost from here on",
                )
            resources = ["*"]
        stmts.append(
            {
                "Sid": "Allow" + re.sub(r"[^A-Za-z0-9]", "", action),
                "Effect": "Allow",
                "Action": action,
                "Resource": resources if len(resources) > 1 else resources[0],
            }
        )
    return {"Version": "2012-10-17", "Statement": stmts}


def as_list(v):
    """Wrap a bare IAM policy value in a list.

    Action and Resource may each be a string or a list of strings.

    Args:
        v: The raw field value.

    Returns:
        `v` if it is already a list, otherwise a one-element list.
    """
    return v if isinstance(v, list) else [v]


def _shrink(v):
    """A single-element list adds bytes for nothing."""
    v = sorted(v)
    return v[0] if len(v) == 1 else v


def expand(doc):
    """Flatten a policy to its (effect, action, resource) triples.

    Two documents that expand to the same set are equivalent, whatever their
    statement structure. Used to prove compaction is lossless.
    """
    out = set()
    for st in doc["Statement"]:
        for a in as_list(st["Action"]):
            for r in as_list(st["Resource"]):
                out.add((st.get("Effect", "Allow"), a.lower(), r))
    return out


def compact_policy(doc):
    """Losslessly shrink a policy so it fits inside IAM's size limits.

    Per-ARN scoping is what makes the discovered policy worth having, and it is
    also what makes it big. Rather than widening grants to save bytes,
    restructure them: drop the generated Sids, then collapse statements that
    share a resource
    set (and afterwards, those that share an action set). The action x resource
    cross-product is untouched, so the policy grants exactly what it did before.
    """
    by_resource = {}
    for st in doc["Statement"]:
        key = tuple(sorted(as_list(st["Resource"])))
        by_resource.setdefault(key, []).extend(as_list(st["Action"]))

    by_action = {}
    for resources, actions in by_resource.items():
        by_action.setdefault(tuple(sorted(set(actions))), []).extend(resources)

    stmts = [
        {
            "Effect": "Allow",
            "Action": _shrink(set(actions)),
            "Resource": _shrink(set(resources)),
        }
        for actions, resources in by_action.items()
    ]
    stmts.sort(key=lambda s: json.dumps(s["Action"]))
    return {"Version": "2012-10-17", "Statement": stmts}


INVALID_ACTION_RE = re.compile(r"The action (\S+?) does not exist")


def static_scan(doc):
    """Run IAM Access Analyzer over a policy and drop actions it rejects.

    Denial messages are not a reliable source of IAM action names: CloudTrail
    reports API names, which for several S3 operations differ from the action
    that actually authorizes them (PutBucketEncryption vs
    PutEncryptionConfiguration). Those names are syntactically fine and grant
    nothing, so they survive review while quietly doing nothing.

    Access Analyzer knows the real action list. Anything it flags INVALID_ACTION
    is inert by definition, so dropping it costs no access and keeps a policy we
    cannot vouch for from ever reaching IAM.
    """
    body = json.dumps(doc, separators=(",", ":"))
    r = aws(
        "accessanalyzer",
        "validate-policy",
        "--policy-type",
        "IDENTITY_POLICY",
        "--policy-document",
        body,
        "--query",
        "findings[].[findingType,issueCode,findingDetails]",
        "--output",
        "json",
    )
    if r.returncode != 0:
        log(
            f"  !! static scan unavailable, pushing unscanned: "
            f"{r.stderr.strip()[:140]}"
        )
        return doc, []

    try:
        findings = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return doc, []

    bad = set()
    for ftype, code, detail in findings:
        if ftype == "ERROR" and code == "INVALID_ACTION":
            m = INVALID_ACTION_RE.search(detail or "")
            if m:
                bad.add(m.group(1).lower())
        elif ftype == "ERROR":
            log(f"  !! static scan {code}: {(detail or '')[:140]}", L_WARN)
        else:
            # SECURITY_WARNING and SUGGESTION are dropped on the floor. For a
            # least-privilege tool they are the most on-topic thing Access
            # Analyzer says -- "pass role with star resource" and friends.
            debug("scanfinding", f"{ftype}/{code}: {(detail or '')[:120]}")

    if not bad:
        return doc, []

    cleaned = []
    for st in doc["Statement"]:
        actions = [a for a in as_list(st["Action"]) if a.lower() not in bad]
        if actions:
            cleaned.append({**st, "Action": _shrink(set(actions))})
    for a in sorted(bad):
        log(f"  static scan dropped invalid action: {a}")
    return {"Version": "2012-10-17", "Statement": cleaned}, sorted(bad)


def push_policy():
    """Write the full policy, then attach a compacted copy to the role.

    Two artifacts on purpose: the full document is the auditable record (one
    statement per action, exact ARNs, Sids intact), while the compact one is
    what IAM actually gets, because an inline role policy is capped at 10,240
    bytes.

    Raises:
        RuntimeError: If the active credentials are not for ACCOUNT.
    """
    # Guard here, not only at the entry points. This is the function that
    # mutates IAM, and anything importing this module can reach it directly --
    # a test harness calling record() once overwrote a live policy in another
    # account because the entry-point check was never on the path.
    verify_account()
    doc = build_policy()
    with open_out(POLICY_FILE, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    if not doc["Statement"]:
        return

    lean = compact_policy(doc)
    if expand(lean) != expand(doc):
        # Never ship a policy we cannot prove equivalent; fall back to the
        # verbatim document and let the size check deal with it.
        log(
            "  !! compaction changed policy semantics; using full document",
            L_WARN,
        )
        lean = {
            "Version": "2012-10-17",
            "Statement": [
                {k: v for k, v in st.items() if k != "Sid"}
                for st in doc["Statement"]
            ],
        }

    # Nothing reaches IAM without passing a static scan first.
    lean, dropped = static_scan(lean)
    for a in dropped:
        granted.pop(next((k for k in granted if k.lower() == a), ""), None)
        # Remember it. Popping alone means the next denial re-adds the action,
        # the scan drops it again, and the pair loops forever -- burning a pass
        # each time and, worse, making record() report new grants every pass so
        # the "no new permissions" stall check can never fire.
        rejected.add(a)

    with open_out(COMPACT_FILE, "w") as fh:
        json.dump(lean, fh, indent=2)
        fh.write("\n")
    compact = json.dumps(lean, separators=(",", ":"))

    if len(compact) <= 10000:
        r = subprocess.run(
            [
                "aws",
                "--region",
                REGION,
                "iam",
                "put-role-policy",
                "--role-name",
                ROLE,
                "--policy-name",
                POLICY_NAME,
                "--policy-document",
                compact,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode == 0:
            log(
                f"  -> policy updated on {ROLE}: {len(doc['Statement'])} "
                f"statements -> {len(lean['Statement'])} compacted "
                f"({len(compact)}b of 10240)"
            )
            return
        log(f"  !! put-role-policy failed: {r.stderr.strip()[:160]}")

    push_as_managed(lean, len(doc["Statement"]))


def push_as_managed(lean, n_statements):
    """Split the policy across managed policies and attach them to the role."""
    chunks, cur = [], []
    for st in lean["Statement"]:
        trial = cur + [st]
        size = len(
            json.dumps(
                {"Version": "2012-10-17", "Statement": trial},
                separators=(",", ":"),
            )
        )
        if size > 5800 and cur:
            chunks.append(cur)
            cur = [st]
        else:
            cur = trial
    if cur:
        chunks.append(cur)

    # Detach and delete the previous generation so we never exceed 10 attached.
    existing = (
        aws(
            "iam",
            "list-attached-role-policies",
            "--role-name",
            ROLE,
            "--query",
            f"AttachedPolicies[?starts_with(PolicyName,"
            f"`{POLICY_NAME}-`)].PolicyArn",
            "--output",
            "text",
        ).stdout
        or ""
    ).split()
    for arn in existing:
        aws(
            "iam",
            "detach-role-policy",
            "--role-name",
            ROLE,
            "--policy-arn",
            arn,
        )
        aws("iam", "delete-policy", "--policy-arn", arn)
    aws(
        "iam",
        "delete-role-policy",
        "--role-name",
        ROLE,
        "--policy-name",
        POLICY_NAME,
    )

    for i, chunk in enumerate(chunks, 1):
        body = json.dumps(
            {"Version": "2012-10-17", "Statement": chunk}, separators=(",", ":")
        )
        name = f"{POLICY_NAME}-{i}"
        r = aws(
            "iam",
            "create-policy",
            "--policy-name",
            name,
            "--policy-document",
            body,
            "--query",
            "Policy.Arn",
            "--output",
            "text",
        )
        arn = (r.stdout or "").strip()
        if r.returncode != 0 or not arn.startswith("arn:"):
            log(f"  !! create-policy {name} failed: {r.stderr.strip()[:160]}")
            continue
        a = aws(
            "iam",
            "attach-role-policy",
            "--role-name",
            ROLE,
            "--policy-arn",
            arn,
        )
        if a.returncode != 0:
            log(f"  !! attach {name} failed: {a.stderr.strip()[:160]}")
    log(
        f"  -> policy updated on {ROLE}: {n_statements} statements "
        f"across {len(chunks)} managed policies"
    )


# --- stack ---------------------------------------------------------------


def stack_status():
    """Return the stack's current status, or None if it does not exist."""
    r = aws(
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        STACK,
        "--query",
        "Stacks[0].StackStatus",
        "--output",
        "text",
    )
    return r.stdout.strip() if r.returncode == 0 else None


def teardown():
    """Delete the stack using the admin cleanup role so rollback isn't blocked.

    CloudFormation refuses a delete while a rollback is still in flight, so wait
    out any *_IN_PROGRESS state and (re)issue the delete once the stack settles.
    """
    requested = False
    retained = False
    for _ in range(240):
        s = stack_status()
        if s is None:
            return
        if s.endswith("_IN_PROGRESS"):
            time.sleep(5)
            continue

        if s == "DELETE_FAILED":
            # Documented recovery: re-run the delete naming the stuck resources
            # in RetainResources. CloudFormation drops the stack and leaves
            # them.
            stuck = failed_deletes()
            if stuck and not retained:
                log(
                    f"  DELETE_FAILED; retrying with --retain-resources {stuck}"
                )
                aws(
                    "cloudformation",
                    "delete-stack",
                    "--stack-name",
                    STACK,
                    "--role-arn",
                    CLEANUP_ROLE_ARN,
                    "--retain-resources",
                    *stuck,
                )
                retained = True
                time.sleep(10)
                continue
            log("  !! DELETE_FAILED persists; forcing stack deletion", L_WARN)
            aws(
                "cloudformation",
                "delete-stack",
                "--stack-name",
                STACK,
                "--deletion-mode",
                "FORCE_DELETE_STACK",
            )
            time.sleep(10)
            continue

        if s == "UPDATE_ROLLBACK_FAILED":
            # A change set cannot even be created in this state; the rollback
            # has to be continued (skipping what cannot be rolled back) first.
            stuck = failed_resources()
            log(
                f"  UPDATE_ROLLBACK_FAILED; "
                f"continue-update-rollback skip={stuck}"
            )
            args = [
                "cloudformation",
                "continue-update-rollback",
                "--stack-name",
                STACK,
                "--role-arn",
                CLEANUP_ROLE_ARN,
            ]
            if stuck:
                args += ["--resources-to-skip", *stuck]
            aws(*args)
            time.sleep(10)
            continue

        # Settled in some terminal state -> safe to ask for deletion.
        r = aws(
            "cloudformation",
            "delete-stack",
            "--stack-name",
            STACK,
            "--role-arn",
            CLEANUP_ROLE_ARN,
        )
        if r.returncode != 0 and requested:
            log(f"  !! delete-stack rejected: {r.stderr.strip()[:200]}")
            return
        requested = True
        time.sleep(5)
    log("  !! teardown timed out", L_WARN)


def purge_orphans():
    """Delete resources CloudFormation gave up on.

    Per the AWS docs, CloudFormation tries a resource delete three times, then
    drops it from the stack and moves on - it never retries. Anything left
    behind must be removed through the owning service or it will collide with
    the next create (named IAM roles and queues are not reusable).
    """
    r = aws(
        "iam",
        "list-roles",
        "--query",
        f"Roles[?contains(RoleName,`{STACK}`)].RoleName",
        "--output",
        "text",
    )
    for name in (r.stdout or "").split():
        delete_role(name)


purged_queue = [False]


def purge_all():
    """Remove every account resource this stack names, tracked or not.

    Once CloudFormation abandons a resource it keeps the physical object but
    stops managing it. Because the template hard-codes names (RoleName,
    BucketName, TableName...), the next create collides with AlreadyExists and
    fails pre-deployment validation - no permission is ever exercised, so the
    loop sees a stall it cannot escape. The only way forward is a real
    uninstall.
    """
    log("  purging all orphaned resources for a clean reinstall")

    for name in (
        aws(
            "iam",
            "list-roles",
            "--query",
            f"Roles[?contains(RoleName,`{STACK}`)].RoleName",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        delete_role(name)

    for arn in (
        aws(
            "iam",
            "list-policies",
            "--scope",
            "Local",
            "--query",
            f"Policies[?contains(PolicyName,`{STACK}`)].Arn",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        for v in (
            aws(
                "iam",
                "list-policy-versions",
                "--policy-arn",
                arn,
                "--query",
                "Versions[?!IsDefaultVersion].VersionId",
                "--output",
                "text",
            ).stdout
            or ""
        ).split():
            aws(
                "iam",
                "delete-policy-version",
                "--policy-arn",
                arn,
                "--version-id",
                v,
            )
        if aws("iam", "delete-policy", "--policy-arn", arn).returncode == 0:
            log(f"  purged policy {arn.rsplit('/', 1)[-1]}")

    for g in (
        aws(
            "logs",
            "describe-log-groups",
            "--log-group-name-prefix",
            f"/aws/lambda/{STACK}",
            "--query",
            "logGroups[].logGroupName",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        aws("logs", "delete-log-group", "--log-group-name", g)
        log(f"  purged log group {g}")

    for b in (
        aws(
            "s3api",
            "list-buckets",
            "--query",
            f"Buckets[?contains(Name,`{STACK}`)].Name",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        subprocess.run(
            ["aws", "s3", "rm", f"s3://{b}", "--recursive"],
            capture_output=True,
            text=True,
            check=False,
        )
        if aws("s3api", "delete-bucket", "--bucket", b).returncode == 0:
            log(f"  purged bucket {b}")

    for q in (
        aws(
            "sqs",
            "list-queues",
            "--queue-name-prefix",
            STACK,
            "--query",
            "QueueUrls",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        if q.startswith("http"):
            aws("sqs", "delete-queue", "--queue-url", q)
            purged_queue[0] = True
            log(f"  purged queue {q.rsplit('/', 1)[-1]}")

    for t in (
        aws(
            "sns",
            "list-topics",
            "--query",
            f"Topics[?contains(TopicArn,`{STACK}`)].TopicArn",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        aws("sns", "delete-topic", "--topic-arn", t)
        log(f"  purged topic {t.rsplit(':', 1)[-1]}")

    for t in (
        aws(
            "dynamodb",
            "list-tables",
            "--query",
            f"TableNames[?contains(@,`{STACK}`)]",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        aws("dynamodb", "delete-table", "--table-name", t)
        log(f"  purged table {t}")

    for fn in (
        aws(
            "lambda",
            "list-functions",
            "--query",
            f"Functions[?contains(FunctionName,`{STACK}`)].FunctionName",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        aws("lambda", "delete-function", "--function-name", fn)
        log(f"  purged function {fn}")

    # Event source mappings outlive their function and collide by (queue,
    # function) pair, not by name, so a stale one returns 409 AlreadyExists
    # and names a UUID the template cannot know. Nothing else purges them.
    for uuid in (
        aws(
            "lambda",
            "list-event-source-mappings",
            "--query",
            f"EventSourceMappings[?contains(EventSourceArn,`{STACK}`)].UUID",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        if (
            aws(
                "lambda", "delete-event-source-mapping", "--uuid", uuid
            ).returncode
            == 0
        ):
            log(f"  purged event source mapping {uuid}")

    # EventBridge rules must have their targets removed first, exactly as roles
    # must be stripped of policies. Omitting this service stalled a full run:
    # an orphaned rule collides with AlreadyExists, which is not a denial, so
    # the loop learns nothing and burns its uninstall budget on a purge that
    # cannot reach the offending resource.
    for r in (
        aws(
            "events",
            "list-rules",
            "--name-prefix",
            STACK,
            "--query",
            "Rules[].Name",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        ids = (
            aws(
                "events",
                "list-targets-by-rule",
                "--rule",
                r,
                "--query",
                "Targets[].Id",
                "--output",
                "text",
            ).stdout
            or ""
        ).split()
        if ids:
            aws("events", "remove-targets", "--rule", r, "--ids", *ids)
        if aws("events", "delete-rule", "--name", r).returncode == 0:
            log(f"  purged rule {r}")

    for sm in (
        aws(
            "stepfunctions",
            "list-state-machines",
            "--query",
            f"stateMachines[?contains(name,`{STACK}`)].stateMachineArn",
            "--output",
            "text",
        ).stdout
        or ""
    ).split():
        if (
            aws(
                "stepfunctions",
                "delete-state-machine",
                "--state-machine-arn",
                sm,
            ).returncode
            == 0
        ):
            log(f"  purged state machine {sm.rsplit(':', 1)[-1]}")

    # SQS deletes are eventually consistent: a queue name stays reserved for
    # ~60s afterwards. Only pay that wait when a queue was actually removed.
    if purged_queue[0]:
        purged_queue[0] = False
        time.sleep(65)


def delete_role(name):
    """IAM roles must be stripped of policies before they can be deleted."""
    pol = aws(
        "iam",
        "list-attached-role-policies",
        "--role-name",
        name,
        "--query",
        "AttachedPolicies[].PolicyArn",
        "--output",
        "text",
    )
    for arn in (pol.stdout or "").split():
        aws(
            "iam",
            "detach-role-policy",
            "--role-name",
            name,
            "--policy-arn",
            arn,
        )
    inline = aws(
        "iam",
        "list-role-policies",
        "--role-name",
        name,
        "--query",
        "PolicyNames",
        "--output",
        "text",
    )
    for pname in (inline.stdout or "").split():
        aws(
            "iam",
            "delete-role-policy",
            "--role-name",
            name,
            "--policy-name",
            pname,
        )
    r = aws("iam", "delete-role", "--role-name", name)
    log(
        f"  purged orphan role {name}"
        if r.returncode == 0
        else f"  !! could not purge role {name}: {r.stderr.strip()[:120]}"
    )


def failure_reasons(since=None):
    """Failed-resource events, optionally limited to those after `since`.

    describe-stack-events returns the stack's entire history, so without a
    time filter every pass re-parses denials from earlier iterations.
    """
    r = aws(
        "cloudformation",
        "describe-stack-events",
        "--stack-name",
        STACK,
        "--query",
        "StackEvents[?ResourceStatus==`CREATE_FAILED`"
        "||ResourceStatus==`UPDATE_FAILED`"
        "||ResourceStatus==`DELETE_FAILED`]"
        ".[LogicalResourceId,ResourceStatusReason,Timestamp]",
        "--output",
        "json",
    )
    if r.returncode != 0:
        return []
    rows = json.loads(r.stdout or "[]")
    out = []
    for row in rows:
        lid, reason = row[0], row[1]
        ts = row[2] if len(row) > 2 else None
        if since and ts:
            try:
                # Stack event timestamps are UTC; timegm converts a UTC
                # struct_time directly. mktime assumes local time and its
                # time.timezone correction is wrong under DST.
                when = calendar.timegm(
                    time.strptime(ts.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                )
                if when < since:
                    continue
            except (ValueError, TypeError):
                pass
        out.append([lid, reason])

    # The time filter above stops stale denials being re-parsed every pass, but
    # it also hides denials belonging to resources that are *persistently*
    # failed: the event fired once, in a window that has since closed, while
    # the resource stays stuck. A run wedged for two iterations on an
    # iam:DeleteRole ARN that was readable here the whole time. Current
    # resource state carries no timestamp, so it is never filtered out.
    r = aws(
        "cloudformation",
        "describe-stack-resources",
        "--stack-name",
        STACK,
        "--query",
        "StackResources[?ends_with(ResourceStatus,`_FAILED`)]"
        ".[LogicalResourceId,ResourceStatusReason]",
        "--output",
        "json",
    )
    if r.returncode == 0:
        seen = {(lid, reason) for lid, reason in out}
        for row in json.loads(r.stdout or "[]"):
            lid, reason = row[0], row[1]
            if reason and (lid, reason) not in seen:
                out.append([lid, reason])
    return out


def deploy(template=None, disable_rollback=True):
    """Deploy the stack with the test role.

    Args:
        template: Path to the template to deploy. Defaults to the configured
            template, resolved at call time rather than as a default argument
            value: the default would bind at import, before a tool has parsed
            the command line that may have changed it.
        disable_rollback: Leave a failed stack in place so its denials can be
            harvested, instead of unwinding it immediately.

    Returns:
        The completed `aws cloudformation deploy` subprocess result.
    """
    cmd = [
        "aws",
        "--region",
        REGION,
        "cloudformation",
        "deploy",
        "--stack-name",
        STACK,
        "--template-file",
        template or TEMPLATE,
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        "--parameter-overrides",
        "Environment=dev",
        f"ProjectName={PROJECT_NAME}",
        "--role-arn",
        ROLE_ARN,
        "--no-fail-on-empty-changeset",
    ]
    if disable_rollback:
        cmd.append("--disable-rollback")
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def wait_terminal(timeout=1800):
    """Block until the stack leaves any *_IN_PROGRESS state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = stack_status()
        if s is None or not s.endswith("_IN_PROGRESS"):
            return s
        time.sleep(10)
    return stack_status()


def harvest(started, label):
    """Collect denials from CloudTrail (authoritative) + stack events."""
    events = failure_reasons(since=started)
    stack_denials = parse_denials([e[1] for e in events])
    log(f"  [{label}] stack events: {len(stack_denials)} denial(s)")
    log("  polling CloudTrail...")
    ct_denials = cloudtrail_denials(started)
    log(f"  [{label}] cloudtrail: {len(ct_denials)} denial(s)")

    # Dedup by (action, resource), not action alone. CloudTrail's structured
    # resources field is not always the resource IAM actually authorizes
    # against: lambda:CreateEventSourceMapping reports the function ARN there,
    # while the real authorizing resource - visible only in the stack-event
    # message text - is the event-source-mapping ARN. Deduping by action name
    # silently discarded that correct grant every pass because CloudTrail
    # "already had an answer" for the action, wedging a live run for 15
    # iterations across all three uninstalls until deny_first gave up.
    ct_pairs = {(a.lower(), r) for a, r in ct_denials}
    denials = list(ct_denials)
    for action, res in stack_denials:
        if (action.lower(), res) not in ct_pairs:
            log(f"  (stack-events only: {action} -> {res})")
            denials.append((action, res))
    return denials


def record(denials, phase):
    """Merge denials into the policy. Returns count of newly added grants."""
    new = 0
    for action, resource in denials:
        if action.lower() in rejected:
            continue
        resource = canon_resource(resource)
        key = next((k for k in granted if k.lower() == action.lower()), action)
        bucket = granted.setdefault(key, set())
        if resource not in bucket:
            bucket.add(resource)
            phases.setdefault(key, set()).add(phase)
            new += 1
            log(f"  + [{phase}] {key}  ->  {resource}")
    if new:
        push_policy()
        time.sleep(12)  # IAM propagation
    return new


# --- main ----------------------------------------------------------------


def completed_resources():
    """How many stack resources are fully provisioned."""
    r = aws(
        "cloudformation",
        "describe-stack-resources",
        "--stack-name",
        STACK,
        "--query",
        "length(StackResources[?ResourceStatus==`CREATE_COMPLETE`"
        "||ResourceStatus==`UPDATE_COMPLETE`])",
        "--output",
        "text",
    )
    try:
        return int((r.stdout or "0").strip())
    except ValueError:
        return 0


def failed_resources():
    """Logical IDs in any *_FAILED state."""
    r = aws(
        "cloudformation",
        "describe-stack-resources",
        "--stack-name",
        STACK,
        "--query",
        "StackResources[?ends_with(ResourceStatus,`_FAILED`)]"
        ".LogicalResourceId",
        "--output",
        "text",
    )
    return [x for x in (r.stdout or "").split() if x]


def failed_deletes():
    """Logical IDs stuck in DELETE_FAILED.

    CloudFormation skips these on the next pass.
    """
    r = aws(
        "cloudformation",
        "describe-stack-resources",
        "--stack-name",
        STACK,
        "--query",
        "StackResources[?ResourceStatus==`DELETE_FAILED`]" ".LogicalResourceId",
        "--output",
        "text",
    )
    return [x for x in (r.stdout or "").split() if x]


def phase_create():
    """Deploy with --disable-rollback until the stack reaches CREATE_COMPLETE.

    Rollback is off so successfully-created resources persist between passes;
    each iteration therefore advances one dependency layer deeper instead of
    rebuilding the whole stack from scratch.
    """
    last_done = [completed_resources()]
    uninstalls = [0]
    for i in range(1, MAX_ITERS + 1):
        log(f"\n## [create] Iteration {i}  ({time.strftime('%H:%M:%S')})")
        # A previous operation may still be executing server-side; deploying
        # into that gets rejected outright and harvests a half-finished stack.
        wait_terminal()
        started = time.time() - 60
        r = deploy(disable_rollback=True)
        if r.returncode == 0:
            log("  ** CREATE COMPLETE **")
            return True

        err = (r.stderr or "") + (r.stdout or "")
        # deploy can return before CloudFormation settles; let it finish so we
        # harvest a complete set of denials rather than a partial one.
        status = wait_terminal()
        log(f"  stack status: {status}")

        new = record(harvest(started, "create"), "create")

        done = completed_resources()
        progressed = done > last_done[0]
        last_done[0] = done

        why = stuck_reason(err, status, new, progressed)
        if why is None:
            # Normal pass: we learned something, or resources are still landing.
            continue

        # A pass that fails with no new denials can still be healthy if
        # CloudFormation is skipping resources it already gave up deleting.
        if (
            not progressed
            and new == 0
            and failed_deletes()
            and uninstalls[0] == 0
        ):
            log(
                f"  {len(failed_deletes())} resource(s) in DELETE_FAILED; "
                f"one more pass before uninstalling"
            )
            uninstalls[0] = -1  # allow exactly one grace pass
            continue

        if uninstalls[0] >= MAX_UNINSTALLS:
            log(
                f"  !! still stuck after {MAX_UNINSTALLS} uninstalls: {why}",
                L_WARN,
            )
            for lid, reason in failure_reasons()[:10]:
                log(f"    {lid}: {(reason or '')[:300]}")
            log(f"  deploy stderr: {err.strip()[:500]}")
            # phase_uninstall() escalates to admin credentials only within its
            # own retry loop, when the test role stops yielding new
            # permissions mid-teardown. It does not run again here, so giving
            # up at this outer level previously left whatever partial stack
            # existed live in the account - discovered once, as a stack still
            # standing after an --all pipeline run exited nonzero and halted
            # before its teardown stage. A failed discovery run must not also
            # leave a mess: force a clean teardown with admin credentials
            # before reporting failure, the same guarantee a successful run
            # gets from phase_delete().
            log(
                "  forcing cleanup with admin credentials before giving up",
                L_WARN,
            )
            teardown()
            purge_all()
            return False

        uninstalls[0] = max(uninstalls[0], 0) + 1
        log(
            f"  STUCK ({why}) - uninstalling with the discovered policy "
            f"[{uninstalls[0]}/{MAX_UNINSTALLS}]"
        )
        phase_uninstall(why)
        last_done[0] = 0

    log("  hit MAX_ITERS in create phase")
    return False


def phase_uninstall(reason, max_passes=8):
    """Uninstall the stack using the TEST role, discovering delete permissions.

    Called when in-place retries wedge. Deleting with the test role means the
    teardown is itself a discovery pass: every denial it hits is a permission a
    real deploy role genuinely needs to unwind a failed deployment. Falling back
    to the admin role would clear the stack but teach us nothing.

    Only if the test role cannot finish the job - after it stops yielding new
    permissions - do we force it with admin credentials so the loop can proceed.
    """
    log(f"\n## [uninstall] {reason}  ({time.strftime('%H:%M:%S')})")
    for i in range(1, max_passes + 1):
        if stack_status() is None:
            log("  ** UNINSTALL COMPLETE (test role) **")
            purge_all()
            return True

        started = time.time() - 60
        r = aws(
            "cloudformation",
            "delete-stack",
            "--stack-name",
            STACK,
            "--role-arn",
            ROLE_ARN,
        )
        if r.returncode != 0:
            log(f"  delete-stack rejected: {r.stderr.strip()[:200]}")
        status = wait_terminal()
        log(f"  pass {i}: stack status {status}")

        if status is None:
            log("  ** UNINSTALL COMPLETE (test role) **")
            purge_all()
            return True

        new = record(harvest(started, "delete"), "delete")
        if new == 0:
            log(
                f"  test role cannot uninstall further after {i} pass(es); "
                f"forcing with admin credentials"
            )
            break

    teardown()
    purge_all()
    return stack_status() is None


def stuck_reason(err, status, new, progressed):
    """Classify why a create pass failed, or None if it is still healthy.

    Distinguishes 'needs another permission' (normal, keep going) from
    'structurally wedged' (no permission grant can fix this).
    """
    if (
        "AlreadyExists" in err
        or "already exists" in err
        or "ResourceExistenceCheck" in err
    ):
        return "orphaned resources collide with the changeset"
    if status in (
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "DELETE_FAILED",
    ):
        return f"stack in unrecoverable state {status}"
    if "can not be updated" in err:
        return "stack cannot be updated in place"
    if new == 0 and not progressed:
        return "no new permissions and no resource progress"
    # Healthy: the pass failed but learned something. This is the branch that
    # keeps the loop going, so when a run does not terminate it is the one to
    # check -- a phantom grant counted as `new` reads as progress and defers
    # recovery indefinitely.
    debug(
        "notstuck",
        f"status={status} new={new} progressed={progressed} -- "
        f"treating as healthy, continuing",
    )
    return None


def phase_rollback():
    """Exercise the update-rollback path with a deliberately broken template.

    Rollback is left ENABLED so CloudFormation unwinds the failed update; that
    path needs a different action set than a clean create.
    """
    log(
        f"\n## [rollback] inducing update failure  "
        f"({time.strftime('%H:%M:%S')})"
    )
    with open(TEMPLATE, encoding="utf-8") as fh:
        body = fh.read()
    # The probe is a Resource, so it has to go before the Outputs block.
    # Appending to the end of the file buries it under Outputs and produces a
    # template CloudFormation rejects outright.
    head, sep, tail = body.partition("\nOutputs:")
    # The probe has to survive pre-deployment validation and fail during the
    # resource operation - a template CloudFormation rejects up front never
    # starts an update, so nothing rolls back and the phase learns nothing.
    # A FIFO queue whose name lacks the required ".fifo" suffix is accepted by
    # the template checker and rejected by SQS at create time.
    probe = """
  RollbackProbeQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub "${ProjectName}-${Environment}-rollback-probe"
      FifoQueue: true
"""
    with open(BROKEN_TEMPLATE, "w", encoding="utf-8") as fh:
        fh.write(head + probe + sep + tail)

    # This template is generated, so validate it. The probe must fail during the
    # resource operation, not at parse time: a malformed template also makes
    # `deploy` return non-zero, which is indistinguishable from a successful
    # induction and silently turns this phase into a no-op.
    v = aws(
        "cloudformation",
        "validate-template",
        "--template-body",
        f"file://{BROKEN_TEMPLATE}",
    )
    if v.returncode != 0:
        log(
            f"  !! probe template is invalid, skipping rollback phase: "
            f"{v.stderr.strip()[:200]}"
        )
        return
    lint = subprocess.run(
        ["cfn-lint", BROKEN_TEMPLATE],
        capture_output=True,
        text=True,
        check=False,
    )
    if lint.returncode not in (0, 4):  # 4 = informational only
        log(
            f"  !! cfn-lint rejected the probe template, skipping rollback: "
            f"{(lint.stdout or lint.stderr).strip()[:200]}"
        )
        return

    for i in range(1, 8):
        log(f"  rollback pass {i}")
        started = time.time() - 60
        r = deploy(template=BROKEN_TEMPLATE, disable_rollback=False)
        if r.returncode == 0:
            log(
                "  !! probe unexpectedly succeeded; skipping rollback phase",
                L_WARN,
            )
            return
        status = wait_terminal()
        log(f"  stack status: {status}")
        new = record(harvest(started, "rollback"), "rollback")
        if status == "UPDATE_ROLLBACK_COMPLETE":
            log("  ** ROLLBACK COMPLETED CLEANLY **")
            return
        if new == 0:
            log("  no NEW permissions; rollback phase stalled.")
            return


def phase_delete():
    """Delete the stack with the TEST role to discover teardown permissions."""
    for i in range(1, MAX_ITERS + 1):
        log(f"\n## [delete] Iteration {i}  ({time.strftime('%H:%M:%S')})")
        if stack_status() is None:
            log("  ** DELETE COMPLETE **")
            return True
        started = time.time() - 60
        aws(
            "cloudformation",
            "delete-stack",
            "--stack-name",
            STACK,
            "--role-arn",
            ROLE_ARN,
        )
        status = wait_terminal()
        log(f"  stack status: {status}")
        if status is None:
            log("  ** DELETE COMPLETE **")
            return True
        if record(harvest(started, "delete"), "delete") == 0:
            log("  no NEW permissions this pass; delete phase stalled.")
            return False
    return False


def write_summary():
    """Write the action -> phase -> resources table to summary.md."""
    lines = [
        "# Discovered deployment permissions",
        "",
        f"Role: `{ROLE}` - {len(granted)} distinct actions",
        "",
        "| Action | Phase(s) | Resources |",
        "| --- | --- | --- |",
    ]
    for action in sorted(granted, key=str.lower):
        ph = ",".join(sorted(phases.get(action, set()) or {"create"}))
        res = sorted(granted[action])
        shown = res[0] if len(res) == 1 else f"{len(res)} ARNs"
        lines.append(f"| `{action}` | {ph} | `{shown}` |")
    with open_out(f"{RESULTS}/summary.md", "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    """Run create, rollback, and delete discovery phases in order.

    Returns:
        0 if the create phase converged, 1 otherwise.
    """
    ap = argparse.ArgumentParser(
        description="Deny-first least-privilege discovery loop."
    )
    config.add_arguments(ap)
    config.apply_args(ap.parse_args())
    reconfigure()
    verify_account()
    seed_from_policy_file()
    # Re-push immediately: seeding canonicalises ARNs, and the role may still be
    # carrying an earlier statement whose resource form never matched.
    if granted:
        push_policy()
        time.sleep(12)
    ok = phase_create()
    if ok:
        phase_rollback()
        phase_delete()
    else:
        log(
            "\ncreate phase did not converge; "
            "skipping rollback and delete phases"
        )
    write_summary()
    debug_summary()
    log(f"\nFINAL: {len(granted)} distinct actions -> {POLICY_FILE}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
