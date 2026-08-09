# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""Integration tests against real AWS.

Everything else in this suite is pure. That leaves the three places the
tools actually talk to CloudFormation -- the parameter overrides deploy()
builds, the template it defaults to, and the status/teardown polling -- which
no amount of unit testing reaches, and which a full deny-first run would take
hours and real money to exercise.

Two tiers, both opt-in:

    --integration              read-only; credentials, account gate, status
                               of a stack that does not exist. Seconds, free.
    --integration-destructive  also deploys and deletes a one-resource stack.
                               A few minutes; an SNS topic costs nothing.

The destructive tier deliberately uses its own stack name. purge_all() and
the survey helpers match resources on a substring of the stack name, so a
test sharing a name with the real stack could enumerate and delete it.
"""
import os
import time

import pytest

import discover

pytestmark = pytest.mark.integration

# Distinct from the project's real stack on purpose; see the module docstring.
SELFTEST_STACK = "iam-discovery-selftest"
TEMPLATE = os.path.join(os.path.dirname(__file__), "fixtures", "selftest.yaml")


def live_account():
    """Return the account the ambient credentials belong to.

    Returns:
        The account ID, or None if credentials do not resolve.
    """
    r = discover.aws(
        "sts", "get-caller-identity", "--query", "Account", "--output", "text"
    )
    return (r.stdout or "").strip() if r.returncode == 0 else None


@pytest.fixture
def live(resolve):
    """Configure the tools for the account the credentials actually name.

    Skips rather than fails when there are no credentials: an opt-in flag
    means "run these if you can", and a missing profile is not a defect in
    the code under test.

    Returns:
        The configured config module.
    """
    account = live_account()
    if not account:
        pytest.skip("no usable AWS credentials")
    region = os.environ.get("AWS_REGION") or "us-east-2"
    return resolve(
        "--account", account, "--region", region, "--stack", SELFTEST_STACK
    )


# --- read-only ------------------------------------------------------------


def test_verify_account_accepts_matching_credentials(live):
    """The guard passes when the target is the account we are in."""
    discover.verify_account()


def test_verify_account_rejects_a_different_account(live, resolve):
    """The guard refuses when they disagree.

    This is the check that stops purge_all() from enumerating and deleting
    in whichever account the credentials happen to point at while every log
    line claims otherwise.
    """
    resolve("--account", "000000000000", "--region", live.REGION)
    with pytest.raises(RuntimeError, match="refusing to run"):
        discover.verify_account()


def test_status_of_a_nonexistent_stack_is_none(live, resolve):
    """A stack that was never created reports None, not an exception."""
    resolve(
        "--account",
        live.ACCOUNT,
        "--region",
        live.REGION,
        "--stack",
        "iam-discovery-stack-that-does-not-exist",
    )
    assert discover.stack_status() is None


def test_aws_wrapper_surfaces_a_failure_without_raising(live):
    """aws() returns the failed result so callers can inspect it."""
    r = discover.aws("cloudformation", "describe-stacks", "--stack-name", "no")
    assert r.returncode != 0
    assert r.stderr


def test_preflight_reports_a_missing_role(live, resolve):
    """A role that does not exist is named, not discovered at deploy time.

    Reproducing the experiment from a clean account used to get "all checks
    passed" with none of the four roles created, then a CloudFormation error
    that said nothing about roles. Read-only: it asks IAM for a role whose
    name no account should have.
    """
    import pipeline

    resolve(
        "--account",
        live.ACCOUNT,
        "--region",
        live.REGION,
        "--stack",
        SELFTEST_STACK,
        "--cleanup-role",
        "iam-discovery-role-that-does-not-exist",
    )
    problems = pipeline.check_roles(["teardown"])
    assert len(problems) == 1
    assert "iam-discovery-role-that-does-not-exist" in problems[0]
    assert "--cleanup-role" in problems[0]


# --- destructive ----------------------------------------------------------


@pytest.fixture
def selftest_stack(live, resolve):
    """Point the tools at the throwaway stack and guarantee cleanup.

    Yields before the test and tears down afterwards whatever happened, so a
    failed assertion cannot leave a stack behind to collide with the next
    run -- the AlreadyExists stall this project documents at length.

    Yields:
        The configured config module.
    """
    cfg = resolve(
        "--account",
        live.ACCOUNT,
        "--region",
        live.REGION,
        "--stack",
        SELFTEST_STACK,
        "--role",
        os.environ.get("IAMD_CLEANUP_ROLE", "cfn-cleanup-role"),
        "--template",
        TEMPLATE,
    )
    assert discover.STACK == SELFTEST_STACK
    if discover.stack_status() is not None:
        discover.teardown()
    yield cfg
    discover.teardown()


@pytest.mark.destructive
def test_deploy_creates_the_stack_and_passes_its_parameters(selftest_stack):
    """The real deploy path works end to end.

    Asserts the thing unit tests cannot: that --parameter-overrides is built
    correctly and ProjectName reaches CloudFormation. A wrong value here
    produces resources under the wrong names, which the discovery loop then
    fails to purge and stalls on.
    """
    r = discover.deploy(disable_rollback=True)
    assert r.returncode == 0, f"deploy failed: {r.stderr[:500]}"

    status = discover.wait_terminal(timeout=600)
    assert status == "CREATE_COMPLETE", f"unexpected status {status}"

    out = discover.aws(
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        discover.STACK,
        "--query",
        "Stacks[0].Parameters[?ParameterKey=='ProjectName']"
        "|[0].ParameterValue",
        "--output",
        "text",
    )
    assert out.stdout.strip() == discover.PROJECT_NAME

    # The topic name can only be right if both parameters substituted, so
    # this checks the template actually used them rather than defaulted.
    name = discover.aws(
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        discover.STACK,
        "--query",
        "Stacks[0].Outputs[?OutputKey=='TopicName']|[0].OutputValue",
        "--output",
        "text",
    )
    assert name.stdout.strip() == f"{discover.PROJECT_NAME}-dev-selftest"


@pytest.mark.destructive
def test_teardown_removes_the_stack(selftest_stack):
    """teardown() leaves no stack behind.

    The delete path is where the deny-first loop discovers permissions the
    create path never needs, so it has to be exercised, not assumed.
    """
    assert discover.deploy(disable_rollback=True).returncode == 0
    assert discover.wait_terminal(timeout=600) == "CREATE_COMPLETE"

    discover.teardown()
    deadline = time.time() + 600
    while time.time() < deadline and discover.stack_status() is not None:
        time.sleep(5)
    assert discover.stack_status() is None
