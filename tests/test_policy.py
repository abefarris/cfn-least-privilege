# Copyright 2026 Abraham Farris
# SPDX-License-Identifier: Apache-2.0
"""ARN handling and policy construction.

These are the pure functions between a harvested denial and a pushed policy.
Each one has a failure mode that produces a plausible, wrong result rather
than an error: a widened grant, a statement that never matches, a permission
quietly dropped.
"""
import json
import pathlib

import pytest

import config
import discover

RESULTS = pathlib.Path(__file__).resolve().parent.parent / "results"


# --- as_list --------------------------------------------------------------


def test_as_list_wraps_a_bare_string():
    """Action and Resource may each be a string or a list."""
    assert discover.as_list("s3:GetObject") == ["s3:GetObject"]


def test_as_list_passes_a_list_through():
    """An existing list is returned unchanged."""
    assert discover.as_list(["a", "b"]) == ["a", "b"]


# --- rehome_account -------------------------------------------------------


def test_rehome_rewrites_the_account_field(resolve):
    """A seeded ARN is repointed at the configured account."""
    resolve("--account", "999988887777")
    assert (
        discover.rehome_account("arn:aws:iam::123456789012:role/foo")
        == "arn:aws:iam::999988887777:role/foo"
    )


def test_rehome_handles_a_regional_arn(resolve):
    """The account field is found even with a region present."""
    resolve("--account", "999988887777")
    out = discover.rehome_account(
        "arn:aws:lambda:us-east-2:123456789012:function:f"
    )
    assert out == "arn:aws:lambda:us-east-2:999988887777:function:f"


def test_rehome_leaves_accountless_arns_alone(resolve):
    """S3 bucket ARNs have an empty account field and must stay intact."""
    resolve("--account", "999988887777")
    arn = "arn:aws:s3:::my-bucket/*"
    assert discover.rehome_account(arn) == arn


def test_rehome_does_not_touch_a_digit_run_in_a_name(resolve):
    """A 12-digit string inside a resource name is not an account field.

    Rewriting it would silently rename someone's bucket in the grant, and
    the resulting statement would never match anything.
    """
    resolve("--account", "999988887777")
    arn = "arn:aws:s3:::my-123456789012-bucket"
    assert discover.rehome_account(arn) == arn


def test_rehome_passes_through_a_wildcard(resolve):
    """`*` is a legal resource and is not an ARN."""
    resolve("--account", "999988887777")
    assert discover.rehome_account("*") == "*"


def test_rehome_is_a_noop_with_no_account_configured():
    """With no target there is nothing to rehome to."""
    arn = "arn:aws:iam::123456789012:role/foo"
    assert config.ACCOUNT == ""
    assert discover.rehome_account(arn) == arn


# --- canon_resource -------------------------------------------------------


def test_canon_rewrites_the_log_group_form():
    """Logs report `:log-stream:`, but IAM authorizes against `:*`."""
    arn = (
        "arn:aws:logs:us-east-2:123456789012:log-group:/aws/lambda/f:"
        "log-stream:"
    )
    assert discover.canon_resource(arn).endswith(":log-group:/aws/lambda/f:*")


def test_canon_repairs_a_doubled_prefix():
    """A re-prefixed ARN is trimmed back to the inner one."""
    inner = "arn:aws:iam::123456789012:policy/x"
    doubled = f"arn:aws:iam::123456789012:policy/{inner}"
    assert discover.canon_resource(doubled) == inner


def test_canon_leaves_an_ordinary_arn_alone():
    """Anything without a known defect passes through untouched."""
    arn = "arn:aws:dynamodb:us-east-2:123456789012:table/orders"
    assert discover.canon_resource(arn) == arn


# --- compaction -----------------------------------------------------------


def policies():
    """Return every committed policy document, for the round-trip checks."""
    return sorted(RESULTS.glob("*policy*.json"))


def test_expand_ignores_statement_structure():
    """Two documents granting the same triples are equivalent."""
    split = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "a"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "b"},
        ],
    }
    merged = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["a", "b"],
            }
        ],
    }
    assert discover.expand(split) == discover.expand(merged)


def test_compaction_is_lossless_on_a_synthetic_policy():
    """Compaction restructures statements; it must not change the grants."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"S{i}",
                "Effect": "Allow",
                "Action": action,
                "Resource": resource,
            }
            for i, (action, resource) in enumerate(
                [
                    ("s3:GetObject", "arn:aws:s3:::b/*"),
                    ("s3:PutObject", "arn:aws:s3:::b/*"),
                    ("sns:Publish", "arn:aws:sns:us-east-2:1:t"),
                    ("sns:Subscribe", "arn:aws:sns:us-east-2:1:t"),
                    ("iam:PassRole", "arn:aws:iam::1:role/r"),
                ]
            )
        ],
    }
    compact = discover.compact_policy(doc)
    assert discover.expand(compact) == discover.expand(doc)
    assert len(compact["Statement"]) < len(doc["Statement"])


@pytest.mark.parametrize("path", list(policies()), ids=lambda p: p.name)
def test_compaction_is_lossless_on_the_committed_policies(path):
    """The real artifacts survive a compaction round trip.

    This is the property the README claims and the code falls back on: if a
    compacted document does not expand to the same triples, the verbatim one
    is pushed instead. Proving it on the committed policies also proves the
    account scrub did not corrupt them.
    """
    doc = json.loads(path.read_text())
    assert discover.expand(discover.compact_policy(doc)) == discover.expand(doc)


# The only account IDs allowed to appear in a committed artifact: AWS's own
# documentation example, and a second placeholder kept distinct so the
# two-account history in the README still reads correctly.
#
# Written as an allowlist, not a denylist of the real IDs. A denylist would
# have to name the accounts it is protecting, which would defeat the scrub by
# committing them to this file -- and it would say nothing about a third
# account ID arriving later.
PLACEHOLDER_ACCOUNTS = {"123456789012", "210987654321"}


@pytest.mark.parametrize("path", list(policies()), ids=lambda p: p.name)
def test_committed_policies_name_no_real_account(path):
    """Published artifacts may carry placeholder account IDs only.

    A regression here means some real account ID has been committed, which
    is exactly what the scrub existed to prevent.
    """
    found = set(discover.ARN_ACCOUNT.findall(path.read_text()))
    assert found <= PLACEHOLDER_ACCOUNTS, (
        f"{path.name} names non-placeholder account(s): "
        f"{sorted(found - PLACEHOLDER_ACCOUNTS)}"
    )


# --- build_policy ---------------------------------------------------------


def test_build_policy_emits_one_statement_per_action(granted_isolated):
    """The record form keeps actions separate and Sids intact."""
    granted_isolated["s3:GetObject"] = {"arn:aws:s3:::b/*"}
    granted_isolated["sns:Publish"] = {"arn:aws:sns:us-east-2:1:t"}
    doc = discover.build_policy()
    assert len(doc["Statement"]) == 2
    assert all("Sid" in st for st in doc["Statement"])
    actions = {st["Action"] for st in doc["Statement"]}
    assert actions == {"s3:GetObject", "sns:Publish"}


def test_seeding_rehomes_and_canonicalises(tmp_path, resolve, granted_isolated):
    """A scrubbed policy file seeds grants against the configured account.

    This is the path that makes results/deploy-policy.json usable as resume
    state even though it is published with a placeholder account. A grant
    seeded against the wrong account looks exactly like a permission that
    was never discovered.
    """
    resolve("--account", "999988887777")
    seed = tmp_path / "deploy-policy.json"
    seed.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:GetRole",
                        "Resource": "arn:aws:iam::123456789012:role/r",
                    }
                ],
            }
        )
    )
    discover.POLICY_FILE = str(seed)
    discover.seed_from_policy_file()
    assert granted_isolated["iam:GetRole"] == {
        "arn:aws:iam::999988887777:role/r"
    }


def test_seeding_refuses_to_treat_a_corrupt_file_as_a_fresh_start(
    tmp_path, granted_isolated
):
    """An unreadable resume state is a failure, not zero prior grants.

    Returning quietly would restart from scratch or push an empty policy
    over a good one, both of which look like ordinary progress.
    """
    seed = tmp_path / "deploy-policy.json"
    seed.write_text("{not json")
    discover.POLICY_FILE = str(seed)
    with pytest.raises(RuntimeError, match="cannot seed"):
        discover.seed_from_policy_file()


# --- the account guard ----------------------------------------------------


def test_verify_account_refuses_when_unconfigured():
    """Nothing may touch AWS without a target account.

    purge_all() deletes what it enumerates, so an unset account is not a
    condition the tools could recover from later.
    """
    assert discover.ACCOUNT == ""
    with pytest.raises(RuntimeError, match="no target account configured"):
        discover.verify_account()


def test_verify_account_refuses_without_a_stack(resolve):
    """A configured account is not enough; the stack is a target too.

    purge_all() matches orphans on a substring of the stack name, so an
    empty one would scope real deletions to a string nobody chose.
    """
    resolve("--account", "123456789012")
    with pytest.raises(RuntimeError, match="no target stack configured"):
        discover.verify_account()


def test_survey_finds_nothing_without_a_stack():
    """An unconfigured survey must not match the whole account.

    Every check is a contains(name, stack) filter, and contains() against
    an empty string matches every resource there is -- so the unguarded
    version reported a clean account as full of leftovers, and preflight
    refused to run against it.
    """
    import pipeline

    assert discover.STACK == ""
    assert pipeline.survey() == []
