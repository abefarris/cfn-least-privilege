# Deny-first vs admin-first: analysis

Hand-authored conclusions. The measured tables are regenerated separately
into [comparison.generated.md](comparison.generated.md) — nothing here is
produced by a script, so a re-run cannot overwrite it.

## The test that settles it

The admin-derived policy was attached to a role with nothing else - no
`ReadOnlyAccess`, no admin - and used to deploy the same template.

| Attempt | Result |
| --- | --- |
| Admin-derived policy, as generated | **failed** - 11 of 23 resources |
| After 10 convergence passes + 2 manual fixes (first run) | 23 of 23 |
| 15 convergence passes, no manual widening (rerun) | **hit the cap** - 22 of 23 |

The first run needed **10 further deploy/harvest iterations** plus two fixes
the loop could not make on its own. A later rerun withheld the first of those
fixes and never converged: it hit `MAX_PASSES` at 15, having added 20 actions
and still one resource short. The two fixes are not incidental - without them
the method does not terminate:

1. **Stale physical IDs.** `lambda:GetEventSourceMapping` was captured scoped to
   the UUID minted during the admin run. Every deploy mints a new one, so the
   loop added a fresh dead ARN each pass and *could never terminate*. Widening to
   `event-source-mapping:*` is unavoidable - the identifier does not exist until
   the resource does.
2. **An orphaned mapping** from a failed pass had to be deleted by hand.

### What convergence had to add

- `iam:PassRole` - invisible to CloudTrail, the predicted blocker, and it stopped
  the run dead at 21/23 until granted
- `s3:PutEncryptionConfiguration`, `s3:PutLifecycleConfiguration` - the real
  actions behind the API names the static scan correctly rejected. Admin-first
  saw the operations and still lost the permissions
- `s3:TagResource`, `s3:PutBucketTagging` - never surfaced as successful calls
- A dozen `s3:GetBucket*` reads - so even the 52-action read set, admin-first's
  clearest advantage, was materially incomplete
- Real ARNs for actions admin-first had wildcarded

## Verdict

**Admin-first is ~60x cheaper and does not produce a working policy.**

Deny-first: ~20 iterations over hours, 44 actions, **0 wildcards**, deploys and
tears down the stack unaided.

Admin-first: 292 seconds, 41 mutating actions that look comparable, **24 of them
wildcarded**, and it does not deploy. Closing the gap took 10 more iterations
with manual help, and 15 without it were not enough - at which point it had
become a deny-first run wearing admin-first's starting set.

The action lists are similar; that similarity is misleading. Least privilege
lives in the `Resource` field, and a denial names the resource that was refused
while a successful CloudTrail event usually does not. Learning from failure is
strictly more informative than learning from success, because a failure says
*what was needed*, while a success only says *what happened*.

**Use both:** admin-first for a fast inventory of services and the read set,
deny-first for scoping, `PassRole`, and the failure and replacement paths.
