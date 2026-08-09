# Deny-first vs admin-first permission discovery

Two ways to derive a deployment policy for the same CloudFormation stack.

| | Deny-first | Admin-first |
| --- | --- | --- |
| Starting permissions | `ReadOnlyAccess` | `AdministratorAccess` |
| Learns from | AccessDenied failures | successful calls |
| Deploy iterations | ~20 across the run | 1 |
| Wall clock | hours | 131s deploy + 162s delete |
| Mutating actions | 44 | 41 |
| Read actions | 0 (masked by ReadOnlyAccess) | 52 |
| Policy size | 4268b | 1943b mutating, 3523b with reads |

## Only deny-first found these (6)

Permissions an admin-first run cannot see, because nothing failed and CloudTrail records no denial.

| Action | Resources |
| --- | --- |
| `iam:PassRole` | 4 ARN(s) |
| `s3:PutBucketTagging` | 1 ARN(s) |
| `s3:PutEncryptionConfiguration` | 1 ARN(s) |
| `s3:PutLifecycleConfiguration` | 1 ARN(s) |
| `s3:TagResource` | 1 ARN(s) |
| `states:TagResource` | 1 ARN(s) |

## Only admin-first found these (3)

Calls that succeeded under admin. Some are real gaps in the deny-first policy; some are API names that are not IAM actions.

| Action | Resources |
| --- | --- |
| `kms:CreateGrant` | 1 ARN(s) |
| `kms:Decrypt` | 1 ARN(s) |
| `kms:Encrypt` | 1 ARN(s) |

## Found by both (38)

`dynamodb:CreateTable`, `dynamodb:DeleteTable`, `dynamodb:UpdateTimeToLive`, `events:DeleteRule`, `events:PutRule`, `events:PutTargets`, `events:RemoveTargets`, `events:TagResource`, `iam:AttachRolePolicy`, `iam:CreatePolicy`, `iam:CreateRole`, `iam:DeletePolicy`, `iam:DeleteRole`, `iam:DeleteRolePolicy`, `iam:DetachRolePolicy`, `iam:PutRolePolicy`, `lambda:AddPermission`, `lambda:CreateEventSourceMapping`, `lambda:CreateFunction`, `lambda:DeleteEventSourceMapping`, `lambda:DeleteFunction`, `lambda:RemovePermission`, `logs:CreateLogGroup`, `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`, `s3:CreateBucket`, `s3:DeleteBucket`, `s3:DeleteBucketPolicy`, `s3:PutBucketPolicy`, `s3:PutBucketPublicAccessBlock`, `sns:CreateTopic`, `sns:DeleteTopic`, `sns:SetTopicAttributes`, `sqs:CreateQueue`, `sqs:DeleteQueue`, `sqs:SetQueueAttributes`, `states:CreateStateMachine`, `states:DeleteStateMachine`

## Resource scoping

The point of the exercise is least privilege, and that lives in the `Resource` field rather than the action list.

| | Deny-first | Admin-first |
| --- | --- | --- |
| Actions scoped to a specific ARN | 44 | 17 |
| Actions scoped to `*` | 0 | 24 |

A denial message always names the resource that was refused. A successful CloudTrail event often has an empty `resources` array and no error text, so there is nothing to scope to and the derivation falls back to `*`. This is why the admin-first policy is *smaller* - it is less specific, not tighter.

Wildcarded under admin-first: `events:DeleteRule`, `events:PutRule`, `events:PutTargets`, `events:RemoveTargets`, `events:TagResource`, `iam:AttachRolePolicy`, `iam:CreatePolicy`, `iam:CreateRole`, `iam:DeletePolicy`, `iam:DeleteRole`, `iam:DeleteRolePolicy`, `iam:DetachRolePolicy`, `iam:PutRolePolicy`, `lambda:AddPermission`, `lambda:CreateFunction`, `lambda:DeleteFunction`, `lambda:RemovePermission`, `logs:CreateLogGroup`, `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`, `s3:CreateBucket`, `sns:CreateTopic`, `states:CreateStateMachine`, `states:DeleteStateMachine`

## Same action, different resource scope (26)

| Action | Deny-first | Admin-first |
| --- | --- | --- |
| `events:DeleteRule` | 1 ARN(s) | `*` |
| `events:PutRule` | 1 ARN(s) | `*` |
| `events:PutTargets` | 1 ARN(s) | `*` |
| `events:RemoveTargets` | 1 ARN(s) | `*` |
| `events:TagResource` | 1 ARN(s) | `*` |
| `iam:AttachRolePolicy` | 1 ARN(s) | `*` |
| `iam:CreatePolicy` | 1 ARN(s) | `*` |
| `iam:CreateRole` | 4 ARN(s) | `*` |
| `iam:DeletePolicy` | 1 ARN(s) | `*` |
| `iam:DeleteRole` | 4 ARN(s) | `*` |
| `iam:DeleteRolePolicy` | 4 ARN(s) | `*` |
| `iam:DetachRolePolicy` | 1 ARN(s) | `*` |
| `iam:PutRolePolicy` | 4 ARN(s) | `*` |
| `lambda:AddPermission` | 1 ARN(s) | `*` |
| `lambda:CreateEventSourceMapping` | 2 ARN(s) | 1 ARN(s) |
| `lambda:CreateFunction` | 6 ARN(s) | `*` |
| `lambda:DeleteFunction` | 3 ARN(s) | `*` |
| `lambda:RemovePermission` | 1 ARN(s) | `*` |
| `logs:CreateLogGroup` | 3 ARN(s) | `*` |
| `logs:DeleteLogGroup` | 3 ARN(s) | `*` |
| `logs:PutRetentionPolicy` | 3 ARN(s) | `*` |
| `s3:CreateBucket` | 1 ARN(s) | `*` |
| `sns:CreateTopic` | 1 ARN(s) | `*` |
| `sqs:DeleteQueue` | 2 ARN(s) | 1 ARN(s) |
| `states:CreateStateMachine` | 2 ARN(s) | `*` |
| `states:DeleteStateMachine` | 1 ARN(s) | `*` |

## Verdict

- `iam:PassRole` present in admin-first derivation: **no**
  - Confirms the prediction. PassRole is authorised inside the calling API, so CloudTrail never logs it as its own event. An admin-first policy therefore cannot create a Lambda function or state machine.
- Deny-first exclusive: 6 action(s)
- Admin-first exclusive: 3 action(s)
- Admin-first actions that could not be scoped: 24/41; deny-first: 0/44

The action lists are close. The resource scoping is not, and that is the part that makes a policy least-privilege. Admin-first is roughly 60x cheaper to run and produces the read set that deny-first structurally cannot see; deny-first produces the scoping and the permissions that only appear when something fails. Neither is complete alone.

