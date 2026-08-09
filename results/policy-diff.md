# Side-by-side: deny-first vs admin-first (mutating actions)

`=` identical · `≠` same action, different scope · `D` deny-first only · `A` admin-first only · ⚠ wildcard

| | Action | Deny-first `Resource` | Admin-first `Resource` |
| --- | --- | --- | --- |
| = | `dynamodb:CreateTable` | table:orders | table:orders |
| = | `dynamodb:DeleteTable` | table:orders | table:orders |
| = | `dynamodb:UpdateTimeToLive` | table:orders | table:orders |
| ≠ | `events:DeleteRule` | rule:report-schedule | `*`  ⚠ |
| ≠ | `events:PutRule` | rule:report-schedule | `*`  ⚠ |
| ≠ | `events:PutTargets` | rule:report-schedule | `*`  ⚠ |
| ≠ | `events:RemoveTargets` | rule:report-schedule | `*`  ⚠ |
| ≠ | `events:TagResource` | rule:report-schedule | `*`  ⚠ |
| ≠ | `iam:AttachRolePolicy` | role/ingest-role | `*`  ⚠ |
| ≠ | `iam:CreatePolicy` | policy/platform-service | `*`  ⚠ |
| ≠ | `iam:CreateRole` | 4: role/ingest-role, role/process-role, role/reconcile-sfn-role, role/report-role | `*`  ⚠ |
| ≠ | `iam:DeletePolicy` | policy/platform-service | `*`  ⚠ |
| ≠ | `iam:DeleteRole` | 4: role/ingest-role, role/process-role, role/reconcile-sfn-role, role/report-role | `*`  ⚠ |
| ≠ | `iam:DeleteRolePolicy` | 4: role/ingest-role, role/process-role, role/reconcile-sfn-role, role/report-role | `*`  ⚠ |
| ≠ | `iam:DetachRolePolicy` | role/ingest-role | `*`  ⚠ |
| D | `iam:PassRole` | 4: role/ingest-role, role/process-role, role/reconcile-sfn-role, role/report-role | — |
| ≠ | `iam:PutRolePolicy` | 4: role/ingest-role, role/process-role, role/reconcile-sfn-role, role/report-role | `*`  ⚠ |
| A | `kms:CreateGrant` | — | kms:us-east-2:key/9028ae3a-d63c-444d-a7d0-8ff6bcdbe581 |
| A | `kms:Decrypt` | — | kms:us-east-2:key/9028ae3a-d63c-444d-a7d0-8ff6bcdbe581 |
| A | `kms:Encrypt` | — | kms:us-east-2:key/9028ae3a-d63c-444d-a7d0-8ff6bcdbe581 |
| ≠ | `lambda:AddPermission` | function:report | `*`  ⚠ |
| ≠ | `lambda:CreateEventSourceMapping` | 2: esm:*, function:process | function:process |
| ≠ | `lambda:CreateFunction` | 3: function:ingest, function:process, function:report | `*`  ⚠ |
| ≠ | `lambda:DeleteEventSourceMapping` | esm:* | esm:c545b97e-a3d5-43b7-9175-4241bfed6fbd |
| ≠ | `lambda:DeleteFunction` | 3: function:ingest, function:process, function:report | `*`  ⚠ |
| ≠ | `lambda:RemovePermission` | function:report | `*`  ⚠ |
| ≠ | `logs:CreateLogGroup` | 3: log-group:ingest:*, log-group:process:*, log-group:report:* | `*`  ⚠ |
| ≠ | `logs:DeleteLogGroup` | 3: log-group:ingest:*, log-group:process:*, log-group:report:* | `*`  ⚠ |
| ≠ | `logs:PutRetentionPolicy` | 3: log-group:ingest:*, log-group:process:*, log-group:report:* | `*`  ⚠ |
| ≠ | `s3:CreateBucket` | bucket:123456789012-orders | `*`  ⚠ |
| = | `s3:DeleteBucket` | bucket:123456789012-orders | bucket:123456789012-orders |
| = | `s3:DeleteBucketPolicy` | bucket:123456789012-orders | bucket:123456789012-orders |
| = | `s3:PutBucketPolicy` | bucket:123456789012-orders | bucket:123456789012-orders |
| = | `s3:PutBucketPublicAccessBlock` | bucket:123456789012-orders | bucket:123456789012-orders |
| D | `s3:PutBucketTagging` | bucket:123456789012-orders | — |
| D | `s3:PutEncryptionConfiguration` | bucket:123456789012-orders | — |
| D | `s3:PutLifecycleConfiguration` | bucket:123456789012-orders | — |
| D | `s3:TagResource` | bucket:123456789012-orders | — |
| ≠ | `sns:CreateTopic` | topic:order-events | `*`  ⚠ |
| = | `sns:DeleteTopic` | topic:order-events | topic:order-events |
| = | `sns:SetTopicAttributes` | topic:order-events | topic:order-events |
| = | `sqs:CreateQueue` | 2: queue:orders, queue:orders-dlq | 2: queue:orders, queue:orders-dlq |
| = | `sqs:DeleteQueue` | 2: queue:orders, queue:orders-dlq | 2: queue:orders, queue:orders-dlq |
| = | `sqs:SetQueueAttributes` | queue:orders | queue:orders |
| ≠ | `states:CreateStateMachine` | sfn:reconcile | `*`  ⚠ |
| ≠ | `states:DeleteStateMachine` | sfn:reconcile | `*`  ⚠ |
| D | `states:TagResource` | sfn:reconcile | — |

**12 identical · 26 differ in scope · 6 deny-only · 3 admin-only**
