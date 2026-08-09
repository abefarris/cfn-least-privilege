# Discovered deployment permissions

Role: `cfn-deploy-role` - 44 distinct actions

| Action | Phase(s) | Resources |
| --- | --- | --- |
| `dynamodb:CreateTable` | create | `arn:aws:dynamodb:us-east-2:123456789012:table/order-pipeline-iamtest-dev-orders` |
| `dynamodb:DeleteTable` | create | `arn:aws:dynamodb:us-east-2:123456789012:table/order-pipeline-iamtest-dev-orders` |
| `dynamodb:UpdateTimeToLive` | create | `arn:aws:dynamodb:us-east-2:123456789012:table/order-pipeline-iamtest-dev-orders` |
| `events:DeleteRule` | delete | `arn:aws:events:us-east-2:123456789012:rule/order-pipeline-iamtest-dev-report-schedule` |
| `events:PutRule` | create | `arn:aws:events:us-east-2:123456789012:rule/order-pipeline-iamtest-dev-report-schedule` |
| `events:PutTargets` | create | `arn:aws:events:us-east-2:123456789012:rule/order-pipeline-iamtest-dev-report-schedule` |
| `events:RemoveTargets` | create | `arn:aws:events:us-east-2:123456789012:rule/order-pipeline-iamtest-dev-report-schedule` |
| `events:TagResource` | create | `arn:aws:events:us-east-2:123456789012:rule/order-pipeline-iamtest-dev-report-schedule` |
| `iam:AttachRolePolicy` | create | `arn:aws:iam::123456789012:role/order-pipeline-iamtest-dev-ingest-role` |
| `iam:CreatePolicy` | create | `arn:aws:iam::123456789012:policy/order-pipeline-iamtest-dev-platform-service` |
| `iam:CreateRole` | create | `4 ARNs` |
| `iam:DeletePolicy` | delete | `arn:aws:iam::123456789012:policy/order-pipeline-iamtest-dev-platform-service` |
| `iam:DeleteRole` | create | `4 ARNs` |
| `iam:DeleteRolePolicy` | create,delete | `4 ARNs` |
| `iam:DetachRolePolicy` | delete | `arn:aws:iam::123456789012:role/order-pipeline-iamtest-dev-ingest-role` |
| `iam:PassRole` | create | `4 ARNs` |
| `iam:PutRolePolicy` | create | `4 ARNs` |
| `lambda:AddPermission` | create | `arn:aws:lambda:us-east-2:123456789012:function:order-pipeline-iamtest-dev-report` |
| `lambda:CreateEventSourceMapping` | create | `2 ARNs` |
| `lambda:CreateFunction` | create | `6 ARNs` |
| `lambda:DeleteEventSourceMapping` | delete | `arn:aws:lambda:us-east-2:123456789012:event-source-mapping:*` |
| `lambda:DeleteFunction` | create | `3 ARNs` |
| `lambda:RemovePermission` | create | `arn:aws:lambda:us-east-2:123456789012:function:order-pipeline-iamtest-dev-report` |
| `logs:CreateLogGroup` | create | `3 ARNs` |
| `logs:DeleteLogGroup` | create | `3 ARNs` |
| `logs:PutRetentionPolicy` | create | `3 ARNs` |
| `s3:CreateBucket` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:DeleteBucket` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:DeleteBucketPolicy` | delete | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:PutBucketPolicy` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:PutBucketPublicAccessBlock` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:PutBucketTagging` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:PutEncryptionConfiguration` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:PutLifecycleConfiguration` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `s3:TagResource` | create | `arn:aws:s3:::order-pipeline-iamtest-dev-123456789012-orders` |
| `sns:CreateTopic` | create | `arn:aws:sns:us-east-2:123456789012:order-pipeline-iamtest-dev-order-events` |
| `sns:DeleteTopic` | delete | `arn:aws:sns:us-east-2:123456789012:order-pipeline-iamtest-dev-order-events` |
| `sns:SetTopicAttributes` | create | `arn:aws:sns:us-east-2:123456789012:order-pipeline-iamtest-dev-order-events` |
| `sqs:CreateQueue` | create | `2 ARNs` |
| `sqs:DeleteQueue` | delete | `2 ARNs` |
| `sqs:SetQueueAttributes` | create | `arn:aws:sqs:us-east-2:123456789012:order-pipeline-iamtest-dev-orders` |
| `states:CreateStateMachine` | create | `2 ARNs` |
| `states:DeleteStateMachine` | delete | `arn:aws:states:us-east-2:123456789012:stateMachine:order-pipeline-iamtest-dev-reconcile` |
| `states:TagResource` | create | `arn:aws:states:us-east-2:123456789012:stateMachine:order-pipeline-iamtest-dev-reconcile` |
