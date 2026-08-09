
## Iteration 1  (21:40:17)

## Iteration 1  (21:42:23)
  + logs:DeleteLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-ingest:log-stream:
  + logs:DeleteLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-report:log-stream:
  + logs:DeleteLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-process:log-stream:
  + sqs:createqueue  ->  arn:aws:sqs:us-east-2:210987654321:order-pipeline-iamtest-dev-orders-dlq
  + SNS:CreateTopic  ->  arn:aws:sns:us-east-2:210987654321:order-pipeline-iamtest-dev-order-events
  + iam:CreatePolicy  ->  arn:aws:iam::210987654321:policy/order-pipeline-iamtest-dev-platform-service
  -> policy updated on cfn-deploy-role: 4 statements

## Iteration 2  (21:46:10)

---
# RESTART: CloudTrail-sourced capture

## Iteration 1  (21:49:30)

---
# RESTART: phased (create --disable-rollback / rollback / delete)

## [create] Iteration 1  (21:54:13)
  stack status: ROLLBACK_FAILED
  [create] stack events: 6 denial(s)
  polling CloudTrail...

## [create] Iteration 1  (22:00:49)
  stack status: ROLLBACK_FAILED
  [create] stack events: 6 denial(s)
  polling CloudTrail...

---
# RUN: clean slate, paginated CloudTrail, phased create/rollback/delete

## [create] Iteration 1  (22:03:10)
  stack status: CREATE_FAILED
  [create] stack events: 11 denial(s)
  polling CloudTrail...
  streamed 29 CloudTrail event(s) in window
  [create] cloudtrail: 7 denial(s)
  (stack-events only: iam:CreateRole)
  (stack-events only: iam:CreateRole)
  (stack-events only: iam:CreateRole)
  (stack-events only: iam:CreatePolicy)
  + [create] logs:CreateLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-report:log-stream:
  + [create] logs:CreateLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-ingest:log-stream:
  + [create] logs:CreateLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-process:log-stream:
  + [create] dynamodb:CreateTable  ->  arn:aws:dynamodb:us-east-2:210987654321:table/order-pipeline-iamtest-dev-orders
  + [create] s3:CreateBucket  ->  arn:aws:s3:::order-pipeline-iamtest-dev-210987654321-orders
  + [create] sqs:CreateQueue  ->  arn:aws:sqs:us-east-2:210987654321:order-pipeline-iamtest-dev-orders-dlq
  + [create] sns:CreateTopic  ->  arn:aws:sns:us-east-2:210987654321:order-pipeline-iamtest-dev-order-events
  + [create] iam:CreateRole  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-reconcile-sfn-role
  + [create] iam:CreateRole  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-report-role
  + [create] iam:CreateRole  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-process-role
  + [create] iam:CreatePolicy  ->  arn:aws:iam::210987654321:policy/order-pipeline-iamtest-dev-platform-service
  -> policy updated on cfn-deploy-role: 7 statements

## [create] Iteration 2  (22:06:10)
  seeded 7 action(s) from <repo>/deploy-policy.json

## [create] Iteration 1  (22:08:37)
  stack status: UPDATE_IN_PROGRESS
  [create] stack events: 14 denial(s)
  polling CloudTrail...

---
# RESTART: wait for terminal state before harvest (race fix)
  seeded 7 action(s) from <repo>/deploy-policy.json

## [create] Iteration 1  (22:09:56)
  stack status: UPDATE_FAILED
  [create] stack events: 25 denial(s)
  polling CloudTrail...
  streamed 66 CloudTrail event(s) in window
  [create] cloudtrail: 16 denial(s)
  (stack-events only: s3:TagResource)
  (stack-events only: logs:CreateLogGroup)
  (stack-events only: logs:CreateLogGroup)
  (stack-events only: logs:CreateLogGroup)
  (stack-events only: SNS:CreateTopic)
  (stack-events only: iam:CreatePolicy)
  + [create] iam:PutRolePolicy  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-report-role
  + [create] iam:PutRolePolicy  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-process-role
  + [create] iam:PutRolePolicy  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-reconcile-sfn-role
  + [create] sqs:CreateQueue  ->  arn:aws:sqs:us-east-2:210987654321:order-pipeline-iamtest-dev-orders
  + [create] dynamodb:UpdateTimeToLive  ->  arn:aws:dynamodb:us-east-2:210987654321:table/order-pipeline-iamtest-dev-orders
  + [create] logs:DeleteLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-ingest:log-stream:
  + [create] logs:DeleteLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-report:log-stream:
  + [create] logs:DeleteLogGroup  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-process:log-stream:
  + [create] logs:PutRetentionPolicy  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-ingest:log-stream:
  + [create] logs:PutRetentionPolicy  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-report:log-stream:
  + [create] logs:PutRetentionPolicy  ->  arn:aws:logs:us-east-2:210987654321:log-group:/aws/lambda/order-pipeline-iamtest-dev-process:log-stream:
  + [create] s3:PutBucketTagging  ->  arn:aws:s3:::order-pipeline-iamtest-dev-210987654321-orders
  + [create] sns:SetTopicAttributes  ->  arn:aws:sns:us-east-2:210987654321:order-pipeline-iamtest-dev-order-events
  + [create] iam:CreateRole  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-ingest-role
  + [create] s3:TagResource  ->  arn:aws:s3:::order-pipeline-iamtest-dev-210987654321-orders
  -> policy updated on cfn-deploy-role: 14 statements

## [create] Iteration 2  (22:13:32)

---
# RESTART: canonicalise log-group ARNs (:log-stream: -> :*), time-filter stack events
  seeded 14 action(s) from <repo>/deploy-policy.json
  -> policy updated on cfn-deploy-role: 14 statements

## [create] Iteration 1  (22:15:30)
  stack status: UPDATE_FAILED
  [create] stack events: 0 denial(s)
  polling CloudTrail...
  seeded 14 action(s) from <repo>/deploy-policy.json
  -> policy updated on cfn-deploy-role: 14 statements

## [create] Iteration 1  (22:18:54)
  stack status: UPDATE_FAILED
  [create] stack events: 2 denial(s)
  polling CloudTrail...
  streamed 16 CloudTrail event(s) in window
  [create] cloudtrail: 2 denial(s)
  + [create] sqs:SetQueueAttributes  ->  arn:aws:sqs:us-east-2:210987654321:order-pipeline-iamtest-dev-orders
  + [create] iam:DeleteRole  ->  arn:aws:iam::210987654321:role/order-pipeline-iamtest-dev-ingest-role
  -> policy updated on cfn-deploy-role: 16 statements

## [create] Iteration 2  (22:22:03)
  stack status: UPDATE_FAILED
  [create] stack events: 0 denial(s)
  polling CloudTrail...

---
# RESTART: progress-aware stall detection (DELETE_FAILED does not mean stalled)
  seeded 16 action(s) from <repo>/deploy-policy.json
  -> policy updated on cfn-deploy-role: 16 statements

## [create] Iteration 1  (22:26:44)
  stack status: UPDATE_FAILED
  [create] stack events: 0 denial(s)
  polling CloudTrail...

---
# RESTART: stuck-state recovery (retain-resources / continue-update-rollback / force delete / orphan purge)
  seeded 16 action(s) from <repo>/deploy-policy.json
  -> policy updated on cfn-deploy-role: 16 statements

## [create] Iteration 1  (22:30:14)
  stack status: UPDATE_FAILED
  [create] stack events: 0 denial(s)
  polling CloudTrail...
