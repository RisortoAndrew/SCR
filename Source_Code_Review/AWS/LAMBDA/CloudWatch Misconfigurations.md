### 1 Insufficient log filtering exposes sensitive data

```regex
filter[Pp]attern\s*[:=]\s*["']\s*["']
```

```yaml
Resources:
  AllLogsToKinesis:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/lambda/payment
      FilterPattern: ""     # ← everything passes
```

_Impact – the empty pattern forwards every log line (PII, secrets, keys) to downstream targets that an attacker could read or replay._

---

### 2 Overly permissive CloudWatch Logs access policy

```regex
"Action"\s*:\s*\[\s*"?logs:\*"?\s*\]
```

```json
{
  "Effect": "Allow",
  "Action": [ "logs:*" ],
  "Resource": "*"
}
```

_Impact – compromise of this principal lets an attacker read, delete or alter any log group, erasing evidence or harvesting data._

---

### 3 Missing encryption on CloudWatch Logs

```regex
Type\s*:\s*["']AWS::Logs::LogGroup["'](?![\s\S]*kms[Kk]ey[Ii]d)
```

```yaml
UnencryptedLogs:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: /prod/app   # no KmsKeyId
```

_Impact – logs sit unencrypted at rest; anyone with low-level storage access can read them in plaintext._

---

### 4 No alarm on critical metrics

```regex
MetricName\s*:\s*["'](CPUUtilization|Errors|Throttles)["'](?![\s\S]*AWS::CloudWatch::Alarm)
```

```yaml
PaymentLambda:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: payment-handler   # no CloudWatch alarm
```

_Impact – attack-driven spikes in errors or throttles go unnoticed, giving adversaries more dwell time._

---

### 5 EventBridge rule with overly broad pattern

```regex
"(detail-type|source)"\s*:\s*\[\s*"\*"\s*\]
```

```json
{
  "Source": [ "*" ],
  "DetailType": [ "*" ]
}
```

_Impact – the rule captures every event; a malicious actor can flood the target or inject unexpected payloads._

---

### 6 No log retention (cost bloat)

```regex
Type\s*:\s*["']AWS::Logs::LogGroup["'](?![\s\S]*RetentionInDays)
```

```yaml
HugeLogGroup:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: /aws/bigdata/verbose   # infinite retention
```

_Impact – storage costs balloon and incident response slows because of an ever-growing log backlog._

---

### 7 Alarms fire too late

```regex
EvaluationPeriods\s*:\s*(?:[6-9]|\d{2,})
```

```yaml
HighErrorRate:
  Type: AWS::CloudWatch::Alarm
  Properties:
    MetricName: Errors
    Period: 60
    EvaluationPeriods: 12   # waits 12 min
```

_Impact – long evaluation windows delay paging, letting attacks proceed unchecked._

---

### 8 Uncontrolled cross-account log sharing

```regex
arn:aws:logs:[^:]+:\d{12}:destination\/[^\s"']+
```

```bash
aws logs put-destination \
  --destination-name "ToPartner" \
  --target-arn "arn:aws:kinesis:us-east-1:444455556666:stream/partner"
```

_Impact – partner (or breached) accounts receive your logs and can mine or poison them._

---

### 9 Security events not logged

```regex
eventName\s*=\s*"ConsoleLogin"(?![\s\S]*MetricTransformation)
```

```yaml
# CloudTrail on, but no metric filter for ConsoleLogin
```

_Impact – root or suspicious console logins create no metric or alarm, hiding credential-stuffing attempts._

---

### 10 Unencrypted SNS alarm topics

```regex
Type\s*:\s*["']AWS::SNS::Topic["'](?![\s\S]*KmsMasterKeyId)
```

```yaml
AlarmTopic:
  Type: AWS::SNS::Topic
  Properties:
    TopicName: prod-alarms   # unencrypted
```

_Impact – alarm messages with stack traces or secrets travel and rest in clear text._

---

### 11 No Logs Insights queries for monitoring

```regex
aws\s+logs\s+describe-insights-queries\b
```

```bash
# Empty list returned → no saved queries
aws logs describe-insights-queries --log-group-name /aws/lambda/*
```

_Impact – investigators waste time crafting ad-hoc searches and may miss subtle Indicators of Compromise._

---

### 12 Missing dead-letter queue

```regex
Type\s*:\s*["']AWS::Lambda::Function["'](?![\s\S]*DeadLetterConfig)
```

```yaml
ParseEventsFn:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: parseEvents   # no DLQ
```

_Impact – failed invocations vanish, letting attackers break monitoring by feeding malformed events._

---

### 13 Wildly shared CloudWatch dashboards

```regex
"sharedAccounts"\s*:\s*\[\s*"\*"\s*\]
```

```json
{
  "widgets": [ /* … */ ],
  "sharedAccounts": [ "*" ]
}
```

_Impact – any AWS account can fetch the dashboard JSON and glean ARNs, resource names and usage._

---

### 14 Contributor Insights leaks secrets

```regex
"\$\.requestParameters\.(password|secret|token)"
```

```yaml
PasswordInsights:
  Type: AWS::CloudWatch::ContributorInsightsRule
  Properties:
    RuleDefinition:
      Pattern: '{ $.requestParameters.password = "*" }'
```

_Impact – password fields are stored verbatim in rule outputs accessible to anyone with CI permissions._

---

### 15 Synthetics canary with admin role

```regex
RoleArn\s*:\s*arn:aws:iam::\d{12}:role/.*(Admin|Administrator|FullAccess).*
```

```yaml
UptimeCanary:
  Type: AWS::Synthetics::Canary
  Properties:
    RoleArn: arn:aws:iam::111122223333:role/Administrator
```

_Impact – if the canary script or results bucket is compromised, the attacker inherits full account control._

---

### 16 Over-specific metric filter misses events

```regex
FilterPattern\s*:\s*"\{?\s*\$\.eventName\s*=\s*"DeleteUser"[^}]*\}
```

```yaml
DeleteUserOnlyFilter:
  Type: AWS::Logs::MetricFilter
  Properties:
    FilterPattern: '{ $.eventName = "DeleteUser" }'
```

_Impact – attacker performs other destructive actions (DisableMFA, UpdatePolicy) that never trigger the filter._

---

### 17 Unauthorized CloudWatch API calls not monitored

```regex
\$.errorCode\s*=\s*"AccessDenied"
```

```yaml
# Absent in many templates → no alert on AccessDenied storms
```

_Impact – role-spraying or permission-mining attempts generate “AccessDenied” events that nobody sees, giving adversaries unlimited reconnaissance._