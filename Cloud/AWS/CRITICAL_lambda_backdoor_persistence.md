# AWS - Lambda Function Backdoor/Persistence

## Severity
**CRITICAL**

## Description
Detects creation or modification of AWS Lambda functions that could be used for backdoor access, persistence, or privilege escalation.

## MITRE ATT&CK
- **Tactic**: Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004)
- **Technique**: Serverless Execution (T1648), Cloud Administration Command (T1651)

## DEVO Query

```sql
from cloud.aws.cloudtrail
where eventSource = "lambda.amazonaws.com"
  and eventName in ("CreateFunction20150331", "UpdateFunctionCode20150331v2",
                     "UpdateFunctionConfiguration20150331v2", "AddPermission20150331v2",
                     "CreateEventSourceMapping")
  and (errorCode is null or errorCode = "")
select
  eventdate,
  userIdentity.principalId,
  userIdentity.arn as user_arn,
  eventName,
  requestParameters.functionName,
  requestParameters.runtime,
  requestParameters.role as lambda_role,
  requestParameters.code.s3Bucket,
  requestParameters.code.s3Key,
  requestParameters.environment.variables as env_vars,
  requestParameters.layers,
  responseElements.functionArn,
  sourceIPAddress,
  userAgent,
  awsRegion
group by functionName, user_arn, eventName
```

## Alert Configuration
- **Trigger**: Any Lambda function creation/modification
- **Throttling**: 1 alert per function per hour
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. Review Lambda function code immediately
2. Check IAM role assigned to function
3. Verify function creator/modifier authorization
4. Review function triggers and event sources
5. Check environment variables for secrets/credentials
6. Analyze function permissions
7. Review VPC configuration if applicable
8. Check for data exfiltration capabilities
9. Disable function if suspicious
10. Review all recent Lambda changes
11. Audit S3 bucket containing code
12. Reset credentials if compromise suspected

## False Positive Considerations
- Legitimate application deployments
- CI/CD pipeline updates
- Infrastructure-as-code (Terraform, CloudFormation)
- Developer testing in dev/test environments
- Scheduled application updates

**Tuning Recommendations**:
- Whitelist CI/CD service accounts
- Exclude approved deployment pipelines
- Filter dev/test account activities
- Require change management correlation
- Adjust based on environment (prod vs non-prod)

## Enrichment Opportunities
- Review function code from S3
- Check IAM role permissions
- Analyze function logs in CloudWatch
- Review VPC configuration
- Check trigger/event source mappings
- Correlate with GuardDuty findings
- Review recent access to function
- Check for concurrent suspicious activities

## Response Playbook
1. **Immediate Assessment**:
   - Who created/modified the function?
   - What IAM role does it use?
   - What are the permissions?
   - What triggers the function?
   - Is this part of normal deployment?

2. **Code Analysis**:
   - Download function code from S3
   - Review for malicious behavior
   - Check for credential theft
   - Look for reverse shells
   - Analyze network connections
   - Review API calls made
   - Check for data exfiltration

3. **Permission Review**:
   - Lambda execution role permissions
   - Resource-based policy
   - Layer permissions
   - VPC access (if configured)
   - S3 bucket access
   - Secrets Manager access
   - Other AWS service permissions

4. **If Malicious**:
   - Delete function immediately
   - Block source IP
   - Review all Lambda functions
   - Check for similar IOCs
   - Reset exposed credentials
   - Review CloudTrail for function executions
   - Hunt for lateral movement
   - Full account security review

5. **If Legitimate**:
   - Verify deployment approval
   - Document in change management
   - Review security best practices
   - Monitor function behavior
   - Schedule security review

## Investigation Steps
- Review function code line by line
- Check all environment variables
- Analyze IAM role trust policy
- Review attached IAM policies
- Check VPC configuration
- Examine security group rules (if VPC)
- Review CloudWatch Logs
- Check invocation history
- Analyze error logs
- Review X-Ray traces if enabled
- Check for layer usage

## Lambda Backdoor Techniques

**Persistence Methods**:
- Cron-triggered Lambda (EventBridge)
- S3 event-triggered function
- API Gateway endpoint
- SQS/SNS triggered
- DynamoDB Streams trigger
- CloudWatch Events trigger

**Malicious Capabilities**:
- Credential harvesting from environment
- EC2 instance metadata access
- Secrets Manager access
- Parameter Store access
- S3 data exfiltration
- RDS database access
- IAM role assumption
- Reverse shell connections

**Evasion Techniques**:
- Encrypted code in layers
- Obfuscated Python/Node.js
- Base64 encoded commands
- External package dependencies
- Container image obfuscation

## High-Risk Indicators

**Code Red Flags**:
- Reverse shell attempts
- Outbound connections to unknown IPs
- Credential harvesting from env vars
- EC2 metadata queries
- Secrets Manager API calls
- Parameter Store queries
- Base64 decoding operations
- eval() or exec() usage
- Subprocess/os.system calls

**Configuration Red Flags**:
- Overly permissive IAM role
- Administrator access
- Public function URL
- Unrestricted VPC access
- High memory/timeout allocation
- External layers from unknown accounts
- Environment variables with credentials

**Trigger Red Flags**:
- Public API Gateway
- Unauthenticated triggers
- Wildcard S3 bucket events
- High-frequency EventBridge rules

## Common Legitimate Use Cases
- Serverless applications
- Data processing pipelines
- API backends
- Event-driven workflows
- Scheduled tasks
- Image/video processing
- Log processing
- Webhooks

## Enhanced Detection

```sql
-- Detect Lambda with admin permissions
from cloud.aws.cloudtrail
where eventName like "CreateFunction%"
  and requestParameters.role in (
    select arn from iam.roles
    where attached_policies contains "AdministratorAccess"
      or inline_policies like "%:*%"
  )
```

## Lambda Security Best Practices

**Code Security**:
- Code review all functions
- No hardcoded credentials
- Use Secrets Manager/Parameter Store
- Minimal dependencies
- Regular security scanning
- Signed code packages

**IAM Permissions**:
- Least privilege principle
- Function-specific roles
- No administrator access
- Resource-based policies
- Regular permission audits
- Condition keys for restrictions

**Network Security**:
- VPC when accessing private resources
- Security groups with minimal rules
- No public internet unless required
- VPC endpoints for AWS services
- Network ACLs

**Monitoring**:
- CloudWatch Logs enabled
- X-Ray tracing
- GuardDuty for Lambda
- CloudTrail for API calls
- Alarms for errors/throttles
- Cost monitoring

## Suspicious Function Names
- test, temp, backup (generic)
- Similar to legitimate functions (typosquatting)
- Random strings
- Hidden characters

## Runtime Analysis

**High-Risk Runtimes**:
- Custom runtime (bring your own)
- Container images (harder to inspect)
- Older/deprecated runtimes
- Unrestricted package installation

**Safer Runtimes**:
- Managed runtimes (Python, Node.js, etc.)
- Latest versions
- Minimal external dependencies

## Environment Variables Review

Check for:
- AWS access keys (should use IAM role!)
- Database credentials (should use Secrets Manager!)
- API keys
- Encryption keys
- Internal URLs
- Other secrets

## Layers Investigation

Lambda layers can hide malicious code:
- Review layer source
- Check layer permissions
- Verify layer publisher
- Scan layer contents
- Check for obfuscation

## VPC Configuration Risks

If Lambda in VPC:
- Can access private resources
- Security group allows what traffic?
- Which subnets?
- NAT gateway for internet?
- Potential lateral movement

## Function URL Security

Public Function URLs:
- Authentication required?
- CORS configuration
- Rate limiting?
- Behind WAF?
- DDoS protection?

## CloudWatch Logs Analysis

Review logs for:
- Outbound connection attempts
- API calls made
- Error messages
- Execution duration anomalies
- Concurrent execution spikes
- Memory usage patterns

## Cost Anomalies

Unexpected costs may indicate:
- High invocation rate (C2 beaconing?)
- Long execution times
- High memory usage
- Data transfer costs (exfiltration?)

## Prevention Measures
- Lambda code signing
- Function-level permissions (resource policies)
- VPC controls
- SCPs to restrict Lambda capabilities
- Automated code scanning
- Deployment approval workflows
- Infrastructure-as-code for all functions
- Regular security audits
- GuardDuty for Lambda protection
- CloudTrail monitoring
- Least privilege IAM roles

## Incident Response Integration
- Automated function disabling
- Code backup before deletion
- Forensic log collection
- S3 code preservation
- Execution history analysis
- Related resource review

## Compliance Impact
- Unauthorized compute resource
- Potential data access
- Audit trail requirements
- Change management violation
- May indicate broader compromise

## Notes
- Lambda is powerful persistence mechanism
- Often overlooked in security reviews
- Can access many AWS services
- Difficult to detect if well-hidden
- Review all functions periodically
- Infrastructure-as-code helps security
- GuardDuty has Lambda-specific detections
