# AWS - Root Account Usage Detection

## Severity
**HIGH**

## Description
Detects usage of AWS root account credentials, which violates security best practices and indicates potential security risk or policy violation.

## MITRE ATT&CK
- **Tactic**: Privilege Escalation (TA0004), Persistence (TA0003)
- **Technique**: Valid Accounts (T1078), Cloud Accounts (T1078.004)

## DEVO Query

```sql
from cloud.aws.cloudtrail
where userIdentity.type = "Root"
  and eventName != "ConsoleLogin"
  and eventType != "AwsServiceEvent"
  and errorCode is null
select
  eventdate,
  userIdentity.accountId as account_id,
  eventName,
  eventSource,
  awsRegion,
  sourceIPAddress,
  userAgent,
  requestParameters,
  responseElements,
  errorCode,
  errorMessage
group by account_id, eventName, sourceIPAddress
```

## Alert Configuration
- **Trigger**: Any root account API usage
- **Throttling**: 1 alert per eventName per 30 minutes
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Verify if root account usage was authorized
2. Contact account owner immediately
3. Review what actions were performed
4. Check for unauthorized changes
5. Rotate root account credentials if unauthorized
6. Enable MFA on root account if not enabled
7. Review IAM users for proper permissions
8. Document legitimate use case if authorized
9. Implement Service Control Policies to restrict root
10. Set up CloudWatch alarm for root usage

## False Positive Considerations
- Initial account setup activities
- Specific tasks requiring root (billing, account closure)
- Break-glass emergency scenarios
- Legitimate administrative tasks

**Tuning Recommendations**:
- Exclude specific authorized root activities
- Whitelist ConsoleLogin for monitoring (separate alert)
- Document and approve root usage procedures
- Filter AwsServiceEvent and scheduled events

## Enrichment Opportunities
- Correlate with AWS Organizations activities
- Check against change management tickets
- Review IAM policy changes
- Cross-reference with security team schedules
- Analyze source IP geolocation
- Check for MFA usage

## Root Account Best Practices
- Never use for daily operations
- Enable MFA (hardware token preferred)
- Use strong, unique password
- Store credentials in secure vault
- Limit to absolute necessity
- Create IAM users with appropriate permissions
- Use AWS Organizations SCPs to restrict root

## Actions Requiring Root (Limited)
- Change account settings
- Close AWS account
- Restore IAM user permissions (if all admins locked out)
- Change AWS Support plan
- Register for GovCloud
- Modify account-level settings

## Response Playbook
1. Immediately verify root usage legitimacy
2. If unauthorized:
   - Lock down account immediately
   - Rotate root credentials
   - Enable MFA
   - Review all recent account changes
   - Check billing for unauthorized resources
   - Enable CloudTrail in all regions
   - Contact AWS Support
3. If authorized:
   - Document justification
   - Ensure MFA was used
   - Review changes made
   - Return to IAM user access
4. Implement preventive controls

## Investigation Steps
- Review full CloudTrail event details
- Check source IP and geolocation
- Verify user agent (is it expected?)
- Review all events in same session
- Check for resource creation/deletion
- Review IAM policy changes
- Analyze billing impact
- Check for data access

## Preventive Controls
- AWS Organizations SCP to deny root
- CloudWatch alarm for root login
- SNS notification for root usage
- Regular access reviews
- Security awareness training
- Documented root usage procedure
- Break-glass process for emergencies

## Compliance Impact
- Violates CIS AWS Benchmark
- PCI-DSS requirement violation
- SOC 2 control weakness
- May require audit notification

## Notes
- Root usage should be extremely rare
- Even authorized usage needs review
- Implement compensating controls
- High-value target for attackers
- Document every root usage
