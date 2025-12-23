# AWS - Secrets Manager Secret Access Spike

## Severity
**HIGH**

## Description
Detects unusual or excessive access to AWS Secrets Manager secrets, which may indicate credential harvesting, data exfiltration, or compromised credentials.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006), Collection (TA0009)
- **Technique**: Unsecured Credentials: Credentials In Files (T1552.001), Cloud Instance Metadata API (T1552.005)

## DEVO Query

```sql
from cloud.aws.cloudtrail
select eventdate
select userIdentity.principalId
select userIdentity.arn as accessor_arn
select userIdentity.type as identity_type
select requestParameters.secretId as secret_name
select sourceIPAddress
select userAgent
select awsRegion
select recipientAccountId
select mm2country(sourceIPAddress) as source_country
select mm2city(sourceIPAddress) as source_city
select count() as access_count
select countdistinct(requestParameters.secretId) as unique_secrets_accessed
where weakhas(eventSource, "secretsmanager.amazonaws.com")
  and `in`("GetSecretValue", "BatchGetSecretValue", eventName)
  and errorCode is null
group by accessor_arn, sourceIPAddress
every 1h
having access_count > 50 or unique_secrets_accessed > 10
```

## Alert Configuration
- **Trigger**: > 50 accesses OR > 10 different secrets in 1 hour
- **Throttling**: 1 alert per accessor per 2 hours
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Identify the accessor (user, role, or service)
2. Verify legitimate business need for access
3. Review which secrets were accessed
4. Check access pattern (automated vs manual)
5. Verify source IP and location
6. Review accessor's recent activities
7. Check for data exfiltration indicators
8. Assess if credentials are compromised
9. Rotate accessed secrets if suspicious
10. Review IAM permissions for secret access
11. Enable secret rotation if not enabled
12. Audit all secret access policies

## False Positive Considerations
- Application startup (multiple secrets loaded)
- CI/CD pipeline deployments
- Auto-scaling events
- Legitimate batch operations
- Disaster recovery procedures
- Migration activities

**Tuning Recommendations**:
- Baseline normal access patterns per application
- Whitelist known application roles/users
- Exclude CI/CD service roles
- Adjust thresholds based on environment
- Different thresholds for different secret types
- Time-based exceptions (deployment windows)

## Enrichment Opportunities
- Review secret metadata and tags
- Check CloudTrail for related API calls
- Verify accessor's normal behavior baseline
- Review IAM role trust policy
- Check for concurrent suspicious activities
- Correlate with GuardDuty findings
- Review VPC Flow Logs if from EC2
- Check for impossible travel (cross-region)

## Response Playbook
1. **Immediate Assessment**:
   - Who/what is accessing secrets?
   - Which secrets were accessed?
   - Normal pattern or anomaly?
   - Source IP legitimate?
   - Access pattern (burst, steady, etc.)?

2. **Identity Analysis**:
   - IAM user or role?
   - Service account or human?
   - Recently created identity?
   - Permission changes recently?
   - MFA used?

3. **Secret Sensitivity Review**:
   - Database credentials?
   - API keys?
   - Encryption keys?
   - Third-party service tokens?
   - Production vs non-production?

4. **Risk Assessment**:
   - Compromised credentials suspected?
   - Data exfiltration risk?
   - Lateral movement potential?
   - Business impact if misused?

5. **If Suspicious**:
   - Rotate affected secrets immediately
   - Disable accessor credentials
   - Review all recent activities
   - Check for unauthorized access to resources
   - Hunt for lateral movement
   - Enable enhanced monitoring
   - Escalate to security team

6. **If Legitimate**:
   - Document business justification
   - Verify least privilege
   - Implement secret caching
   - Optimize access patterns
   - Set up monitoring baseline

## Investigation Steps
- Review complete CloudTrail history for accessor
- Check secret access patterns over time
- Verify source IP ownership and reputation
- Review IAM permissions for accessor
- Check for AssumeRole chains
- Analyze user agent strings
- Review session duration
- Check for concurrent API calls
- Verify geographic consistency
- Review error logs (denied attempts)

## Secrets Manager Attack Scenarios

**Credential Harvesting**:
- Compromised IAM credentials
- Stolen EC2 instance profile
- Lambda function abuse
- Container escape
- SSRF to metadata service

**Data Exfiltration**:
- Steal database credentials
- Access API keys
- Obtain encryption keys
- Third-party service tokens
- Certificate private keys

**Lateral Movement**:
- Database access
- Cross-account access
- Third-party services
- Internal APIs
- Production environments

**Persistence**:
- Create backdoor credentials
- Modify rotation functions
- Disable secret rotation
- Access long-lived secrets

## High-Risk Access Patterns

**Anomalies**:
- Sudden spike in access volume
- Access outside business hours
- New accessor (never accessed before)
- Different geographic location
- Multiple secrets accessed rapidly
- Failed attempts followed by success
- Access from unusual IP ranges

**Dangerous Patterns**:
- Brute force secret enumeration
- Sequential secret name testing
- Cross-region access spikes
- Unusual user agent (scripted tools)
- Multiple identity types accessing same secret

## Secret Types to Monitor

**Critical Secrets**:
- Production database passwords
- Root/admin credentials
- Encryption keys (KMS-related)
- API keys for critical services
- OAuth tokens
- Service-to-service auth tokens

**Medium Risk**:
- Non-production database creds
- Development API keys
- Internal service credentials
- Certificate private keys

## Enhanced Detection

```sql
-- Detect secret access from new IP/identity combination
from cloud.aws.cloudtrail
where eventName = "GetSecretValue"
  and concat(userIdentity.arn, sourceIPAddress) not in (
    select distinct concat(userIdentity.arn, sourceIPAddress)
    from cloud.aws.cloudtrail
    where eventName = "GetSecretValue"
      and eventdate between now() - 30d and now() - 1d
  )
select
  userIdentity.arn,
  sourceIPAddress,
  requestParameters.secretId,
  count() as new_access_count
group by userIdentity.arn, sourceIPAddress
```

## IAM Permission Review

Check for overly broad permissions:
- `secretsmanager:GetSecretValue` on `*`
- `secretsmanager:*` policies
- Cross-account secret access
- Public resource policies (rare but dangerous)

Recommended:
- Least privilege per application
- Resource-based policies
- Condition keys (source IP, VPC, etc.)
- Tag-based access control

## Secret Rotation Review

Ensure secrets have:
- Automatic rotation enabled
- Rotation frequency (30-90 days)
- Rotation Lambda function tested
- Rotation failure alerts
- Version tracking

## Source IP Analysis

Verify source:
- Corporate IP ranges?
- AWS service IP (Lambda, ECS, etc.)?
- Unknown external IP?
- VPN endpoint?
- Cloud provider IP?
- Tor exit node?
- Known bad IP?

## User Agent Analysis

Common legitimate:
- `aws-cli/2.x`
- AWS SDK user agents
- Application-specific agents
- CloudFormation/Terraform

Suspicious:
- Generic user agents
- Custom/unusual tools
- Obfuscated strings
- Known attack tools

## Secret Access Policy

Best practices:
- Deny by default
- Explicit allow per application
- VPC endpoint restriction
- Source IP conditions
- Time-based conditions
- MFA requirements for sensitive secrets
- Resource tagging requirements

## Monitoring Recommendations

**CloudWatch Metrics**:
- Access count per secret
- Unique accessors per secret
- Failed access attempts
- Cross-region access
- After-hours access

**CloudTrail Insights**:
- Enable for Secrets Manager events
- Detect unusual API activity patterns
- Automatic anomaly detection

**GuardDuty**:
- Enable for Secrets Manager
- Credential exposure detection
- Unusual API call patterns

## Caching and Optimization

Applications should:
- Cache secret values
- Use client-side caching
- Minimize API calls
- Use AWS SDK built-in caching
- Implement exponential backoff
- Set appropriate TTL

## Secrets Organization

**Tagging Strategy**:
- Environment (prod, dev, test)
- Application name
- Data classification
- Compliance requirements
- Owner/team
- Rotation schedule

**Naming Convention**:
- Include environment
- Application identifier
- Secret type
- Avoid exposing sensitive info in name

## Incident Response

If breach suspected:
1. Identify all accessed secrets
2. Rotate ALL accessed secrets immediately
3. Check secret version history
4. Review resources using secrets (databases, APIs)
5. Audit for unauthorized data access
6. Hunt for lateral movement
7. Disable compromised credentials
8. Review and strengthen IAM policies
9. Enable enhanced monitoring
10. Document and report

## Cost Considerations

High access volume impacts:
- API call costs
- Secret storage costs
- Data transfer costs
- KMS encryption costs

Optimize:
- Implement caching
- Batch operations where possible
- Use secret versions efficiently
- Review and clean up unused secrets

## Compliance Impact
- Unauthorized credential access
- Potential data breach
- Audit logging requirements
- Rotation policy compliance
- Access control violations
- May require incident reporting

## Automation Opportunities
- Auto-alert on anomalous access
- Automatic secret rotation on suspicious access
- Disable accessor on confirmed breach
- Integration with SOAR
- Automated forensic data collection
- Slack/Teams notifications
- Ticket creation

## Prevention Measures
- Least privilege IAM policies
- VPC endpoint policies
- Resource-based secret policies
- MFA for sensitive secrets
- Secret rotation enabled
- Regular access reviews
- Application-specific secrets
- Encryption in transit enforced
- CloudTrail logging enabled
- GuardDuty for Secrets Manager
- Secrets Manager Insights

## Notes
- Secret access is legitimate for applications
- Pattern analysis is key to detection
- Context matters (who, when, where, why)
- Baseline normal access first
- Combine multiple indicators
- Secrets are high-value targets
- Rotation is critical defense
- Monitor secret usage, not just access
