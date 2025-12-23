# AWS - GuardDuty Cryptocurrency Mining Detection

## Severity
**CRITICAL**

## Description
Detects cryptocurrency mining activity identified by AWS GuardDuty, indicating compromised EC2 instances being used for unauthorized crypto mining.

## MITRE ATT&CK
- **Tactic**: Impact (TA0040), Resource Hijacking (TA0042)
- **Technique**: Resource Hijacking (T1496)

## DEVO Query

```sql
from cloud.aws.guardduty
where type like "%CryptoCurrency%"
  or type = "CryptoCurrency:EC2/BitcoinTool.B!DNS"
  or type = "CryptoCurrency:EC2/BitcoinTool.B"
  and severity >= 7
select
  eventdate,
  accountid,
  region,
  resource.instanceDetails.instanceId as instance_id,
  resource.instanceDetails.imageId as ami_id,
  type,
  title,
  description,
  severity,
  service.action.networkConnectionAction.remoteIpDetails.ipAddressV4 as mining_pool_ip,
  service.action.networkConnectionAction.remotePortDetails.port as mining_port,
  resource.instanceDetails.tags
group by accountid, instance_id, type
```

## Alert Configuration
- **Trigger**: Any cryptocurrency mining detection
- **Throttling**: 1 alert per instance per 2 hours
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Isolate affected EC2 instance
2. Snapshot instance for forensics
3. Review instance launch details and who deployed it
4. Check CloudTrail for unauthorized activities
5. Identify how instance was compromised
6. Review security groups and network ACLs
7. Terminate compromised instance
8. Launch new instance from clean AMI
9. Review AWS billing for unusual charges
10. Scan other instances for similar IOCs
11. Reset all credentials that had access to instance

## False Positive Considerations
- Authorized blockchain development/testing
- Legitimate cryptocurrency operations
- Approved mining pools for research

**Tuning Recommendations**:
- Whitelist approved instances/accounts for crypto activities
- Exclude dev/test environments with documented crypto work
- Very low false positive rate for production

## Enrichment Opportunities
- Correlate with CloudTrail for user activities
- Check VPC Flow Logs for mining pool connections
- Review IAM activities on the account
- Check for other GuardDuty findings on same instance
- Analyze AWS Config for configuration changes
- Review Systems Manager Session Manager logs

## Response Playbook
1. Confirm cryptocurrency mining activity
2. Immediately isolate instance (modify security groups)
3. Create snapshot for forensics
4. Review CloudTrail for compromise timeline
5. Identify initial access vector
6. Check for persistence mechanisms (user data, startup scripts)
7. Review IAM credentials exposure
8. Terminate compromised instance
9. Hunt for similar activity across account
10. Review and harden security controls
11. Check billing for resource abuse
12. Report to AWS Abuse if external compromise

## Common Cryptocurrency Mining Indicators
- High CPU utilization (80-100%)
- Connections to known mining pools
- Unusual DNS queries for mining domains
- Modified user data or startup scripts
- Unexpected scheduled tasks/cron jobs
- Unauthorized software installations

## Mining Pool Domains/IPs to Monitor
- moneropool.com
- minergate.com
- nanopool.org
- ethermine.org
- Stratum protocol (port 3333, 4444, 14444)

## Investigation Steps
1. Review instance metadata
2. Check System Manager logs
3. Analyze network connections
4. Review running processes (if accessible)
5. Check for SSH/RDP brute force in auth logs
6. Review IAM key usage
7. Check for vulnerable services

## Cost Impact Analysis
- Review CloudWatch metrics for CPU usage
- Check AWS Cost Explorer for unexpected charges
- Calculate financial impact
- Document for billing dispute if needed

## Prevention Measures
- Enable GuardDuty in all regions
- Implement least privilege IAM
- Use instance metadata service v2 (IMDSv2)
- Regular vulnerability scanning
- Security group restrictions
- VPC endpoint policies
- CloudWatch alarms for CPU anomalies

## Notes
- Crypto mining indicates full instance compromise
- May be part of broader attack campaign
- Check for data exfiltration alongside mining
- Review all resources in affected account
- Consider account-wide security review
