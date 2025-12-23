# AWS - Security Group Configuration Changes

## Severity
**LOW**

## Description
Monitors changes to EC2 security groups to track network access control modifications and ensure compliance with security policies.

## MITRE ATT&CK
- **Tactic**: Defense Evasion (TA0005), Persistence (TA0003)
- **Technique**: Impair Defenses (T1562), Disable or Modify Cloud Firewall (T1562.007)

## DEVO Query

```sql
from cloud.aws.cloudtrail
where eventSource = "ec2.amazonaws.com"
  and eventName in ("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
                     "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
                     "CreateSecurityGroup", "DeleteSecurityGroup",
                     "ModifySecurityGroupRules")
  and errorCode is null
select
  eventdate,
  userIdentity.principalId,
  userIdentity.arn as user_arn,
  eventName,
  requestParameters.groupId as security_group_id,
  requestParameters.groupName as security_group_name,
  requestParameters.ipPermissions,
  awsRegion,
  sourceIPAddress,
  userAgent
group by security_group_id, eventName, user_arn
```

## Alert Configuration
- **Trigger**: Aggregated daily or per significant change
- **Throttling**: 1 alert per security group per 6 hours
- **Severity**: Low
- **Priority**: P4

## Recommended Actions
1. Review the security group changes made
2. Verify changes align with change management
3. Check for overly permissive rules (0.0.0.0/0)
4. Validate business justification
5. Review associated EC2 instances
6. Document approved changes
7. Revert unauthorized changes
8. Review user's permissions

## False Positive Considerations
- Routine infrastructure changes
- Auto-scaling group updates
- Terraform/CloudFormation deployments
- Legitimate administrative activities

**Tuning Recommendations**:
- Exclude CI/CD service accounts
- Filter infrastructure-as-code deployments
- Whitelist approved change windows
- Focus on 0.0.0.0/0 rules for higher priority

## Enrichment Opportunities
- Correlate with change management tickets
- Check associated EC2 instances
- Review user's recent activities
- Verify against infrastructure-as-code
- Check for multiple security group changes

## High-Risk Patterns to Flag
1. **0.0.0.0/0 on sensitive ports**:
   - Port 22 (SSH)
   - Port 3389 (RDP)
   - Port 3306 (MySQL)
   - Port 5432 (PostgreSQL)
   - Port 1433 (MSSQL)

2. **Broad egress allowing all traffic**

3. **Changes outside business hours**

4. **Multiple rapid changes**

## Enhanced Detection Query
```sql
from cloud.aws.cloudtrail
where eventSource = "ec2.amazonaws.com"
  and eventName in ("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress")
  and (requestParameters.ipPermissions.items.ipRanges.items.cidrIp = "0.0.0.0/0"
    or requestParameters.ipPermissions.items.ipv6Ranges.items.cidrIpv6 = "::/0")
  and requestParameters.ipPermissions.items.toPort in (22, 3389, 3306, 5432, 1433, 1521, 27017)
```

## Response Playbook
1. Review security group change details
2. Check if change follows approved process
3. For high-risk changes (0.0.0.0/0):
   - Escalate to medium severity
   - Immediate review required
   - Contact change maker
   - Verify necessity
4. For routine changes:
   - Log for audit purposes
   - Periodic review
5. Revert if unauthorized
6. Update documentation

## Compliance Tracking
- Maintain audit trail of all changes
- Regular security group reviews
- Compare against security baselines
- Report violations to compliance team

## Security Group Best Practices
- Principle of least privilege
- Use specific IP ranges, not 0.0.0.0/0
- Separate security groups by tier
- Document security group purpose
- Regular access reviews
- Use VPC endpoints where possible
- Implement Security Group rules as code

## Investigation Checklist
- [ ] Change authorized in change management?
- [ ] User has legitimate access need?
- [ ] Source IP from corporate network?
- [ ] During approved change window?
- [ ] Infrastructure-as-code deployment?
- [ ] Associated with incident/emergency?
- [ ] Follows security standards?

## Automation Opportunities
- Auto-revert unauthorized 0.0.0.0/0 rules
- Slack/Teams notification for sensitive changes
- Integration with change management system
- Automated compliance checking
- Tag-based approval workflows

## Reporting Metrics
- Number of security group changes per week
- Percentage of changes with 0.0.0.0/0
- Top users making changes
- Most modified security groups
- Changes outside business hours
- Unauthorized changes

## AWS Config Rules
- restricted-ssh (Check for 0.0.0.0/0 on port 22)
- restricted-common-ports
- vpc-sg-open-only-to-authorized-ports

## Notes
- Low severity for tracking/audit purposes
- Can escalate based on specific changes
- Important for compliance documentation
- Enable AWS Config for continuous monitoring
- Consider aggregated daily reports
