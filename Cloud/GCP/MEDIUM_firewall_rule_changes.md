# GCP - VPC Firewall Rule Modifications

## Severity
**MEDIUM**

## Description
Monitors changes to GCP VPC firewall rules that control network access to resources.

## MITRE ATT&CK
- **Tactic**: Defense Evasion (TA0005), Persistence (TA0003)
- **Technique**: Impair Defenses (T1562), Disable or Modify Cloud Firewall (T1562.007)

## DEVO Query

```sql
from cloud.gcp.audit
select eventdate
select protoPayload.authenticationInfo.principalEmail as modifier
select protoPayload.methodName as action
select protoPayload.resourceName as firewall_rule
select protoPayload.request.sourceRanges
select protoPayload.request.allowed
select protoPayload.request.denied
select protoPayload.request.priority
select protoPayload.requestMetadata.callerIp as source_ip
select resource.labels.project_id
where `in`("v1.compute.firewalls.insert",
                                   "v1.compute.firewalls.patch",
                                   "v1.compute.firewalls.update",
                                   "v1.compute.firewalls.delete", protoPayload.methodName)
  and (protoPayload.status.code is null or protoPayload.status.code = 0)

group by modifier, firewall_rule, action
```

## Alert Configuration
- **Trigger**: Any firewall rule modification
- **Throttling**: 1 alert per rule per 2 hours
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Review firewall rule change details
2. Verify change was authorized
3. Check for overly permissive rules (0.0.0.0/0)
4. Assess security impact
5. Review who made the change
6. Validate business justification
7. Revert if unauthorized
8. Test connectivity impact if needed

## False Positive Considerations
- Infrastructure-as-code deployments
- Network team routine changes
- Application deployment automation
- Troubleshooting activities

**Tuning Recommendations**:
- Whitelist Terraform/IaC service accounts
- Exclude CI/CD pipeline activities
- Require change tickets
- Focus on delete and high-risk changes

## Enrichment Opportunities
- Correlate with change management
- Review related GCP resource changes
- Check infrastructure-as-code repositories
- Verify with network team
- Review affected instances

## High-Risk Firewall Changes
Escalate to HIGH severity if:
- **0.0.0.0/0 source range** with sensitive ports (22, 3389, 3306, 5432, 1433)
- **Deletion of security rules**
- **Wide port ranges** (1-65535)
- **Changes to production** VPCs
- **Egress rules allowing all** traffic
- **Priority conflicts** with security rules

## Response Playbook
1. Review firewall rule modification:
   - What changed?
   - Source ranges added/removed?
   - Ports/protocols modified?
   - Priority changes?
2. Assess risk level:
   - Does it expose sensitive services?
   - Are source ranges too broad?
   - Is egress unrestricted?
3. Verify authorization:
   - Change management approval?
   - Infrastructure-as-code deployment?
   - Emergency change procedures followed?
4. For high-risk changes:
   - Review immediately
   - Contact change maker
   - Verify necessity
   - Implement least privilege alternative
5. For unauthorized:
   - Revert changes
   - Investigate modifier's account
   - Check for other suspicious changes

## Investigation Steps
- Compare before/after rule configuration
- Review affected instances/services
- Check rule priority and conflicts
- Verify source/destination ranges
- Analyze port and protocol changes
- Review target tags or service accounts
- Check for rule disablement

## GCP Firewall Components
- **Source Ranges**: IP addresses allowed
- **Target Tags**: Which instances rule applies to
- **Allowed/Denied**: Protocols and ports
- **Priority**: Rule evaluation order (0-65535)
- **Direction**: Ingress or egress
- **Action**: Allow or deny

## Common Security Issues
1. **0.0.0.0/0 on SSH/RDP**: Remote access from internet
2. **Wide port ranges**: Exposing unnecessary services
3. **Low priority security rules**: Easily overridden
4. **Disabled firewall rules**: Intended protections inactive
5. **All egress allowed**: Potential data exfiltration
6. **Legacy rules**: Forgotten, overly permissive rules

## Best Practices
- Default deny all traffic
- Explicit allow rules only
- Use least privilege
- Specific source IP ranges
- Named tags for organization
- Infrastructure-as-code for firewall rules
- Regular firewall rule audits
- Document rule purposes
- Remove unused rules

## gcloud Commands
```bash
# List firewall rules
gcloud compute firewall-rules list

# Describe specific rule
gcloud compute firewall-rules describe RULE_NAME

# Update rule (example: remove 0.0.0.0/0)
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges=SPECIFIC_IPS

# Delete rule
gcloud compute firewall-rules delete RULE_NAME

# View audit logs for firewall changes
gcloud logging read "protoPayload.methodName:firewalls"
```

## Sensitive Ports to Monitor
- 22 (SSH)
- 3389 (RDP)
- 3306 (MySQL)
- 5432 (PostgreSQL)
- 1433 (SQL Server)
- 27017 (MongoDB)
- 6379 (Redis)
- 9200 (Elasticsearch)
- 8080, 8443 (Common app ports)

## Compliance Impact
- CIS GCP Benchmark requirements
- Network segmentation standards
- PCI-DSS network isolation
- Audit trail requirements

## Automation Opportunities
- Auto-revert high-risk changes
- Integration with change management
- Terraform drift detection
- Automated compliance checking
- Alert routing based on risk level

## Notes
- Firewall changes impact security posture
- Review even authorized changes
- Infrastructure-as-code recommended
- Regular audits prevent rule sprawl
- Consider aggregated reports for low-risk changes
