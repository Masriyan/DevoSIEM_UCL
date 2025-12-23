# GCP - IAM Policy Modification

## Severity
**HIGH**

## Description
Detects modifications to IAM policies in GCP that could grant unauthorized access or escalate privileges.

## MITRE ATT&CK
- **Tactic**: Privilege Escalation (TA0004), Persistence (TA0003)
- **Technique**: Account Manipulation (T1098), Valid Accounts (T1078.004)

## DEVO Query

```sql
from cloud.gcp.audit
select eventdate
select protoPayload.authenticationInfo.principalEmail as modifier
select protoPayload.resourceName as resource
select resource.labels.project_id
select protoPayload.serviceData.policyDelta.bindingDeltas.action as action
select protoPayload.serviceData.policyDelta.bindingDeltas.role as role
select protoPayload.serviceData.policyDelta.bindingDeltas.member as member
select protoPayload.requestMetadata.callerIp as source_ip
where `in`("SetIamPolicy", "google.iam.admin.v1.SetIAMPolicy", protoPayload.methodName)
  and protoPayload.serviceData.policyDelta.bindingDeltas is not null
  and (protoPayload.status.code is null or protoPayload.status.code = 0)

group by modifier, resource, role, member
```

## Alert Configuration
- **Trigger**: Any IAM policy modification
- **Throttling**: 1 alert per resource per 1 hour
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Review the IAM policy change details
2. Verify change was authorized
3. Assess new permissions granted
4. Check for overly permissive roles (Owner, Editor)
5. Review who made the modification
6. Validate member being granted access
7. Revert if unauthorized
8. Document if legitimate
9. Review all recent changes by same principal
10. Check for privilege escalation patterns

## False Positive Considerations
- Terraform/infrastructure-as-code deployments
- Legitimate user onboarding
- Service account configuration
- Project setup activities
- Automated deployment pipelines

**Tuning Recommendations**:
- Whitelist service accounts for IaC
- Exclude known deployment pipelines
- Require change management correlation
- Focus on high-privilege role assignments
- Filter automated GCP service modifications

## Enrichment Opportunities
- Correlate with change management tickets
- Review modified resource's purpose
- Check member's existing permissions
- Verify modifier's authorization level
- Review related IAM changes
- Check for infrastructure-as-code commits

## High-Risk IAM Modifications
Escalate to CRITICAL if:
- **Owner role granted** at project/org level
- **Service Account Admin** with key creation
- **Security Admin** role assignments
- **IAM Admin** role granted
- **Compute Admin** for VM access
- **Storage Admin** for data access
- Organization-level policy changes
- Public access granted (allUsers, allAuthenticatedUsers)

## Response Playbook
1. Identify what changed in IAM policy
2. Assess privilege level granted:
   - Primitive roles (Owner/Editor/Viewer)?
   - Predefined roles (what capabilities)?
   - Custom roles (review permissions)?
3. Verify legitimacy:
   - Change management approval?
   - Infrastructure-as-code change?
   - Authorized by resource owner?
4. For suspicious changes:
   - Revert IAM policy immediately
   - Review all changes by same principal
   - Check for unauthorized access
   - Investigate modifier's account
   - Look for compromise indicators
5. For legitimate changes:
   - Document justification
   - Verify least privilege
   - Set access review reminder
   - Monitor new member's activity

## Investigation Steps
- Review binding deltas (added/removed)
- Check role capabilities
- Verify member identity
- Review resource sensitivity
- Check modifier's permissions
- Analyze source IP and location
- Review audit logs for resource access
- Check for subsequent suspicious activities

## GCP IAM Roles by Risk

**Critical Risk**:
- roles/owner
- roles/iam.securityAdmin
- roles/iam.organizationAdmin
- roles/resourcemanager.organizationAdmin

**High Risk**:
- roles/editor
- roles/iam.serviceAccountAdmin
- roles/compute.admin
- roles/storage.admin
- roles/container.admin

**Medium Risk**:
- roles/compute.instanceAdmin
- roles/storage.objectAdmin
- Predefined resource-specific admin roles

## Common Privilege Escalation Patterns
1. Grant self higher privileges
2. Grant service account high privileges, then use key
3. Grant permissions to external account
4. Add allUsers/allAuthenticatedUsers
5. Modify custom role to add permissions
6. Grant at organization level for broad access

## Best Practices
- Use least privilege principle
- Prefer predefined over primitive roles
- Avoid Owner and Editor roles
- Use groups for access management
- Regular access reviews
- Infrastructure-as-code for IAM
- Conditional IAM bindings
- Organization policy constraints

## gcloud Commands
```bash
# View current IAM policy
gcloud projects get-iam-policy PROJECT_ID

# View specific binding
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.role:ROLE_NAME"

# Remove binding
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member='user:EMAIL' \
  --role='ROLE_NAME'

# View policy change history (via audit logs)
gcloud logging read "protoPayload.methodName=SetIamPolicy"
```

## Policy Delta Analysis
- **ADD**: New role binding created
- **REMOVE**: Role binding removed
- **Member changes**: Added/removed from existing role

## Compliance Considerations
- SOC 2: Access control changes
- ISO 27001: Authorization management
- PCI-DSS: Least privilege requirement
- Document in audit trail

## Automated Controls
- Organization policies to restrict roles
- Custom role restrictions
- VPC Service Controls
- Access Approval for sensitive changes
- Terraform Cloud/Sentinel policies

## Notes
- IAM changes are critical security events
- Even legitimate changes need review
- Primitive roles (Owner/Editor) are red flags
- Organization-level changes have wide impact
- Monitor for privilege escalation chains
