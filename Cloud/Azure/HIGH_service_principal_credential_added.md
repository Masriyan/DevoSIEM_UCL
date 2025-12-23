# Azure - Service Principal Credential Added

## Severity
**HIGH**

## Description
Detects when credentials (secrets or certificates) are added to Azure service principals or applications, which could indicate persistence or privilege escalation.

## MITRE ATT&CK
- **Tactic**: Persistence (TA0003), Credential Access (TA0006), Privilege Escalation (TA0004)
- **Technique**: Account Manipulation (T1098), Additional Cloud Credentials (T1098.001)

## DEVO Query

```sql
from cloud.azure.auditlogs
where OperationName in ("Add service principal credentials",
                         "Update application - Certificates and secrets management",
                         "Add owner to service principal")
  and ResultStatus = "Success"
select
  eventdate,
  InitiatedBy.user.userPrincipalName as actor,
  InitiatedBy.user.ipAddress,
  TargetResources.displayName as app_or_sp_name,
  TargetResources.id as app_or_sp_id,
  TargetResources.modifiedProperties.displayName as property_modified,
  TargetResources.modifiedProperties.newValue as new_credential,
  ActivityDisplayName,
  Category,
  CorrelationId,
  AdditionalDetails
group by app_or_sp_name, actor
```

## Alert Configuration
- **Trigger**: Any credential addition to service principal/application
- **Throttling**: 1 alert per service principal per 30 minutes
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Verify if credential addition was authorized
2. Identify who added the credential
3. Review service principal/application permissions
4. Check for recent sign-ins using new credential
5. Review Azure AD audit logs for related activities
6. Verify business justification
7. Remove unauthorized credentials immediately
8. Reset all credentials if compromise suspected
9. Review application registration ownership
10. Check for privilege escalation attempts
11. Enable MFA for privileged accounts
12. Document approved credential additions

## False Positive Considerations
- Legitimate application deployments
- Credential rotation procedures
- CI/CD pipeline configurations
- Developer testing
- Approved automation workflows

**Tuning Recommendations**:
- Whitelist approved deployment service accounts
- Exclude CI/CD pipelines with documentation
- Require change management tickets
- Filter credential rotations (documented)
- Adjust for different environments

## Enrichment Opportunities
- Review service principal permissions
- Check application registration details
- Correlate with sign-in logs
- Review ownership of application
- Check for recent permission changes
- Verify assigned roles
- Review API permissions granted
- Check for concurrent suspicious activities

## Response Playbook
1. **Immediate Verification**:
   - Who added the credential?
   - Which service principal/application?
   - What permissions does it have?
   - When was it added?
   - Any recent sign-ins using it?

2. **Permission Assessment**:
   - Application permissions (delegated/application)
   - Directory role assignments
   - Resource access granted
   - API permissions
   - Scope of access

3. **Risk Determination**:
   - High-privilege SP? (Global Admin, etc.)
   - Access to sensitive data?
   - Recent permission grants?
   - Suspicious source IP?
   - After-hours addition?

4. **If Unauthorized**:
   - Remove credential immediately
   - Disable service principal if needed
   - Review all recent activities
   - Check for data access
   - Hunt for similar activity
   - Reset all credentials
   - Escalate to security team

5. **If Legitimate**:
   - Document approval
   - Verify least privilege
   - Set expiration on credential
   - Schedule periodic review
   - Update documentation

## Investigation Steps
- Review service principal's current permissions
- Check sign-in logs for credential usage
- Verify application ownership
- Review recent permission grants
- Check for admin consent grants
- Analyze source IP and location
- Review user account that added credential
- Check for pattern of credential additions
- Verify against change management

## Service Principal Attack Scenarios

**Persistence**:
- Add secret to existing high-privilege SP
- Use for long-term access
- Backdoor access to tenant
- Survive password resets

**Privilege Escalation**:
- Add credential to high-privilege app
- Exploit application permissions
- Escalate from user to application permissions
- Bypass conditional access

**Lateral Movement**:
- Access multiple resources
- Impersonate application
- API access without user context
- Cross-tenant access

**Data Exfiltration**:
- Access Graph API
- Read mail, files, etc.
- Export user data
- Access databases

## High-Risk Service Principals

**Critical Permissions**:
- Directory.ReadWrite.All
- User.ReadWrite.All
- Mail.ReadWrite
- Files.ReadWrite.All
- Application.ReadWrite.All
- RoleManagement.ReadWrite.Directory

**High-Privilege Roles**:
- Global Administrator
- Application Administrator
- Cloud Application Administrator
- Privileged Role Administrator

## Credential Types

**Client Secrets**:
- Password-based
- Expiration dates
- Can be multiple per app
- Harder to track usage

**Certificates**:
- More secure than secrets
- Public key uploaded
- Private key kept by application
- Can track by thumbprint

## Enhanced Detection

```sql
-- Detect credential add to privileged service principal
from cloud.azure.auditlogs
where OperationName like "%Add service principal credentials%"
  and TargetResources.id in (
    select servicePrincipalId from azure.roleassignments
    where roleDefinitionName in ("Global Administrator",
                                   "Application Administrator")
  )
```

## Investigation Queries

```powershell
# Get service principal details
Get-AzureADServicePrincipal -ObjectId <ServicePrincipalId>

# List application permissions
Get-AzureADServicePrincipal -ObjectId <Id> |
  Select-Object -ExpandProperty AppRoles

# Get recent sign-ins
Get-AzureADAuditSignInLogs -Filter "appId eq '<AppId>'" |
  Select TimeGenerated, UserPrincipalName, IPAddress, Status

# List credentials
Get-AzureADServicePrincipalKeyCredential -ObjectId <Id>
Get-AzureADServicePrincipalPasswordCredential -ObjectId <Id>
```

## Suspicious Patterns

**Red Flags**:
- After-hours credential addition
- Unusual source IP/location
- Multiple credentials added rapidly
- Addition to dormant service principal
- Privileged SP credential addition
- Addition by recently compromised account
- No change management ticket
- Credential never expires

## Legitimate Use Cases
- Application deployment
- Credential rotation
- Disaster recovery setup
- Multi-region deployment
- DevOps automation
- Backup credentials

## Prevention Measures
- Require approval workflow
- Conditional access policies
- Privileged Identity Management (PIM)
- Certificate-based auth preferred
- Short credential lifetimes
- Regular credential rotation
- Least privilege for SPs
- Audit log monitoring
- Alert on additions
- Regular SP reviews
- Remove unused SPs
- Disable instead of delete (audit trail)

## Service Principal Security Best Practices

**Credential Management**:
- Use certificates over secrets
- Short expiration periods (90 days max)
- Automated rotation
- Secure storage (Key Vault)
- Never hardcode in applications
- Monitor for expiration
- Remove unused credentials

**Permission Management**:
- Least privilege principle
- Application permissions only when needed
- Regular permission reviews
- Document all permissions
- Separate SPs per environment
- Limit scope of permissions

**Monitoring**:
- Alert on credential additions
- Monitor sign-in logs
- Track API usage
- Audit permission changes
- Review ownership changes
- Monitor certificate renewals

## Application vs Service Principal

**Application Object**:
- Template/definition
- Single instance in home tenant
- Defines permissions and configuration

**Service Principal**:
- Local instance in each tenant
- Used for actual sign-in
- Has credentials attached
- Subject to conditional access

## Ownership Review

Check owners:
- Who can modify?
- Recent ownership changes?
- Compromised owner accounts?
- Appropriate ownership?

## API Permissions to Flag

**Graph API**:
- Directory.ReadWrite.All
- User.ReadWrite.All
- Mail.Read/ReadWrite
- Files.ReadWrite.All
- Sites.ReadWrite.All

**Exchange**:
- full_access_as_app

**SharePoint**:
- Sites.FullControl.All

## Credential Lifetime Policy

Best practices:
- Secrets: 90 days or less
- Certificates: 1 year or less
- No indefinite credentials
- Automated expiration warnings
- Rotation procedures documented

## Automation Opportunities
- Auto-alert on additions
- Require approval workflow
- Temporary credential grants
- Automatic expiration enforcement
- Integration with SOAR
- Ticket creation
- Owner notification

## Compliance Impact
- Privileged access management
- Change control requirements
- Audit trail documentation
- Separation of duties
- Least privilege violations

## Recovery Actions

If compromise confirmed:
1. Remove all credentials
2. Disable service principal
3. Review all activities
4. Check data access logs
5. Reset related accounts
6. Review all SPs in tenant
7. Enhance monitoring
8. Update response procedures

## Notes
- Service principals are powerful
- Often overlooked in security
- Can bypass user protections
- No MFA by default
- Critical for cloud security
- Regular audits essential
- Automation requires careful security
