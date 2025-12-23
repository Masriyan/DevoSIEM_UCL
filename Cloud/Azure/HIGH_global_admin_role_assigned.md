# Azure - Global Administrator Role Assigned

## Severity
**HIGH**

## Description
Detects when the Global Administrator role is assigned to a user in Azure AD, providing complete access to all Azure AD and Microsoft 365 services.

## MITRE ATT&CK
- **Tactic**: Privilege Escalation (TA0004), Persistence (TA0003)
- **Technique**: Account Manipulation (T1098), Valid Accounts (T1078.004)

## DEVO Query

```sql
from cloud.azure.auditlogs
where OperationName in ("Add member to role", "Add eligible member to role")
  and TargetResources.modifiedProperties.newValue contains "Company Administrator"
  or TargetResources.modifiedProperties.newValue contains "Global Administrator"
  or TargetResources.modifiedProperties.newValue contains "62e90394-69f5-4237-9190-012177145e10"
  and ResultStatus = "Success"
select
  eventdate,
  InitiatedBy.user.userPrincipalName as admin_who_assigned,
  TargetResources.userPrincipalName as new_global_admin,
  TargetResources.modifiedProperties.displayName as role_name,
  ActivityDisplayName,
  Category,
  IPAddress,
  SourceSystem,
  AdditionalDetails
group by new_global_admin, admin_who_assigned
```

## Alert Configuration
- **Trigger**: Any Global Admin role assignment
- **Throttling**: Real-time, no throttling
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Verify the role assignment was authorized
2. Confirm legitimate business need for Global Admin
3. Check if Privileged Identity Management (PIM) should be used instead
4. Review who made the assignment
5. Validate new admin's identity
6. Ensure MFA is enabled for new admin
7. Review new admin's recent activities
8. Document justification if legitimate
9. Remove role if unauthorized
10. Implement PIM for just-in-time access

## False Positive Considerations
- Approved new administrator onboarding
- Emergency break-glass scenarios
- Legitimate privilege escalation for projects
- PIM permanent assignments (should be avoided)

**Tuning Recommendations**:
- Require change management tickets
- Whitelist expected admin onboarding
- Alert on permanent vs. PIM eligible assignments
- Exclude known break-glass accounts (but monitor separately)

## Enrichment Opportunities
- Correlate with HR onboarding data
- Check against change management system
- Review user's previous role assignments
- Verify MFA enrollment status
- Check Conditional Access policies applied
- Review privileged access workstation usage

## Global Administrator Capabilities
The Global Administrator can:
- Manage all users and groups
- Reset passwords for any user
- Manage all licenses
- Access all data in Microsoft 365
- Configure all service settings
- Bypass most security controls
- Assign administrator roles
- Access all Azure resources (with elevation)

## Response Playbook
1. Verify assignment legitimacy immediately
2. Check if authorized in change management
3. Review new admin's account:
   - MFA enabled?
   - Account age and history
   - Recent sign-in patterns
   - Associated risks
4. If unauthorized:
   - Remove role immediately
   - Review audit logs for actions taken
   - Reset credentials of both accounts
   - Check for privilege abuse
   - Escalate to security team
5. If legitimate:
   - Ensure MFA is enabled
   - Implement PIM if not used
   - Set expiration date
   - Document business justification
   - Schedule access review

## Best Practices for Global Admins
- Minimize number of Global Admins (recommended: 2-4)
- Use Privileged Identity Management (PIM)
- Require just-in-time activation
- Enforce MFA with hardware tokens
- Use dedicated admin accounts (no daily use)
- Implement Privileged Access Workstations (PAW)
- Regular access reviews (monthly)
- Emergency access accounts (break-glass)

## Investigation Steps
- Review who made the assignment
- Check source IP and location
- Verify assignment was from trusted device
- Review timing (business hours vs. after hours)
- Check for concurrent suspicious activities
- Review both accounts' recent sign-in history
- Verify against approval workflows

## Alternative Roles to Consider
Instead of Global Admin, consider:
- **User Administrator**: Manage users/groups
- **Exchange Administrator**: Email management
- **SharePoint Administrator**: SharePoint management
- **Security Administrator**: Security settings
- **Compliance Administrator**: Compliance features
- Custom role with specific permissions

## PowerShell Commands
```powershell
# Check current Global Admins
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" |
  Get-AzureADDirectoryRoleMember

# Remove Global Admin role
Remove-AzureADDirectoryRoleMember -ObjectId <RoleObjectId> -MemberId <UserObjectId>

# Enable PIM for role
# (Use Azure Portal or PIM PowerShell module)
```

## Compliance Considerations
- Violates principle of least privilege
- May not comply with PCI-DSS
- SOC 2 control concern
- Required in audit logs

## PIM Configuration
If using Privileged Identity Management:
- Maximum activation duration: 8 hours
- Require MFA for activation
- Require approval for activation
- Require justification
- Set role assignment duration limit
- Configure access reviews

## Emergency Access Accounts
- Maintain 2 break-glass accounts
- Cloud-only accounts
- Excluded from Conditional Access
- Long, random passwords
- Stored in secure vault
- Monitor usage with high-priority alerts
- Never use for routine operations

## Notes
- Global Admin is most powerful role
- Should use PIM for just-in-time access
- Permanent assignments should be rare
- Regular reviews essential
- Consider administrative units for delegation
