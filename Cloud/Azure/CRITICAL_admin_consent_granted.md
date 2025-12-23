# Azure - Admin Consent Granted to Application

## Severity
**CRITICAL**

## Description
Detects when administrative consent is granted to applications in Azure AD, which could allow malicious applications to gain broad access to organizational data.

## MITRE ATT&CK
- **Tactic**: Persistence (TA0003), Privilege Escalation (TA0004)
- **Technique**: Account Manipulation (T1098), Additional Cloud Credentials (T1098.001)

## DEVO Query

```sql
from cloud.azure.auditlogs
where OperationName = "Consent to application"
  and ActivityDisplayName = "Consent to application"
  and ResultStatus = "Success"
  and TargetResources.modifiedProperties.newValue contains "AllPrincipal"
select
  eventdate,
  Identity,
  UserPrincipalName,
  AppDisplayName,
  ResourceDisplayName,
  TargetResources.modifiedProperties.displayName as permission_type,
  TargetResources.modifiedProperties.newValue as permissions_granted,
  SourceSystem,
  IPAddress,
  ResultReason,
  AdditionalDetails
group by UserPrincipalName, AppDisplayName, permissions_granted
```

## Alert Configuration
- **Trigger**: Any admin consent to new application
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Review the application and permissions granted
2. Verify if consent was authorized
3. Check application publisher and legitimacy
4. Review what data the application can access
5. Examine who granted the consent
6. Review application's previous activities
7. Revoke consent if suspicious
8. Disable application if malicious
9. Reset credentials of affected users
10. Review for data exfiltration
11. Implement conditional access policies

## False Positive Considerations
- Legitimate enterprise application deployments
- Approved SaaS integrations
- Microsoft first-party applications
- IT admin approved installations

**Tuning Recommendations**:
- Whitelist known/approved applications by App ID
- Exclude Microsoft first-party apps
- Require change management tickets
- Document approval process

## Enrichment Opportunities
- Check application registration details
- Review application's permissions scope
- Correlate with sign-in logs
- Check threat intelligence for app ID
- Review publisher verification status
- Analyze recent changes to application

## High-Risk Permissions
Critical permissions that should trigger immediate review:
- **Mail.Read/Mail.ReadWrite**: Email access
- **Files.Read.All**: All file access
- **Directory.Read.All/Directory.ReadWrite.All**: Full directory access
- **User.Read.All**: All user profile data
- **Calendars.Read**: Calendar access
- **Contacts.Read**: Contact information

## Response Playbook
1. Identify application and granted permissions
2. Verify application legitimacy:
   - Publisher verification status
   - Application age and reputation
   - Known in threat intelligence?
   - Requested permissions reasonable?
3. If suspicious or unauthorized:
   - Immediately revoke consent
   - Disable application
   - Review audit logs for application activity
   - Check for data access/exfiltration
   - Reset affected user credentials
   - Report to Microsoft if malicious
4. If legitimate:
   - Document approval
   - Verify least privilege
   - Implement monitoring
   - Set review reminder

## Investigation Steps
- Check Azure AD application registration
- Review application's sign-in logs
- Analyze Microsoft Graph API calls made
- Check for anomalous data access patterns
- Review who granted consent and from where
- Verify against procurement/purchase records
- Check for similar applications already in use

## Consent Types
- **Admin consent**: Applies to all users in organization
- **User consent**: Individual user only
- **Static consent**: Requested at app registration
- **Dynamic/Incremental consent**: Requested at runtime

## Malicious Application Indicators
- Recently created application
- Unverified publisher
- Excessive permissions requested
- Suspicious redirect URIs
- Typosquatting legitimate app names
- Generic or vague application names
- No clear business purpose

## Prevention Measures
- Disable user consent for applications
- Require admin approval for all apps
- Use verified publishers only
- Implement conditional access policies
- Regular application access reviews
- User awareness training (consent phishing)
- Azure AD Identity Protection

## PowerShell Commands
```powershell
# Review application permissions
Get-AzureADApplication -ObjectId <AppId> | Get-AzureADApplicationOAuth2Permission

# Revoke consent
Remove-AzureADOAuth2PermissionGrant -ObjectId <ConsentId>

# Disable application
Set-AzureADServicePrincipal -ObjectId <ServicePrincipalId> -AccountEnabled $false
```

## Compliance Impact
- GDPR: Potential unauthorized data access
- SOC 2: Access control violation
- May require data breach notification

## Threat Scenarios
1. **Consent Phishing**: Attacker tricks admin into consenting malicious app
2. **Compromised Admin**: Attacker uses compromised admin account
3. **Insider Threat**: Malicious insider grants access to external app
4. **Supply Chain**: Legitimate app compromised, malicious update

## Notes
- Admin consent is extremely powerful
- Should be rare and well-documented
- Implement approval workflow
- Regular audit of consented applications
- Zero tolerance for unauthorized consents
