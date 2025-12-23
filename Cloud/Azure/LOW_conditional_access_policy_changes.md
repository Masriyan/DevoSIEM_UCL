# Azure - Conditional Access Policy Changes

## Severity
**LOW**

## Description
Monitors changes to Azure AD Conditional Access policies to ensure security controls are maintained and unauthorized modifications are detected.

## MITRE ATT&CK
- **Tactic**: Defense Evasion (TA0005), Persistence (TA0003)
- **Technique**: Impair Defenses (T1562), Modify Cloud Compute Infrastructure (T1578)

## DEVO Query

```sql
from cloud.azure.auditlogs
where Category = "Policy"
  and OperationName in ("Add conditional access policy",
                         "Update conditional access policy",
                         "Delete conditional access policy")
  and ResultStatus = "Success"
select
  eventdate,
  InitiatedBy.user.userPrincipalName as modified_by,
  OperationName,
  TargetResources.displayName as policy_name,
  TargetResources.modifiedProperties.displayName as property_modified,
  TargetResources.modifiedProperties.oldValue,
  TargetResources.modifiedProperties.newValue,
  IPAddress,
  ActivityDisplayName
group by policy_name, modified_by, OperationName
```

## Alert Configuration
- **Trigger**: Any CA policy modification
- **Throttling**: 1 alert per policy per 4 hours
- **Severity**: Low
- **Priority**: P4

## Recommended Actions
1. Review the policy change details
2. Verify change was authorized in change management
3. Assess impact of the modification
4. Check if security posture was weakened
5. Review who made the change
6. Document the change rationale
7. Revert if unauthorized
8. Test policy impact if significant change

## False Positive Considerations
- Routine policy optimization
- Approved security improvements
- Troubleshooting access issues
- Pilot programs and testing
- Infrastructure-as-code deployments

**Tuning Recommendations**:
- Exclude service accounts used for automation
- Whitelist approved change windows
- Filter read-only operations
- Focus on delete and critical modifications
- Consider aggregated daily reports

## Enrichment Opportunities
- Correlate with change management tickets
- Review related policy changes
- Check sign-in impact metrics
- Verify with infrastructure-as-code repo
- Review change maker's recent activities

## High-Risk Policy Changes
Escalate to MEDIUM severity if:
- Policy deletion
- MFA requirement removed
- Trusted location requirements relaxed
- Disable policy protecting sensitive apps
- Exclude admin accounts from policies
- Block controls changed to report-only

## Response Playbook
1. Review change details in audit logs
2. Assess security impact:
   - Was protection weakened?
   - Were users/apps excluded?
   - Were controls relaxed?
3. Verify authorization:
   - Change management ticket?
   - Approved by security team?
   - Part of documented process?
4. For unauthorized changes:
   - Revert immediately
   - Investigate who made change
   - Review for compromise indicators
   - Check other changes by same user
5. For authorized changes:
   - Document justification
   - Monitor impact on sign-ins
   - Schedule follow-up review
   - Update documentation

## Investigation Steps
- Review old vs new policy configuration
- Check affected users/groups
- Verify app assignments
- Review grant controls changes
- Analyze session controls modifications
- Check conditions (locations, platforms, risk levels)
- Review exclusions added/removed

## Conditional Access Policy Components
- **Assignments**: Users, apps, conditions
- **Conditions**: Locations, devices, risk, platforms
- **Grant Controls**: MFA, compliant device, approved app
- **Session Controls**: Sign-in frequency, persistent browser

## Common Policy Changes
1. **User/Group Assignments**: Adding/removing scope
2. **Location Conditions**: Trusted locations changes
3. **MFA Requirements**: Enabling/disabling MFA
4. **Device Compliance**: Require/not require
5. **Application Assignments**: Protected apps changes
6. **Risk-Based Access**: Risk level thresholds
7. **Session Controls**: Timeout modifications

## Policy Change Categories
- **Protective**: Strengthening security (good)
- **Neutral**: Configuration updates (review)
- **Permissive**: Relaxing controls (scrutinize)
- **Deletion**: Removing policies (high scrutiny)

## Compliance Tracking
- Maintain audit trail
- Regular policy reviews
- Compare against security baseline
- Document all changes
- Report to compliance team
- Track policy coverage gaps

## Automation Opportunities
- Auto-approve infrastructure-as-code changes
- Integrate with change management system
- Automated policy backup before changes
- Policy configuration drift detection
- Weekly summary reports
- Tag-based change tracking

## Best Practices
- Use infrastructure-as-code for CA policies
- Implement change approval workflow
- Test in report-only mode first
- Document each policy's purpose
- Regular access impact reviews
- Version control for policies
- Backup policy configurations
- Staged rollout for major changes

## PowerShell Commands
```powershell
# Export CA policies
Get-AzureADMSConditionalAccessPolicy | ConvertTo-Json

# Compare policy versions
# (Use version control or backup comparison)

# Restore previous policy configuration
# Set-AzureADMSConditionalAccessPolicy
```

## Reporting Metrics
- Number of policy changes per week
- Top policy modifiers
- Most frequently modified policies
- Change types distribution
- Unauthorized change rate
- Time to detection for unauthorized changes

## Integration Points
- Change management system
- Infrastructure-as-code repositories (Terraform, ARM)
- SOAR for automated validation
- Slack/Teams for notifications
- Compliance dashboards

## Notes
- Low severity for routine tracking
- Can escalate based on change type
- Critical for compliance audit trail
- Enables configuration drift detection
- Foundation for security governance
