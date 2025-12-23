# IAM - Privileged Account Login Outside Business Hours

## Severity
**HIGH**

## Description
Detects when privileged/administrative accounts authenticate outside of normal business hours, which may indicate unauthorized access or insider threat activity.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Privilege Escalation (TA0004)
- **Technique**: Valid Accounts (T1078), Domain Accounts (T1078.002)

## DEVO Query

```sql
from siem.logins
where result = "success"
  and (username in (select username from privileged_accounts)
    or usergroup in ("Domain Admins", "Enterprise Admins", "Administrators", "Global Admins")
    or username like "%admin%"
    or username like "%root%")
  and (hour(eventdate) < 6 or hour(eventdate) > 20
    or weekday(eventdate) in (0, 6)) -- Sunday=0, Saturday=6
select
  eventdate,
  username,
  srcip,
  dsthost,
  application,
  useragent,
  geolocation,
  hour(eventdate) as login_hour
group by username, srcip, dsthost
```

## Alert Configuration
- **Trigger**: Any privileged login outside 6 AM - 8 PM weekdays
- **Throttling**: 1 alert per username per 2 hours
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Contact the user immediately via phone (not email)
2. Verify if login was legitimate
3. Review activities performed during session
4. Check for changes to security configurations
5. Review for privilege abuse
6. Validate source IP and location
7. If unauthorized, lock account and kill sessions
8. Review other privileged accounts for similar activity
9. Document justification if legitimate
10. Review on-call schedule for authorized after-hours work

## False Positive Considerations
- On-call administrators
- Scheduled maintenance windows
- Global teams in different time zones
- Emergency incident response
- Approved after-hours projects

**Tuning Recommendations**:
- Adjust business hours based on organization
- Whitelist approved maintenance windows
- Exclude on-call rotations (with documentation)
- Consider time zones for global organizations
- Tag accounts with expected access patterns

## Enrichment Opportunities
- Check on-call schedule
- Review change management tickets
- Correlate with incident response activities
- Check user's normal access patterns
- Verify geolocation consistency
- Review actions performed during session

## What to Review
After detection, check for:
- Account modifications (creation, password resets)
- Group membership changes
- Security policy modifications
- Log tampering or deletion
- Data access and exfiltration
- System configuration changes
- Lateral movement
- Backdoor creation

## Response Playbook
1. **Immediate Verification**:
   - Call user directly (voice verification)
   - Do NOT email (account may be compromised)
   - Check if user is actually working
2. **If User Denies Activity**:
   - Lock account immediately
   - Terminate all sessions
   - Reset credentials
   - Escalate to incident response
   - Forensic investigation
3. **If Legitimate**:
   - Verify business justification
   - Check approval/ticket reference
   - Monitor session activities
   - Document in audit log
   - Set reminder for post-activity review
4. **Post-Session Review**:
   - What changes were made?
   - Was access appropriate?
   - Proper approvals in place?
   - Document for compliance

## Investigation Steps
- Review complete session activities
- Check source IP and geolocation
- Verify user agent and device
- Review privilege usage
- Check for unusual commands/queries
- Analyze data access patterns
- Look for automation indicators
- Cross-reference with other logs

## Privileged Account Indicators
- Domain/Enterprise Admin groups
- Local Administrator accounts
- Service accounts with high privileges
- Break-glass/emergency accounts
- Accounts with "admin", "root", "service" in name
- Cloud admin roles (Global Admin, Owner, etc.)
- Database admin accounts
- Network admin accounts

## High-Risk Activities to Flag
- User/group creation or modification
- Permission/role changes
- Security policy updates
- Log configuration changes
- Audit setting modifications
- Service installation
- Scheduled task creation
- Firewall rule changes
- Data export or download
- Lateral movement attempts

## Business Hours Configuration
Adjust based on your organization:
- Standard: 6 AM - 8 PM weekdays
- Extended: 5 AM - 11 PM including Saturdays
- Global: Account for time zones
- Seasonal: Adjust for business cycles

## Enhanced Detection
```sql
-- Check for multiple privileged accounts used
from siem.logins
where result = "success"
  and usergroup like "%Admin%"
  and hour(eventdate) not between 6 and 20
select
  srcip,
  countdistinct(username) as unique_admin_accounts,
  count() as total_logins
group by srcip
every 1h
having unique_admin_accounts >= 3
```

## Prevention Measures
- Privileged Access Workstations (PAW)
- Just-in-time admin access (PIM/PAM)
- Require approval for after-hours access
- Session recording for admin activities
- Separate admin accounts from regular user accounts
- Time-based conditional access policies
- MFA required for privileged accounts
- Restrict admin access to specific IPs/locations

## Compliance Impact
- SOC 2: Access control monitoring
- PCI-DSS: Privileged account oversight
- HIPAA: Administrative safeguards
- ISO 27001: Access management

## Automation Opportunities
- Auto-open ticket for security review
- Send SMS alert to user
- Require additional authentication
- Trigger session recording
- Alert to SOC in real-time

## Notes
- Not all after-hours access is malicious
- Context is critical (on-call, incident response)
- Balance security with operational needs
- Document approved exceptions
- Consider global teams and time zones
