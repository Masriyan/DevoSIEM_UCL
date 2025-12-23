# IAM - Multiple Failed Logins Followed by Success

## Severity
**CRITICAL**

## Description
Detects successful authentication immediately following multiple failed login attempts, indicating potential credential stuffing or brute force attack success.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006), Initial Access (TA0001)
- **Technique**: Brute Force (T1110), Password Spraying (T1110.003), Credential Stuffing (T1110.004)

## DEVO Query

```sql
from siem.logins
where eventname in ("login", "authentication", "logon")
select
  eventdate,
  username,
  srcip,
  dsthost,
  result,
  application,
  useragent,
  count() as attempt_count,
  countdistinct(result) as distinct_results
group by username, srcip
every 10m
where attempt_count > 10
  and distinct_results > 1
  and some(result = "success")
  and some(result in ("failed", "failure", "denied"))
```

## Alert Configuration
- **Trigger**: 10+ failed attempts with at least 1 success in 10 minute window
- **Throttling**: 1 alert per username per 30 minutes
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Lock compromised account
2. Terminate all active sessions for the user
3. Reset user password immediately
4. Force MFA re-enrollment
5. Review successful login activities
6. Check for data access or exfiltration
7. Block source IP address
8. Review other accounts from same source IP
9. Hunt for lateral movement
10. Enable enhanced monitoring for user
11. Notify user of compromise

## False Positive Considerations
- User forgetting password (multiple retries)
- Password change procedures
- Automated scripts with credential issues
- SSO integration problems

**Tuning Recommendations**:
- Adjust threshold based on user population
- Exclude service accounts (alert separately)
- Consider time window (shorter for high-value accounts)
- Whitelist password reset flows

## Enrichment Opportunities
- Check user's normal login patterns
- Review source IP reputation and geolocation
- Correlate with threat intelligence
- Check for concurrent attacks on other accounts
- Review user's privilege level
- Analyze user agent for anomalies
- Check for impossible travel

## Response Playbook
1. **Immediate Containment**:
   - Lock account
   - Kill all sessions
   - Block source IP
2. **Investigation**:
   - Review all successful login activities
   - Check data accessed after compromise
   - Review privilege escalation attempts
   - Analyze lateral movement indicators
   - Check for persistence mechanisms
3. **Eradication**:
   - Reset password
   - Revoke all tokens/sessions
   - Remove unauthorized access
   - Clear persistence
4. **Recovery**:
   - Re-enable account with new credentials
   - Enforce MFA
   - Monitor for 30 days
   - User awareness training
5. **Lessons Learned**:
   - Document attack patterns
   - Update detection rules
   - Implement additional controls

## Investigation Steps
- Timeline of all login attempts
- Source IP geolocation and reputation
- User agent analysis
- Failed username variations attempted
- Success rate calculation
- Time pattern analysis (automated vs manual)
- Cross-reference with other security logs
- Check for account enumeration first

## Attack Patterns

**Credential Stuffing**:
- Uses known username/password combinations
- Often from breached databases
- High failure rate but some successes
- Multiple usernames from same IP

**Password Spraying**:
- Common passwords across many accounts
- Lower failure rate per account
- Distributed across time
- Multiple accounts from same IP

**Brute Force**:
- Sequential password attempts
- High failure rate
- Concentrated on single account
- May use password dictionaries

## Indicators of Compromise
- Unusual source IP or geolocation
- Login from new device/browser
- Different user agent than usual
- Access during off-hours
- Immediate suspicious actions after login
- Access to sensitive data
- Privilege escalation attempts
- Lateral movement

## Prevention Measures
- Implement MFA for all users
- Account lockout policies
- CAPTCHA after failed attempts
- Rate limiting on authentication
- Geo-blocking for high-risk locations
- Device trust/fingerprinting
- Impossible travel detection
- Leaked credential monitoring
- Password complexity requirements
- Regular password changes
- Security awareness training

## Enhanced Detection
```sql
-- Detect distributed brute force (multiple IPs, one account)
from siem.logins
where result in ("failed", "failure")
select
  username,
  countdistinct(srcip) as unique_ips,
  count() as total_attempts
group by username
every 30m
having unique_ips >= 5 and total_attempts >= 50
```

## Post-Compromise Actions to Check
- Email forwarding rules created
- MFA methods modified
- New app registrations/consents
- Privilege escalation
- Lateral movement to other systems
- Data access and download
- External file shares created
- Persistence mechanisms

## User Communication
Contact user immediately:
- Inform of account compromise
- Verify recent activities
- Confirm password reset
- Re-enable MFA
- Review authorized devices
- Security awareness refresher

## Integration Points
- Auto-lock account via IAM API
- Block IP at firewall
- SOAR playbook execution
- Ticket creation for IR team
- User notification via email/SMS
- Threat intelligence sharing

## Notes
- Critical severity warrants immediate response
- Assume full account compromise
- Check for privileged account targeting
- May be part of larger campaign
- Document for threat intelligence
