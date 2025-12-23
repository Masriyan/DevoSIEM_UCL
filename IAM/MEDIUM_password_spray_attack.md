# IAM - Password Spray Attack Detection

## Severity
**MEDIUM**

## Description
Detects password spray attacks where an attacker attempts the same password against multiple user accounts, typically to avoid account lockouts.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006)
- **Technique**: Brute Force: Password Spraying (T1110.003)

## DEVO Query

```sql
from siem.logins
where result in ("failed", "failure", "denied")
select
  eventdate,
  srcip,
  countdistinct(username) as unique_users_targeted,
  count() as total_attempts,
  collectdistinct(username) as usernames_list
group by srcip
every 15m
having unique_users_targeted >= 10 and total_attempts >= 10
```

## Alert Configuration
- **Trigger**: 10+ usernames with failed logins from same IP in 15 minutes
- **Throttling**: 1 alert per srcip per hour
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Block source IP address immediately
2. Review usernames targeted
3. Check for any successful authentications from same IP
4. Force MFA for targeted accounts
5. Check if any accounts are locked
6. Review source IP reputation and geolocation
7. Hunt for similar activity from related IPs
8. Notify users if compromise suspected
9. Review for weak/common passwords
10. Update account lockout policies

## False Positive Considerations
- SSO authentication failures during outages
- Misconfigured applications
- Load balancer health checks
- Legitimate batch authentication systems

**Tuning Recommendations**:
- Adjust username threshold (10-25 depending on environment)
- Exclude corporate IP ranges with SSO
- Whitelist monitoring systems
- Consider velocity (rapid vs. slow spraying)

## Enrichment Opportunities
- Check targeted accounts for patterns (naming convention)
- Review source IP threat intelligence
- Correlate with other attack indicators
- Check for account enumeration first
- Analyze timing patterns
- Review user agent strings

## Password Spray Characteristics
- **Low failure rate per account**: To avoid lockouts
- **Multiple accounts targeted**: 10-1000s of usernames
- **Common passwords used**: "Password123", "Summer2024", etc.
- **Time-distributed**: May pause between attempts
- **Same source IP or subnet**: Often from single location
- **Known username patterns**: firstname.lastname format

## Response Playbook
1. **Immediate Actions**:
   - Block attacking IP
   - Review for any successful logins
   - Alert security team
2. **Investigation**:
   - Identify all targeted usernames
   - Check for successful authentications
   - Review password patterns attempted
   - Analyze attack timing
   - Check for related IPs
3. **Mitigation**:
   - Force password reset for weak passwords
   - Implement MFA for high-value accounts
   - Update account lockout policies
   - Enable CAPTCHA on login pages
   - Geo-blocking if applicable
4. **Follow-up**:
   - User awareness campaign
   - Password policy review
   - Monitor for follow-up attacks
   - Document attack patterns

## Investigation Steps
- List all usernames targeted
- Check if usernames are valid (enumeration check)
- Verify if any accounts were locked
- Review successful logins from attacking IP
- Check historical activity from source IP
- Analyze user agent for attack tools
- Review timing distribution
- Check for distributed attacks (multiple IPs)

## Common Password Spray Patterns
- **Seasonal**: "Summer2024", "Winter2024"
- **Company name**: "CompanyName123"
- **Common**: "Password123", "Welcome123"
- **Keyboard patterns**: "Qwerty123"
- **Default**: "Admin123", "User123"

## Attack Variations

**Low and Slow**:
- 1-2 attempts per account per day
- Distributed over weeks
- Harder to detect
- Requires baseline analysis

**Distributed**:
- Multiple source IPs
- Cloud/proxy infrastructure
- Coordinated timing
- Requires correlation

**Targeted**:
- Focus on specific departments
- Executive accounts
- High-value targets
- Privilege escalation goal

## Enhanced Detection
```sql
-- Detect slow password spray (daily aggregation)
from siem.logins
where result = "failed"
select
  srcip,
  date(eventdate) as day,
  countdistinct(username) as unique_users,
  count() as attempts,
  max(attempts) as max_per_user
group by srcip, day
every 1d
having unique_users >= 20 and max_per_user <= 3
```

## Prevention Measures
- Account lockout policies (smart lockout)
- CAPTCHA after N failed attempts
- MFA for all users
- Rate limiting on authentication
- IP reputation blocking
- Geo-blocking high-risk countries
- Leaked password protection
- Strong password policies
- User awareness training
- Anomaly detection on auth logs

## Distributed Attack Detection
If password spray is from multiple IPs:
```sql
from siem.logins
where result = "failed"
select
  username,
  countdistinct(srcip) as unique_ips,
  count() as total_attempts
group by username
every 1h
having unique_ips >= 10
```

## Compliance Considerations
- NIST: Monitor for authentication failures
- CIS Controls: Account monitoring
- Document attack attempts
- May require user notification

## Automation Opportunities
- Auto-block attacking IPs
- Trigger MFA enrollment for targets
- Force password reset if weak password detected
- Create tickets for security review
- Update threat intelligence feeds
- Integrate with firewall for IP blocking

## Successful Spray Detection
```sql
-- Critical: Password spray with success
from siem.logins
where srcip in (select srcip from password_spray_ips)
  and result = "success"
select
  eventdate,
  username,
  srcip,
  application
```

## Notes
- Password sprays often precede targeted attacks
- May indicate reconnaissance phase
- Check for account enumeration before spray
- Low per-account failure rate is key indicator
- Successful spray = immediate incident response
