# Impossible Travel Detection

## Severity
**CRITICAL**

## Description
Detects when a user authenticates from two geographically distant locations within a timeframe that makes physical travel impossible, indicating credential compromise or account sharing.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Credential Access (TA0006)
- **Technique**: Valid Accounts (T1078), Stolen Credentials (T1078)

## DEVO Query

```sql
from siem.logins
select eventdate
select username
select srcip
select geolocation.city as city
select geolocation.country as country
select geolocation.latitude as lat
select geolocation.longitude as lon
select application
select useragent
select lag(geolocation.latitude) over username as prev_lat
select lag(geolocation.longitude) over username as prev_lon
select lag(eventdate) over username as prev_login_time
select lag(srcip) over username as prev_ip
select -- Calculate distance in kilometers using Haversine formula
  (6371 * acos(
    cos(radians(prev_lat)) * cos(radians(lat)) *
    cos(radians(lon) - radians(prev_lon)) +
    sin(radians(prev_lat)) * sin(radians(lat))
  )) as distance_km
select -- Time difference in hours
  (eventdate - prev_login_time) / 3600000 as time_diff_hours
select -- Required speed in km/h
  (distance_km / (time_diff_hours + 0.001)) as required_speed_kmh
select mm2country(srcip) as src_country
where weakhas(result, "success")
```

## Alert Configuration
- **Trigger**: Travel speed > 900 km/h and distance > 500 km
- **Throttling**: 1 alert per username per 4 hours
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Lock user account
2. Terminate all active sessions
3. Contact user via phone to verify recent logins
4. Review all activities from both locations
5. Check for data exfiltration
6. Reset user credentials
7. Force MFA re-enrollment
8. Review for privilege escalation
9. Check other accounts for similar patterns
10. Block suspicious source IPs
11. Hunt for lateral movement

## False Positive Considerations
- VPN usage (switching exit points)
- Corporate proxy servers in different locations
- Mobile devices with location services
- Satellite/maritime internet connections
- Geo-IP database inaccuracies

**Tuning Recommendations**:
- Whitelist known VPN exit points
- Exclude corporate proxy IP ranges
- Increase distance threshold for VPN users
- Consider user's normal travel patterns
- Account for geo-IP accuracy (±50km)
- Whitelist trusted device + location combinations

## Enrichment Opportunities
- Check user's travel schedule/calendar
- Review device fingerprints
- Correlate with VPN authentication logs
- Check user agent consistency
- Review historical location patterns
- Verify against HR travel records
- Check for simultaneous sessions

## Response Playbook
1. **Immediate Containment**:
   - Lock account
   - Kill all active sessions
   - Prevent new logins
2. **User Verification**:
   - Call user immediately (voice verify)
   - Confirm physical location
   - Verify recent login locations
   - Ask about VPN usage
3. **Investigation**:
   - Review activities from both locations
   - Check data accessed
   - Look for privilege abuse
   - Analyze session behaviors
   - Check for malicious actions
   - Review similar patterns across users
4. **If Unauthorized**:
   - Full incident response
   - Reset credentials
   - Revoke all tokens
   - Enable enhanced monitoring
   - Hunt for IOCs
   - Report to appropriate teams
5. **If VPN/Legitimate**:
   - Document explanation
   - Update whitelist if needed
   - Re-enable account with MFA
   - Monitor for 30 days

## Investigation Steps
- Map both login locations on map
- Calculate actual travel time required
- Review activities from each location
- Compare user agents and devices
- Check for concurrent sessions
- Verify IP ownership and reputation
- Review authentication methods used
- Analyze access patterns from each location
- Check for data downloads/uploads
- Look for system/policy changes

## Risk Factors (Escalate Priority)
- **Admin/Privileged accounts**
- **Different devices**: Different OS/browser
- **Different user agents**: Indicates different computers
- **Data exfiltration**: Large downloads
- **Sensitive data access**
- **Policy changes**: Security configuration modifications
- **Lateral movement**: Access to other systems
- **Off-hours access**: Outside normal business hours

## Travel Speed Calculations
- **< 900 km/h**: Possibly legitimate (commercial flight)
- **900-2000 km/h**: Suspicious (requires investigation)
- **> 2000 km/h**: Definitely impossible (credential compromise)

## Example Scenarios

**Definitely Malicious**:
- New York (USA) → Tokyo (Japan) in 2 hours
- Speed: ~5,500 km/h (impossible)

**Likely Suspicious**:
- London (UK) → Dubai (UAE) in 1 hour
- Speed: ~5,500 km/h (impossible)

**Possibly Legitimate**:
- San Francisco → London in 12 hours
- Speed: ~700 km/h (possible with flight)
- **But check**: Different devices? Activities overlap?

## Enhanced Detection
```sql
-- Detect concurrent sessions from impossible locations
from siem.logins
where result = "success"
select
  username,
  collectdistinct(geolocation.country) as countries,
  countdistinct(srcip) as unique_ips,
  min(eventdate) as session_start,
  max(eventdate) as session_end
group by username
every 30m
where countdistinct(geolocation.country) >= 2
  and (max(eventdate) - min(eventdate)) < 3600000  -- within 1 hour
```

## Device Fingerprinting
Compare between logins:
- Operating system
- Browser and version
- Screen resolution
- Time zone
- Language settings
- Installed fonts
- Canvas fingerprint

Different fingerprints + impossible travel = High confidence compromise

## Prevention Measures
- Enforce MFA for all users
- Implement device trust/compliance
- Risk-based conditional access
- Continuous access evaluation
- Require device registration
- Geo-velocity checks
- Anomaly detection
- User awareness training
- Monitor for credential leaks
- Session timeouts

## User Communication Template
```
SECURITY ALERT: Suspicious Account Activity Detected

We detected logins to your account from:
1. [Location 1] at [Time 1]
2. [Location 2] at [Time 2]

These locations are [X] km apart and the timeframe makes physical travel impossible.

Your account has been temporarily locked for security.

If you were NOT in both locations:
- Your credentials may be compromised
- Do NOT use the same password elsewhere
- Contact Security IMMEDIATELY

Security Team will contact you shortly for verification.
```

## Compliance Impact
- GDPR: Potential unauthorized access to personal data
- SOC 2: Access control violation
- PCI-DSS: Account monitoring requirement
- May require breach notification

## Integration Points
- Auto-lock account via IAM API
- Block IPs at firewall
- SOAR playbook for investigation
- User notification via SMS/email
- MDM for device verification
- Threat intelligence sharing

## Notes
- One of most reliable compromise indicators
- Velocity impossible = credential theft
- VPNs are common false positives
- Always verify with user
- Critical for executives and privileged accounts
