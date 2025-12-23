# Concurrent Sessions from Different Countries

## Severity
**HIGH**

## Description
Detects when a user has active concurrent sessions from two or more different countries, which may indicate credential sharing or account compromise.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Persistence (TA0003)
- **Technique**: Valid Accounts (T1078), Account Manipulation (T1098)

## DEVO Query

```sql
from siem.logins, siem.activity
where result = "success"
select
  username,
  eventdate,
  srcip,
  geolocation.country as country,
  geolocation.city as city,
  sessionid,
  application,
  useragent,
  deviceid
group by username, sessionid
every 15m
-- Find users with active sessions in multiple countries
with concurrent_countries as (
  select
    username,
    countdistinct(country) as unique_countries,
    collectdistinct(country) as countries_list,
    countdistinct(srcip) as unique_ips,
    collectdistinct(city) as cities_list
  group by username
  having unique_countries >= 2
)
```

## Alert Configuration
- **Trigger**: Active sessions in 2+ countries simultaneously
- **Throttling**: 1 alert per username per 2 hours
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Verify if user is traveling or using VPN
2. Contact user to confirm concurrent access
3. Review activities from each location
4. Check session details (devices, browsers)
5. Terminate suspicious sessions
6. Review for unauthorized access
7. If unauthorized, lock account and reset credentials
8. Force MFA verification
9. Monitor for 48 hours post-resolution
10. Document legitimate multi-country access

## False Positive Considerations
- Traveling users with active sessions
- VPN usage while maintaining local session
- Remote desktop/VDI connections
- Mobile devices roaming internationally
- Cloud services with distributed infrastructure
- SSO with applications in different regions

**Tuning Recommendations**:
- Whitelist VPN exit countries
- Exclude cloud service authentications
- Consider session age (old + new session)
- Document expected multi-country users
- Adjust for global workforce
- Filter same-region countries (EU, APAC)

## Enrichment Opportunities
- Check user's HR profile for role
- Review travel requests/calendar
- Verify device fingerprints
- Check VPN authentication logs
- Review session creation times
- Analyze user's historical patterns
- Cross-reference with expense reports

## Response Playbook
1. **Immediate Assessment**:
   - How many countries?
   - How far apart geographically?
   - When did each session start?
   - What activities in each session?
2. **User Contact**:
   - Call user for verification
   - Confirm physical location
   - Ask about VPN usage
   - Verify devices being used
3. **Session Analysis**:
   - Compare user agents
   - Review device fingerprints
   - Check session activities
   - Look for suspicious patterns
4. **Decision**:
   - **If VPN/Legitimate**: Document and allow
   - **If Traveling**: Verify itinerary
   - **If Suspicious**: Terminate sessions and investigate
   - **If Unauthorized**: Full IR protocol
5. **Follow-up**:
   - Monitor user for 48-72 hours
   - Review final disposition
   - Update detection rules if needed

## Investigation Steps
- List all active sessions with details
- Map session locations
- Timeline of session creation
- Compare activities across sessions
- Device and browser comparison
- Check for data access patterns
- Review privilege usage
- Look for automated vs. human behavior

## Risk Indicators
Increase severity if:
- **Different operating systems**
- **Significantly different time zones**
- **One session accessing sensitive data**
- **Privileged account**
- **No VPN usage detected**
- **Different organizations/networks**
- **Unusual application access**
- **After-hours in one location**

## Legitimate Multi-Country Scenarios
- User on international flight with stopovers
- VPN connection while maintaining local session
- Cloud apps with geo-distributed backends
- Remote work from different country
- Business travel with ongoing sessions
- Mobile device roaming
- Terminal services/VDI

## Session Comparison Matrix
| Attribute | Session 1 | Session 2 | Suspicious? |
|-----------|-----------|-----------|-------------|
| Country | USA | Russia | ✓ Yes |
| Device | iPhone | Windows | ✓ Yes |
| Browser | Safari | Chrome | Maybe |
| Time Zone | EST | MSK | ✓ Yes |
| Activity | Normal | Data Export | ✓ Yes |

## Enhanced Detection
```sql
-- High-risk: Concurrent sessions with different devices
from siem.activity
where sessionid is not null
select
  username,
  countdistinct(geolocation.country) as countries,
  countdistinct(deviceid) as unique_devices,
  countdistinct(useragent) as unique_agents,
  collectdistinct(geolocation.country) as country_list
group by username
every 10m
having countries >= 2 and unique_devices >= 2
```

## Geographic Risk Scoring
- **Low Risk**: Same region (e.g., France + Germany)
- **Medium Risk**: Different continents but plausible (USA + UK)
- **High Risk**: Geopolitically distant (USA + China)
- **Critical Risk**: High-risk country combinations

## Prevention Measures
- Session management policies
- Geographic restrictions for sensitive accounts
- Device trust requirements
- Continuous access evaluation
- Risk-based conditional access
- Session timeout policies
- Device registration requirements
- VPN mandate for international access

## Session Termination Criteria
Automatically terminate if:
- Different OS + different country
- High-risk country + sensitive data access
- Privileged account + suspicious activity
- No VPN + unexpected country
- Failed MFA in concurrent session

## User Communication
```
Security Notice: Multiple Active Sessions Detected

We detected active sessions for your account in:
- [Country 1]: [City] - [Device/Browser]
- [Country 2]: [City] - [Device/Browser]

If both sessions are yours (e.g., VPN, travel):
- No action needed
- Sessions will continue normally

If you do NOT recognize one of these locations:
- Change your password immediately
- Contact Security: [contact]
- Review account activity

Your security is important to us.
```

## Compliance Tracking
- Document all multi-country access
- Maintain user verification records
- Track false positive patterns
- Review monthly for trends

## Automation Opportunities
- Auto-challenge with MFA
- Require re-authentication
- Step-up authentication for risky sessions
- Automated user notification
- Integration with SOAR for investigation

## Notes
- Not as severe as impossible travel but still important
- Often legitimate with global workforce
- Context is crucial
- VPNs are primary false positive source
- Combine with other indicators for confidence
