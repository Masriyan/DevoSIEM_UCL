# Azure - Multiple Failed MFA Challenges

## Severity
**MEDIUM**

## Description
Detects multiple failed MFA attempts for a user, which may indicate MFA fatigue attacks, stolen credentials, or account compromise attempts.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006)
- **Technique**: Multi-Factor Authentication Request Generation (T1621), Brute Force (T1110)

## DEVO Query

```sql
from cloud.azure.signinlogs
select eventdate
select UserPrincipalName
select AppDisplayName
select IPAddress
select Location
select DeviceDetail.operatingSystem
select ResultType
select ResultDescription
select AuthenticationDetails.authenticationMethod
select count() as failed_attempts
where ResultType != "0"
  and weakhas(AuthenticationRequirement, "multiFactorAuthentication")
  and (weakhas(ResultDescription, "MFA")
    or weakhas(ResultDescription, "authentication")
    or weakhas(AuthenticationDetails.authenticationMethod, "PhoneAppNotification")
    or weakhas(AuthenticationDetails.authenticationMethod, "OneWaySMS"))

having failed_attempts >= 5
```

## Alert Configuration
- **Trigger**: 5+ failed MFA attempts in 1 hour
- **Throttling**: 1 alert per user per 2 hours
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Contact user immediately to verify MFA attempts
2. Review if user credentials may be compromised
3. Check for successful logins from same IP/location
4. Verify user's registered MFA methods
5. Review recent password changes
6. Check for account takeover indicators
7. Consider forcing password reset
8. Review conditional access policies
9. Educate user on MFA fatigue attacks
10. Enable additional security monitoring

## False Positive Considerations
- Users accidentally declining MFA prompts
- Poor cell phone coverage
- MFA app issues or device problems
- Users with multiple failed attempts during setup
- Time synchronization issues with TOTP

**Tuning Recommendations**:
- Adjust threshold based on user population
- Exclude MFA enrollment periods
- Consider time window adjustments
- Filter out specific result codes for technical issues

## Enrichment Opportunities
- Correlate with password spray attempts
- Check user's travel patterns
- Review for impossible travel
- Cross-reference with helpdesk tickets
- Analyze device compliance status
- Check for risky sign-in detections

## MFA Fatigue Attack Pattern
Attackers with valid credentials attempt to:
1. Repeatedly prompt user with MFA requests
2. Hope user gets fatigued and approves
3. Often occurs at odd hours
4. May include social engineering calls
5. User may approve just to stop notifications

## Response Playbook
1. Immediately contact user via trusted channel
2. Verify if user is attempting to sign in
3. If user denies attempts:
   - Force password reset immediately
   - Revoke all sessions
   - Review MFA methods for tampering
   - Check for successful logins
   - Enable enhanced monitoring
   - Report as potential compromise
4. If legitimate user attempts:
   - Troubleshoot MFA issues
   - Verify MFA device functionality
   - Check for app updates needed
   - Re-enroll MFA if necessary
5. Educate user on:
   - Never approving unexpected MFA prompts
   - Reporting suspicious activity
   - MFA fatigue attack tactics

## Investigation Steps
- Review full sign-in history for user
- Check source IP reputation and geolocation
- Verify if IP associated with VPN/proxy
- Review user agent and device details
- Check for concurrent successful logins
- Analyze MFA method types attempted
- Review conditional access policy evaluations
- Check for recent password changes

## MFA Fatigue Attack Indicators
- High volume of MFA prompts in short time
- Attempts during off-hours (late night, early morning)
- Followed by helpdesk calls about "MFA issues"
- Geographic mismatch with user's normal location
- Different device or browser than normal
- User reports receiving unexpected MFA prompts

## Prevention Measures
- Implement number matching for MFA
- Use FIDO2 security keys
- Enforce conditional access policies
- Enable sign-in risk policies
- User training on MFA fatigue
- Limit MFA prompt frequency
- Require additional context for MFA approval
- Monitor for abnormal MFA patterns

## Enhanced Detection
Look for patterns like:
- Multiple failures followed by success (possible approval fatigue)
- Attempts from risky locations
- Unusual times for specific user
- Rapid succession of attempts
- Different MFA methods attempted

## User Communication Template
```
We detected unusual MFA activity on your account:
- Multiple failed MFA attempts from [location]
- Time: [timestamp]

If this was you experiencing technical issues, please contact IT.
If you did NOT attempt these logins, your password may be compromised.

IMPORTANT: Never approve MFA prompts you didn't initiate.

Contact Security immediately if suspicious.
```

## Conditional Access Enhancements
- Require compliant devices
- Block access from risky locations
- Require password change on risk
- Session controls for sensitive apps
- Continuous access evaluation

## Notes
- MFA fatigue attacks are increasing
- User education is critical
- Number matching significantly reduces risk
- May need immediate account lockdown
- Balance security with user experience
