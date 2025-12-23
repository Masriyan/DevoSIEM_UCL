# Fortinet - Geographic Location Policy Violation

## Severity
**LOW**

## Description
Monitors connections from or to blocked geographic regions based on security policy, useful for compliance and threat reduction.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001)
- **Technique**: External Remote Services (T1133)

## DEVO Query

```sql
from firewall.fortinet.traffic
where action = "deny"
  and (srcipgeo not in ("US", "CA", "GB", "AU", "DE", "FR", "NL")
  or dstipgeo not in ("US", "CA", "GB", "AU", "DE", "FR", "NL"))
select
  eventdate,
  srcip,
  dstip,
  srcipgeo,
  dstipgeo,
  srcport,
  dstport,
  proto,
  service,
  action,
  policyid,
  count() as attempt_count
group by srcip, dstip, srcipgeo, dstipgeo
having attempt_count > 10
```

## Alert Configuration
- **Trigger**: More than 10 denied connections from/to blocked geo in 6 hours
- **Throttling**: 1 alert per source country per day
- **Severity**: Low
- **Priority**: P4

## Recommended Actions
1. Verify geographic location of source/destination
2. Review if connection is legitimate business need
3. Check for VPN/proxy usage
4. Confirm geo-blocking policy is appropriate
5. Investigate if internal user is traveling
6. Review for compromised accounts (unusual locations)

## False Positive Considerations
- Traveling employees
- VPN exit points
- Cloud services with geo-distributed infrastructure
- CDN networks
- Remote workers in different countries

**Tuning Recommendations**:
- Whitelist corporate VPN endpoints
- Exclude cloud service IP ranges
- Adjust allowed countries based on business needs
- Consider time zones for traveling employees
- Implement user-based exceptions

## Enrichment Opportunities
- Correlate with VPN authentication logs
- Check travel request systems
- Review user's normal access patterns
- Verify against asset management for expected locations
- Cross-reference with HR data for remote workers

## Use Cases
1. **Compliance**: Enforce data sovereignty requirements
2. **Threat Reduction**: Block high-risk countries
3. **Policy Enforcement**: Ensure geo-restrictions are working
4. **Anomaly Detection**: Detect compromised accounts

## Response Playbook
1. Verify actual geographic location (may be VPN)
2. For outbound: Check if user is traveling
3. For inbound: Verify if legitimate business connection
4. Review user authentication logs
5. If suspicious: Reset credentials and investigate
6. If legitimate: Update policy or create exception
7. Document business justification for exceptions

## Common Blocked Regions (Example)
- High-risk countries per threat intelligence
- Regions with no business presence
- Countries under sanctions
- Known attack source regions

## Policy Considerations
- Balance security with business needs
- Document exceptions clearly
- Review policy quarterly
- Consider different rules for different services
- Allow exceptions for critical business needs

## Reporting
- Monthly summary of blocked geo-locations
- Top blocked countries
- Exception usage statistics
- Trend analysis for new geographic threats

## Notes
- Low severity but important for compliance
- Useful for identifying account compromise
- Should align with business operations
- Combine with user context for accuracy
- Consider aggregated reports vs real-time alerts
