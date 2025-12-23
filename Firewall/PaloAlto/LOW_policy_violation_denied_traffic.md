# Palo Alto - Policy Violation - Denied Traffic

## Severity
**LOW**

## Description
Monitors traffic denied by security policies to identify policy violations, misconfigured applications, or reconnaissance activities.

## MITRE ATT&CK
- **Tactic**: Discovery (TA0007), Reconnaissance (TA0043)
- **Technique**: Network Service Scanning (T1046), Active Scanning (T1595)

## DEVO Query

```sql
from firewall.paloalto.traffic
where action = "deny"
  and rule_name not in ("cleanup", "default-deny")
select
  eventdate,
  srcip,
  dstip,
  srcuser,
  dstport,
  application,
  rule_name,
  action,
  count() as attempt_count
group by srcip, dstip, dstport, rule_name
having attempt_count > 20
```

## Alert Configuration
- **Trigger**: More than 20 denies from same source to same destination/port in 1 hour
- **Throttling**: 1 alert per srcip per 4 hours
- **Severity**: Low
- **Priority**: P4

## Recommended Actions
1. Review denied traffic patterns
2. Determine if traffic is legitimate but misconfigured
3. Check if user requires access (policy update needed)
4. Look for scanning patterns
5. Investigate if part of reconnaissance activity
6. Review source device for unauthorized software

## False Positive Considerations
- Application auto-updates
- Service discovery protocols
- Misconfigured applications
- Mobile apps with hardcoded endpoints
- IoT device communications

**Tuning Recommendations**:
- Increase threshold for noisy applications
- Whitelist known service discovery traffic
- Exclude specific rule names that generate noise
- Adjust grouping for your environment

## Enrichment Opportunities
- Correlate with application installation logs
- Review user's role and access requirements
- Check asset inventory for device type
- Analyze timing patterns (automated vs. manual)

## Use Cases
1. **Policy Optimization**: Identify legitimate traffic being blocked
2. **Reconnaissance Detection**: Multiple port denies = scanning
3. **Shadow IT Discovery**: Unapproved applications trying to connect
4. **Compliance Monitoring**: Ensure policies are enforced

## Response Playbook
1. Categorize traffic type (scanning, legitimate, malicious)
2. For legitimate traffic: Update policy or provide alternative
3. For scanning: Investigate source device
4. For policy violations: Educate user or enforce policy
5. Document recurring patterns for policy review

## Reporting
- Weekly summary of top denied sources
- Top denied destinations
- Most triggered rules
- Trend analysis for policy effectiveness

## Notes
- Low severity but valuable for policy tuning
- Multiple denies may escalate to higher severity
- Useful for baseline establishment
- Consider aggregated weekly reports vs. real-time alerts
