# Palo Alto - Command and Control Communication

## Severity
**MEDIUM**

## Description
Detects potential command and control (C2) communication attempts based on Palo Alto threat intelligence and behavioral analysis.

## MITRE ATT&CK
- **Tactic**: Command and Control (TA0011)
- **Technique**: Application Layer Protocol (T1071), Web Protocols (T1071.001)

## DEVO Query

```sql
from firewall.paloalto.traffic
where threat_type = "spyware"
  or category in ("command-and-control", "malware", "phishing")
  and action in ("alert", "block", "drop", "reset-both")
select
  eventdate,
  srcip,
  dstip,
  srcuser,
  dstport,
  application,
  threat_name,
  category,
  action,
  bytes_sent,
  bytes_received,
  url
group by srcip, dstip, threat_name
```

## Alert Configuration
- **Trigger**: Any match
- **Throttling**: 1 alert per srcip per 30 minutes
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Identify the internal host attempting C2 communication
2. Check EDR for malware presence on the host
3. Review user activity and recent downloads
4. Isolate host if malware confirmed
5. Analyze destination IP/domain reputation
6. Review historical traffic from affected host
7. Check for data exfiltration indicators

## False Positive Considerations
- Cloud services misclassified as C2
- CDN networks
- Legitimate remote access tools
- Ad networks

**Tuning Recommendations**:
- Whitelist approved remote access tools
- Exclude corporate VPN endpoints
- Filter known cloud service IPs
- Adjust based on threat_name accuracy

## Enrichment Opportunities
- Correlate with DNS queries
- Check against threat intelligence platforms
- Review SSL certificate details
- Analyze traffic patterns (beaconing)
- Cross-reference with EDR alerts

## Response Playbook
1. Verify if communication was blocked or allowed
2. Scan affected system with updated AV/EDR
3. Review process execution history
4. Check scheduled tasks and persistence mechanisms
5. Reset affected user credentials
6. Hunt for similar IOCs across environment
7. Update threat prevention signatures

## Detection Engineering
- Look for periodic beaconing patterns
- Unusual data volumes
- Connections to recently registered domains
- Traffic to suspicious TLDs (.tk, .ml, etc.)

## Notes
- Blocked C2 still indicates compromised host
- Investigate even if traffic was denied
- May be part of multi-stage attack
