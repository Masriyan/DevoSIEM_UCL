# Fortinet - IPS Botnet Detection

## Severity
**CRITICAL**

## Description
Detects botnet communication identified by FortiGuard IPS signatures, indicating a compromised host participating in botnet activities.

## MITRE ATT&CK
- **Tactic**: Command and Control (TA0011)
- **Technique**: Application Layer Protocol (T1071), Non-Application Layer Protocol (T1095)

## DEVO Query

```sql
from firewall.fortinet.ips
select eventdate
select srcaddr
select dstaddr
select srcintf
select dstintf
select srcport
select dstport
select proto
select attack_name
select attack_id
select severity
select action
select msg
select mm2country(srcaddr) as src_country
select mm2country(dstaddr) as dst_country
select purpose(srcaddr) as src_purpose
select purpose(dstaddr) as dst_purpose
where weakhas(attack_name, "Botnet")
  or weakhas(attack_name, "Bot.")
  or weakhas(signature_subclass, "botnet")
group by srcaddr, dstaddr, attack_name
```

## Alert Configuration
- **Trigger**: Any match
- **Throttling**: 1 alert per srcip per 10 minutes
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Isolate infected host from network
2. Identify botnet family and C2 infrastructure
3. Check EDR for malware presence and persistence
4. Analyze initial infection vector
5. Review all recent activities from affected host
6. Check for data exfiltration
7. Hunt for additional infected systems
8. Reset credentials for affected user/system
9. Block C2 domains/IPs globally

## False Positive Considerations
- Security research tools
- Honeypot traffic
- Threat intelligence collection systems

**Tuning Recommendations**:
- Whitelist security research networks
- Exclude threat intelligence infrastructure
- Very low false positive rate for botnet signatures

## Enrichment Opportunities
- Correlate with DNS logs for C2 domains
- Check historical connections from infected host
- Review email logs for initial infection
- Cross-reference with threat intelligence for botnet family
- Analyze proxy logs for web-based C2

## Response Playbook
1. Confirm botnet infection via EDR/forensics
2. Identify botnet family and capabilities
3. Isolate affected system(s)
4. Capture forensic artifacts
5. Identify root cause/infection vector
6. Eradicate malware and persistence
7. Monitor for reinfection
8. Update security controls with IOCs
9. Report to abuse contacts if external C2
10. Document incident for lessons learned

## Known Botnet Families
- Emotet
- TrickBot
- Dridex
- QakBot
- Mirai (IoT)
- Zeus/Zbot

## Indicators to Hunt
- Scheduled tasks
- Registry run keys
- Unusual network connections
- DGA (Domain Generation Algorithm) patterns
- Lateral movement attempts
- Credential dumping

## Notes
- Botnet detection is high-fidelity
- Assume system compromise
- May be part of ransomware attack chain
- Check for lateral movement immediately
