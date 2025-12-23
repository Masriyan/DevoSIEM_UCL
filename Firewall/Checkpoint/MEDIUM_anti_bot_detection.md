# Checkpoint - Anti-Bot Detection

## Severity
**MEDIUM**

## Description
Detects bot activity identified by Checkpoint Anti-Bot blade, including C2 communications, malicious downloads, and automated attacks.

## MITRE ATT&CK
- **Tactic**: Command and Control (TA0011), Execution (TA0002)
- **Technique**: Application Layer Protocol (T1071), Web Protocols (T1071.001)

## DEVO Query

```sql
from firewall.checkpoint.antibot
where product = "Anti-Bot"
  and action in ("Prevent", "Detect", "Prevent - Terminate")
  and confidence_level >= 2
select
  eventdate,
  src,
  dst,
  src_user_name,
  malware_action,
  bot_name,
  industry_reference,
  confidence_level,
  action,
  protection_name,
  protection_type,
  severity
group by src, dst, bot_name
```

## Alert Configuration
- **Trigger**: Any medium+ confidence bot detection
- **Throttling**: 1 alert per src+bot_name per hour
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Identify infected internal host
2. Check EDR for malware presence
3. Isolate host if confirmed compromise
4. Review bot family and capabilities
5. Identify initial infection vector
6. Check for data exfiltration indicators
7. Hunt for additional infections
8. Block C2 infrastructure
9. Reset affected user credentials
10. Review similar traffic patterns

## False Positive Considerations
- Legitimate automation tools
- Web scrapers for business intelligence
- API clients with aggressive behavior
- Approved remote access tools

**Tuning Recommendations**:
- Whitelist approved automation IPs
- Exclude legitimate bot traffic by user agent
- Adjust confidence threshold
- Document approved bots

## Enrichment Opportunities
- Correlate with DNS logs for C2 domains
- Check proxy logs for full URL context
- Review process execution on endpoint
- Cross-reference with malware databases
- Analyze traffic patterns for beaconing
- Check threat intelligence for bot family

## Common Bot Types
- **Banking Trojans**: Zeus, Gozi, Dridex
- **RATs**: NanoCore, njRAT, DarkComet
- **Info Stealers**: AZORult, Raccoon, RedLine
- **Loaders**: Emotet, TrickBot, QakBot
- **Backdoors**: Cobalt Strike, Meterpreter

## Response Playbook
1. Verify bot detection and confidence level
2. Identify bot family and capabilities
3. Scan affected endpoint with EDR
4. Check for persistence mechanisms
5. Review recent user/system activities
6. Isolate if confirmed compromise
7. Collect forensic artifacts
8. Eradicate malware
9. Hunt for similar IOCs
10. Update detection rules

## Bot Behavior Indicators
- Periodic beaconing to C2
- DGA (Domain Generation Algorithm) usage
- Fast-flux DNS patterns
- Connections to recently registered domains
- Unusual outbound traffic volumes
- Non-standard user agents
- Encrypted C2 channels

## Protection Types
- **Signature**: Known bot patterns
- **Behavioral**: Suspicious behavior analysis
- **Reputation**: Known malicious infrastructure
- **Protocol**: Protocol anomalies

## Integration Opportunities
- Auto-isolate via NAC/EDR
- Block C2 domains in DNS
- Share IOCs with threat intelligence
- Trigger SOAR playbook
- Create tickets for incident response

## Notes
- Anti-Bot detections indicate compromise
- Investigate even if traffic was blocked
- Bot may use multiple C2 channels
- Check for lateral movement
- Document bot family for threat intelligence
