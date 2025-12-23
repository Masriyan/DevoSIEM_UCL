# Fortinet - Network Anomaly Detection

## Severity
**MEDIUM**

## Description
Detects network anomalies identified by Fortinet's anomaly detection engine, including unusual traffic patterns, protocol violations, and suspicious behaviors.

## MITRE ATT&CK
- **Tactic**: Discovery (TA0007), Command and Control (TA0011)
- **Technique**: Network Sniffing (T1040), Protocol Tunneling (T1572)

## DEVO Query

```sql
from firewall.fortinet.anomaly
where anomaly = "anomaly"
  or subtype = "anomaly"
select
  eventdate,
  srcip,
  dstip,
  srcport,
  dstport,
  proto,
  anomaly,
  severity,
  action,
  msg,
  attack_name,
  count() as occurrence_count
group by srcip, dstip, anomaly, attack_name
having occurrence_count > 5
```

## Alert Configuration
- **Trigger**: More than 5 anomalies from same source in 30 minutes
- **Throttling**: 1 alert per srcip per hour
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Analyze the type of anomaly detected
2. Review traffic patterns from source IP
3. Check if behavior is legitimate but unusual
4. Verify protocol compliance
5. Investigate for tunneling or data exfiltration
6. Review affected application/service
7. Check for misconfigured devices

## False Positive Considerations
- Legitimate but uncommon protocols
- Application updates with unusual patterns
- Network performance testing
- Backup operations
- Video conferencing spikes

**Tuning Recommendations**:
- Baseline normal network behavior
- Exclude approved testing activities
- Adjust thresholds for high-volume applications
- Filter specific anomaly types that are known false positives

## Common Anomaly Types
- TCP/UDP port scan anomalies
- Protocol header violations
- Abnormal traffic volumes
- Unusual protocol usage
- Fragment attacks
- Session anomalies

## Enrichment Opportunities
- Correlate with netflow data
- Check user/device context
- Review time-of-day patterns
- Cross-reference with change management
- Analyze application logs

## Response Playbook
1. Classify anomaly type (scanning, tunneling, malformed, volume)
2. Determine if legitimate (testing, new application, etc.)
3. For scanning: Investigate source for compromise
4. For tunneling: Check for data exfiltration
5. For malformed: Check for exploit attempts
6. For volume: Verify if DDoS or data transfer
7. Update baseline if legitimate new pattern
8. Enhance detection if malicious

## Anomaly Categories

### Port Scan Anomalies
- SYN flood patterns
- Horizontal/vertical scanning
- Low-and-slow scans

### Protocol Anomalies
- Malformed packets
- Invalid flags
- Protocol violations

### Volume Anomalies
- Unusual bandwidth consumption
- Spike in connections
- Abnormal session counts

### Behavioral Anomalies
- Unusual hours activity
- Geo-location changes
- New protocol usage

## Notes
- Anomalies may indicate early-stage attacks
- Baseline is critical for accuracy
- Combine with other telemetry for context
- Not all anomalies are malicious
