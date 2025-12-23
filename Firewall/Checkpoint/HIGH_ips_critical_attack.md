# Checkpoint - IPS Critical Attack Prevention

## Severity
**HIGH**

## Description
Detects critical severity attacks prevented by Checkpoint IPS, including exploits, buffer overflows, and remote code execution attempts.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Execution (TA0002), Privilege Escalation (TA0004)
- **Technique**: Exploit Public-Facing Application (T1190), Exploitation for Privilege Escalation (T1068)

## DEVO Query

```sql
from firewall.checkpoint.ips
where product = "IPS"
  and threat_severity in ("Critical", "High")
  and threat_prevention_action in ("Prevent", "Detect")
select
  eventdate,
  src,
  dst,
  service_id,
  application_name,
  protection_name,
  threat_severity,
  threat_prevention_action,
  attack_information,
  cveid,
  performance_impact,
  confidence_level,
  count() as attack_count
group by src, dst, protection_name
having attack_count >= 3
```

## Alert Configuration
- **Trigger**: 3 or more critical attacks from same source in 15 minutes
- **Throttling**: 1 alert per src+dst pair per 30 minutes
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Identify the targeted service/application
2. Verify if attack was successful (check logs)
3. Assess vulnerability status of target system
4. Review source IP reputation
5. Check for any successful connections from attacker
6. Apply security patches immediately
7. Implement virtual patching if patch unavailable
8. Consider blocking source network
9. Review firewall rules allowing access
10. Escalate to vulnerability management team

## False Positive Considerations
- Authorized vulnerability scans
- Penetration testing
- Security assessment tools
- Application compatibility testing

**Tuning Recommendations**:
- Whitelist approved scanner IPs
- Exclude penetration testing windows
- Adjust threshold based on environment
- Review specific protection names for accuracy

## Enrichment Opportunities
- Correlate with vulnerability management data
- Check CVE details and exploitability
- Review patch status of target
- Verify if system is reachable from source
- Cross-reference with threat intelligence
- Check for exploit kits in the wild

## Common Attack Types Detected
- Remote Code Execution (RCE)
- Buffer Overflow attempts
- SQL Injection
- Cross-Site Scripting (XSS)
- Directory Traversal
- Command Injection
- Privilege Escalation exploits

## Response Playbook
1. Verify attack severity and target
2. Check if system is vulnerable to detected attack
3. Review endpoint/server logs for signs of compromise
4. Patch vulnerable system urgently
5. Implement WAF/virtual patching rules
6. Monitor for continued attempts
7. Block persistent attackers
8. Review and tighten access controls
9. Conduct vulnerability assessment
10. Document for risk management

## CVE Analysis
When CVE is identified:
- Check CVSS score and exploitability
- Review vendor patch availability
- Assess exposure and business impact
- Prioritize patching accordingly
- Implement compensating controls

## Protection Levels
- **Prevent**: Attack was blocked
- **Detect**: Attack was detected but allowed (monitor mode)
- **Inactive**: Protection not active (configuration issue)

## Notes
- Even prevented attacks indicate targeting
- Check if protection is in prevent vs detect mode
- Multiple attempts may indicate automated scanning
- Single targeted attempt may be more concerning
- Correlation with vulnerability data is critical
