# Correlation - Kill Chain Lateral Movement

## Severity
**CRITICAL**

## Description
Correlates multiple events across different data sources to detect complete lateral movement attack chains from initial access through credential theft and lateral propagation.

## MITRE ATT&CK
- **Tactic**: Lateral Movement (TA0008), Credential Access (TA0006), Execution (TA0002)
- **Technique**: Remote Services (T1021), Pass the Hash (T1550.002), Valid Accounts (T1078)

## DEVO Query

```sql
-- Correlate failed login, credential dump, and lateral movement
with initial_compromise as (
  select
    hostname,
    username,
    srcip,
    eventdate as compromise_time
  from siem.logins
  where result in ("failed", "failure")
  group by hostname, username, srcip
  every 30m
  having count() >= 10
),
credential_access as (
  select
    hostname,
    username,
    eventdate as cred_dump_time,
    process_name
  from edr.events
  where (target_process = "lsass.exe"
    or process_name like "%mimikatz%"
    or command_line like "%sekurlsa%")
),
lateral_movement as (
  select
    srcip,
    dstip,
    dst_hostname,
    username,
    eventdate as lateral_time,
    service_name
  from network.authentication, network.smb, network.rdp, network.wmi
  where (service_name in ("psexec", "wmiexec", "smbexec", "rdp")
    or event_type in ("smb_admin$", "c$_access", "remote_execution"))
)
-- Join the stages
select
  ic.hostname as patient_zero,
  ic.username as compromised_user,
  ic.compromise_time,
  ca.cred_dump_time,
  lm.dst_hostname as lateral_target,
  lm.lateral_time,
  lm.service_name as lateral_method,
  datediff_minutes(ic.compromise_time, ca.cred_dump_time) as time_to_cred_dump,
  datediff_minutes(ca.cred_dump_time, lm.lateral_time) as time_to_lateral,
  countdistinct(lm.dst_hostname) as systems_compromised
from initial_compromise ic
inner join credential_access ca on ic.hostname = ca.hostname
  and ca.cred_dump_time between ic.compromise_time and ic.compromise_time + 4h
inner join lateral_movement lm on ca.username = lm.username
  and lm.lateral_time between ca.cred_dump_time and ca.cred_dump_time + 2h
group by patient_zero, compromised_user
```

## Alert Configuration
- **Trigger**: Complete kill chain detected (initial compromise → cred dump → lateral movement)
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Activate incident response team
2. Isolate patient zero and all laterally accessed systems
3. Disable compromised user accounts
4. Block attacker source IPs
5. Reset credentials for all potentially compromised accounts
6. Hunt for additional compromised systems
7. Review domain controller for suspicious activity
8. Check for data exfiltration
9. Assess scope of compromise
10. Implement containment measures
11. Document full attack timeline
12. Preserve forensic evidence

## False Positive Considerations
- Legitimate IT administrative activities
- Automated system management
- Approved remote access
- Security tools performing assessments

**Tuning Recommendations**:
- Whitelist approved administrative accounts
- Exclude authorized remote management tools
- Document approved lateral access patterns
- Verify timing thresholds match environment

## Enrichment Opportunities
- Map complete attack path
- Identify all compromised systems
- Review data accessed on each system
- Correlate with threat intelligence
- Check for similar patterns in past
- Analyze attacker tools and techniques
- Identify additional IOCs
- Review network traffic for C2

## Response Playbook
1. **Immediate Containment** (0-30 min):
   - Declare major incident
   - Activate war room
   - Isolate all affected systems
   - Disable compromised accounts
   - Block attacker IPs
   - Snapshot systems for forensics

2. **Scope Assessment** (30 min - 2 hours):
   - Map all compromised systems
   - Identify patient zero
   - Document attack timeline
   - List compromised credentials
   - Check for domain admin compromise
   - Assess data exposure
   - Identify attacker objectives

3. **Threat Hunting** (2-8 hours):
   - Hunt for additional compromise
   - Search for persistence mechanisms
   - Check for backdoors
   - Review domain controllers
   - Scan for malware
   - Analyze network traffic
   - Check for data exfiltration

4. **Eradication** (8-24 hours):
   - Remove malware from all systems
   - Clear persistence mechanisms
   - Reset all compromised credentials
   - Reset krbtgt account (twice, 24h apart)
   - Patch vulnerabilities
   - Update security controls
   - Rebuild severely compromised systems

5. **Recovery** (1-7 days):
   - Staged system restoration
   - Enhanced monitoring
   - Verification testing
   - User communication
   - Normal operations resumption
   - Post-incident review

6. **Post-Incident** (Ongoing):
   - Full investigation report
   - Lessons learned
   - Control improvements
   - Threat intelligence sharing
   - Tabletop exercises
   - Policy updates

## Investigation Steps
- Reconstruct complete attack timeline
- Identify initial access vector
- Map credential theft progression
- Document lateral movement path
- List all affected systems
- Identify compromised accounts
- Check for privilege escalation
- Review data access and exfiltration
- Analyze attacker tools and techniques
- Determine attacker objectives
- Assess business impact

## Kill Chain Stages

**1. Initial Compromise**:
- Phishing
- Vulnerable service
- Weak credentials
- Supply chain

**2. Credential Access**:
- LSASS dumping
- Mimikatz
- DCSync
- Kerberoasting

**3. Lateral Movement**:
- PsExec
- WMI
- RDP
- SMB admin shares
- Pass-the-hash
- Golden ticket

**4. Privilege Escalation**:
- Domain admin compromise
- System vulnerabilities
- Misconfigured permissions

**5. Persistence**:
- Scheduled tasks
- Services
- Registry autoruns
- Backdoor accounts

**6. Impact**:
- Data exfiltration
- Ransomware
- Destruction
- Espionage

## Lateral Movement Techniques

**Windows Admin Shares**:
- \\system\C$
- \\system\ADMIN$
- \\system\IPC$

**Remote Execution**:
- PsExec: Remote process execution
- WMI: Windows Management Instrumentation
- DCOM: Distributed COM
- PowerShell Remoting
- Scheduled Tasks

**Remote Desktop**:
- RDP sessions
- RemoteApp
- Fast user switching

**Pass-the-Hash**:
- NTLM hash reuse
- No plaintext password needed
- Administrative access required

**Pass-the-Ticket**:
- Kerberos ticket reuse
- Golden tickets (krbtgt)
- Silver tickets (service)

## Critical Systems to Monitor
- Domain Controllers
- File Servers
- Database Servers
- Email Servers
- Backup Systems
- Jump Boxes/Bastion Hosts
- Privileged Access Workstations

## Indicators by Stage

**Initial Compromise**:
- Multiple failed logins
- Success after failures
- Unusual login location
- Off-hours access

**Credential Theft**:
- LSASS access
- Mimikatz execution
- SAM registry access
- NTDS.dit access

**Lateral Movement**:
- Admin share access
- Remote execution
- Multiple RDP sessions
- Unusual service accounts
- Cross-subnet access

## Network Patterns
- East-west traffic increase
- SMB traffic to multiple hosts
- RDP to non-standard targets
- WMI remote connections
- NTLM authentication spikes
- Kerberos anomalies

## Enhanced Correlation
```sql
-- Detect pass-the-hash
from network.authentication
where auth_type = "NTLM"
  and username in (select username from credential_access)
  and srcip != usual_srcip_for_user
  and datediff_minutes(auth_time, cred_dump_time) < 120
```

## Automated Response
- Auto-isolate patient zero
- Disable compromised accounts
- Block lateral movement IPs
- Alert SOC and IR team
- Snapshot systems
- Capture network traffic
- Enable enhanced logging

## Domain-Wide Response
If domain compromise confirmed:
- Emergency domain admin password reset
- Reset krbtgt account password
- Review all domain admin accounts
- Check for rogue domain admins
- Review GPOs for persistence
- Check trust relationships
- Reset computer accounts
- Force organizational password reset

## Forensic Collection
- Memory dumps from all systems
- Disk images of patient zero
- Network PCAP
- All authentication logs
- EDR timeline
- Email archives
- Browser history
- File access logs

## Business Impact Assessment
- Number of systems compromised
- Data accessed/exfiltrated
- Critical systems affected
- Downtime estimate
- Financial impact
- Regulatory implications
- Reputation damage
- Customer impact

## Threat Intelligence
Document:
- TTPs observed
- Tools used
- IOCs collected
- Attack timeline
- Attribution indicators
- Share with ISAC/ISAO
- Update threat models

## Notes
- Lateral movement = advanced attack
- Requires immediate response
- Assume domain-wide compromise
- Full investigation required
- Document everything
- Expensive to remediate
- Prevention is critical
