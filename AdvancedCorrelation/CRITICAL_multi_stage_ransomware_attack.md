# Advanced Correlation - Multi-Stage Ransomware Attack Chain

## Severity
**CRITICAL**

## Description
Correlates multiple security events across different data sources to detect the complete ransomware attack lifecycle from initial compromise through reconnaissance, privilege escalation, lateral movement, data exfiltration, and final encryption. This advanced correlation rule identifies ransomware attacks in progress before encryption begins.

## MITRE ATT&CK
- **Tactic**: Full Kill Chain - Initial Access (TA0001) → Execution (TA0002) → Persistence (TA0003) → Privilege Escalation (TA0004) → Defense Evasion (TA0005) → Credential Access (TA0006) → Discovery (TA0007) → Lateral Movement (TA0008) → Collection (TA0009) → Exfiltration (TA0010) → Impact (TA0040)
- **Technique**: Multiple including Phishing (T1566), Exploit Public-Facing Application (T1190), Valid Accounts (T1078), Data Encrypted for Impact (T1486), Inhibit System Recovery (T1490)

## DEVO Query

```sql
-- Stage 1: Initial Compromise Detection
from siem.events initial_compromise
select eventdate as compromise_time
select hostname as patient_zero
select src_ip as attacker_ip
select username as compromised_user
select event_type as initial_vector
where (
    -- Phishing with macro execution
    (event_type = "email_delivered"
     and attachment_type in ("doc", "docm", "xls", "xlsm")
     and attachment_macro_detected = true)

    -- Exploit of public-facing application
    or (event_type = "web_attack"
        and (attack_type in ("rce", "file_upload", "deserialization")
             or cvss_score > 9.0))

    -- RDP brute force success
    or (event_type = "authentication_success"
        and protocol = "rdp"
        and previous_failures > 10 in 1h)

    -- VPN/Remote access compromise
    or (event_type = "vpn_login"
        and (mm2country(src_ip) in ("CN", "RU", "KP", "IR")
             or impossible_travel = true))
  )

-- Stage 2: Malware Execution & Persistence
join edr.process_creation malware_exec
  on malware_exec.hostname = initial_compromise.hostname
  and malware_exec.eventdate > initial_compromise.eventdate
  and malware_exec.eventdate < initial_compromise.eventdate + 1h
where (
    weakhas(malware_exec.process_name, "powershell")
    or weakhas(malware_exec.process_name, "cmd")
    or weakhas(malware_exec.process_name, "wscript")
    or weakhas(malware_exec.process_name, "mshta")
  )
  and (
    weakhas(malware_exec.command_line, "IEX")
    or weakhas(malware_exec.command_line, "Invoke-WebRequest")
    or weakhas(malware_exec.command_line, "DownloadString")
    or weakhas(malware_exec.command_line, "DownloadFile")
    or weakhas(malware_exec.command_line, "-enc")
    or weakhas(malware_exec.command_line, "FromBase64String")
  )

-- Stage 3: Credential Dumping
join edr.process_creation cred_dump
  on cred_dump.hostname = initial_compromise.hostname
  and cred_dump.eventdate > malware_exec.eventdate
  and cred_dump.eventdate < malware_exec.eventdate + 30m
where (
    weakhas(cred_dump.process_name, "mimikatz")
    or (cred_dump.process_name = "lsass.exe" and cred_dump.parent_process != "wininit.exe")
    or weakhas(cred_dump.command_line, "sekurlsa::logonpasswords")
    or weakhas(cred_dump.command_line, "procdump")
       and weakhas(cred_dump.command_line, "lsass")
    or weakhas(cred_dump.file_access, "ntds.dit")
    or weakhas(cred_dump.file_access, "SAM")
  )

-- Stage 4: Lateral Movement
join network.authentication lateral_auth
  on lateral_auth.username = initial_compromise.compromised_user
  and lateral_auth.eventdate > cred_dump.eventdate
  and lateral_auth.eventdate < cred_dump.eventdate + 2h
  and lateral_auth.hostname != initial_compromise.patient_zero
where lateral_auth.protocol in ("smb", "wmi", "rdp", "psexec")
  and lateral_auth.result = "success"

-- Stage 5: Data Exfiltration (Double Extortion)
join network.connections exfil
  on exfil.src_hostname in (initial_compromise.patient_zero, lateral_auth.hostname)
  and exfil.eventdate > lateral_auth.eventdate
  and exfil.eventdate < lateral_auth.eventdate + 4h
where (
    exfil.dst_port in (443, 80, 22, 21)
    and exfil.bytes_sent > 1073741824  -- 1 GB
    and purpose(exfil.dst_ip) = "external"
    and mm2country(exfil.dst_ip) not in ("US", "CA", "GB", "DE", "FR")  -- Adjust for your country
  )

-- Stage 6: Backup/Recovery Deletion
join edr.process_creation backup_delete
  on backup_delete.hostname in (initial_compromise.patient_zero, lateral_auth.hostname)
  and backup_delete.eventdate > exfil.eventdate
  and backup_delete.eventdate < exfil.eventdate + 1h
where (
    (backup_delete.process_name = "vssadmin.exe"
     and weakhas(backup_delete.command_line, "delete shadows"))
    or (backup_delete.process_name = "wbadmin.exe"
        and weakhas(backup_delete.command_line, "delete"))
    or (backup_delete.process_name = "bcdedit.exe"
        and weakhas(backup_delete.command_line, "recoveryenabled no"))
    or weakhas(backup_delete.command_line, "wmic shadowcopy delete")
  )

-- Stage 7: Ransomware Encryption (Final Stage)
join edr.file_activity encryption
  on encryption.hostname in (initial_compromise.patient_zero, lateral_auth.hostname)
  and encryption.eventdate > backup_delete.eventdate
  and encryption.eventdate < backup_delete.eventdate + 30m
where encryption.action = "modify"
  and (
    encryption.files_modified_count > 50 in 5m
    or encryption.file_entropy > 7.5
    or encryption.file_extension in (".encrypted", ".locked", ".crypto", ".crypt")
    or weakhas(encryption.filename, "README")
    or weakhas(encryption.filename, "DECRYPT")
    or weakhas(encryption.filename, "HOW_TO_RECOVER")
  )

group by initial_compromise.patient_zero,
         initial_compromise.attacker_ip,
         initial_compromise.compromised_user
every 30m

select initial_compromise.compromise_time as attack_start
select initial_compromise.patient_zero
select initial_compromise.attacker_ip
select initial_compromise.compromised_user
select initial_compromise.initial_vector
select malware_exec.process_name as malware_process
select cred_dump.process_name as credential_tool
select lateral_auth.hostname as lateral_targets
select count(lateral_auth.hostname) as systems_compromised
select sum(exfil.bytes_sent) as data_exfiltrated_bytes
select encryption.eventdate as encryption_start_time
select datediff_minutes(initial_compromise.compromise_time, encryption.eventdate) as attack_duration_minutes
```

## Alert Configuration
- **Trigger**: Complete ransomware kill chain detected (all 7 stages)
- **Throttling**: No throttling - every instance requires immediate response
- **Severity**: Critical
- **Priority**: P0 (Emergency)
- **SOAR Integration**: Auto-trigger major incident response, isolate all affected systems, disable user accounts
- **Executive Notification**: Auto-notify CISO, CEO, legal team

## Recommended Actions

### IMMEDIATE (Within 5 Minutes)
1. **Declare Major Incident**: Activate incident response team and war room
2. **Isolate Patient Zero**: Network isolation at switch/firewall level
3. **Isolate All Lateral Movement Targets**: Quarantine all affected systems
4. **Disable Compromised User Accounts**: AD/IAM account suspension
5. **Block Attacker IP**: Perimeter firewall block
6. **Snapshot Systems**: Create forensic snapshots before termination
7. **Stop Running Backups**: Prevent backup of encrypted files
8. **Alert Stakeholders**: Executive leadership, legal, PR

### CRITICAL RESPONSE (5-30 Minutes)
9. **Activate Business Continuity Plan**: Failover to DR systems if needed
10. **Hunt for Additional Compromised Systems**: EDR threat hunting
11. **Check Domain Controllers**: Ensure DC integrity
12. **Block C2 Domains/IPs**: Network-wide blocking
13. **Preserve Evidence**: Memory dumps, disk images, network captures
14. **Contact Law Enforcement**: FBI, Secret Service, local authorities
15. **Engage Cyber Insurance**: Initiate insurance claim
16. **Identify Ransomware Variant**: Determine if decryptor available

## False Positive Considerations
- **EXTREMELY RARE**: This correlation requires all 7 stages - false positives are unlikely
- Legitimate IT administrative activities may trigger individual stages but not the full chain
- Penetration testing or red team exercises may trigger (coordinate with security team)
- DR testing or system migrations may cause some correlations

**Tuning Recommendations**:
- Whitelist approved penetration testing source IPs and accounts
- Exclude DR testing time windows
- Document planned red team exercises
- Verify each stage independently before dismissing as false positive
- **ASSUME BREACH** - investigate thoroughly even if single stage looks benign

## Enrichment Opportunities
- Ransomware variant identification (LockBit, BlackCat, Royal, Cl0p, Akira, etc.)
- Threat actor attribution (TTPs, IOCs, campaign correlation)
- Timeline visualization of full attack progression
- Affected systems and data inventory
- Backup status and integrity verification
- External data exfiltration destinations (who received stolen data?)
- Ransom note analysis
- Dark web monitoring (has data been published?)
- Similar historical attacks (is this a repeat?)

## Response Playbook

### Phase 1: Emergency Containment (0-15 Minutes)
**Objective**: Stop ransomware spread immediately

1. **Isolate All Affected Systems**:
   ```bash
   # Disable network adapter (run on each affected host)
   netsh interface set interface "Ethernet" admin=disable

   # Or network isolation via switch/firewall
   # VLAN isolation, ACL blocking, null routing
   ```

2. **Disable Compromised Accounts**:
   ```powershell
   # Active Directory
   Disable-ADAccount -Identity <username>

   # Revoke all sessions
   Get-ADUser <username> | Revoke-ADSession
   ```

3. **Block Attacker Infrastructure**:
   ```bash
   # Perimeter firewall
   firewall-cmd --add-rich-rule='rule family="ipv4" source address="<attacker-ip>" reject'

   # DNS sinkhole for C2 domains
   # WAF blocking
   ```

4. **Snapshot Systems**:
   ```bash
   # Create forensic snapshot before any changes
   # VMware
   vim-cmd vmsvc/snapshot.create <vmid> "Ransomware Incident" "Forensic snapshot"

   # AWS
   aws ec2 create-snapshot --volume-id <vol-id> --description "Ransomware incident"
   ```

5. **Stop Backup Systems**:
   ```bash
   # Prevent backup of encrypted files
   # Suspend Veeam/Backup Exec/etc.
   systemctl stop veeambackup

   # Verify backup integrity BEFORE suspending
   ```

### Phase 2: Scope Assessment (15 min - 2 hours)
**Objective**: Understand full extent of compromise

1. **Identify All Compromised Systems**:
   ```sql
   -- Query SIEM for all systems in lateral movement chain
   SELECT DISTINCT hostname
   FROM authentication_logs
   WHERE username = '<compromised-user>'
     AND timestamp > '<attack-start-time>'
   ```

2. **Map Attack Timeline**:
   ```
   T+0:00 - Initial phishing email delivered
   T+0:05 - Macro execution, malware download
   T+0:15 - Mimikatz credential dumping
   T+0:45 - Lateral movement to file server
   T+2:30 - Data exfiltration begins (500 GB)
   T+4:15 - Shadow copy deletion
   T+4:20 - Encryption starts
   ```

3. **Identify Ransomware Variant**:
   ```bash
   # Analyze ransom note
   cat README_DECRYPT.txt

   # Upload sample to ID Ransomware
   # https://id-ransomware.malwarehunterteam.com/

   # Check for known decryptors
   # https://www.nomoreransom.org/
   ```

4. **Assess Backup Integrity**:
   ```bash
   # Verify backups are not encrypted
   # Check backup age (are they recent?)
   # Test restore capability
   # Verify offline/immutable backups exist
   ```

5. **Data Exfiltration Analysis**:
   ```sql
   SELECT dst_ip, dst_domain, SUM(bytes_sent) as total_exfil
   FROM network_connections
   WHERE src_hostname IN ('<compromised-systems>')
     AND timestamp BETWEEN '<attack-start>' AND '<encryption-start>'
     AND dst_ip NOT IN (internal_networks)
   GROUP BY dst_ip, dst_domain
   ORDER BY total_exfil DESC
   ```

### Phase 3: Threat Hunting (2-8 hours)
**Objective**: Find additional compromised systems and persistence

1. **EDR Threat Hunting**:
   ```sql
   -- Hunt for additional malware instances
   process_name:("mimikatz", "cobalt strike", "metasploit")
   OR command_line:("Invoke-Mimikatz", "IEX", "DownloadString")

   -- Check for scheduled tasks (persistence)
   process_name:schtasks.exe AND command_line:"/create"

   -- Check for new services
   process_name:sc.exe AND command_line:"create"

   -- Check for registry autoruns
   registry_path:("Run", "RunOnce", "Startup")
   ```

2. **Domain Controller Analysis**:
   ```powershell
   # Check for rogue domain admins
   Get-ADGroupMember "Domain Admins" | Where-Object {$_.SID -notlike "*-500"}

   # Review recent AD changes
   Get-ADObject -Filter * -Properties whenChanged |
     Where-Object {$_.whenChanged -gt (Get-Date).AddHours(-24)}

   # Check for Golden Ticket indicators
   Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768,4769}
   ```

3. **File System Forensics**:
   ```bash
   # Find recently modified executables
   find / -type f -executable -mmin -1440

   # Find recently created/modified files
   find / -type f -mmin -60

   # Check for webshells
   find /var/www -name "*.php" -mtime -7 -exec grep -l "eval\|base64_decode\|system\|exec" {} \;
   ```

### Phase 4: Eradication (8-48 hours)
**Objective**: Remove all malware and attacker access

1. **Malware Removal**:
   ```bash
   # Kill malicious processes
   taskkill /F /IM <malware-process>

   # Delete malware files
   rm /path/to/malware

   # Remove persistence mechanisms
   schtasks /delete /tn <malicious-task>
   sc delete <malicious-service>
   ```

2. **Credential Reset**:
   ```powershell
   # Force password reset for all users
   Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true

   # Reset krbtgt account (Golden Ticket mitigation)
   # TWICE, 24 hours apart
   New-KrbtgtKeys.ps1 -

 -Force

   # Rotate all service account passwords
   # Rotate API keys, database passwords
   ```

3. **Patch Vulnerabilities**:
   ```bash
   # Apply security patches
   # Fix exploited vulnerabilities
   # Update EDR/AV signatures
   # Strengthen RDP/VPN configurations
   ```

4. **Rebuild Severely Compromised Systems**:
   ```bash
   # For patient zero and critical systems, rebuild from scratch
   # Restore from clean backup or fresh OS install
   # Do NOT just "clean" the system
   ```

### Phase 5: Recovery (2-14 days)
**Objective**: Restore operations securely

1. **Staged Recovery**:
   ```
   Day 1-2: Critical systems (DC, email, finance)
   Day 3-5: Production systems (databases, apps)
   Day 6-10: Workstations, file servers
   Day 11-14: Non-critical systems
   ```

2. **Restore from Backup**:
   ```bash
   # Verify backup cleanliness
   # Restore to isolated network first
   # Scan restored data for malware
   # Gradual return to production
   ```

3. **Enhanced Monitoring**:
   ```yaml
   # Increase logging verbosity
   # Deploy additional EDR sensors
   # Enhanced network monitoring
   # 24/7 SOC staffing
   ```

4. **User Communication**:
   ```
   - What happened (high-level)
   - What data was affected
   - Actions taken
   - Security improvements
   - What users should do
   ```

### Phase 6: Post-Incident (Ongoing)
**Objective**: Prevent recurrence

1. **Root Cause Analysis**:
   - How did initial compromise occur?
   - What security controls failed?
   - How can we prevent this in the future?

2. **Security Improvements**:
   - Deploy MFA for all remote access
   - Implement application whitelisting
   - Network segmentation
   - Privileged Access Management (PAM)
   - Email security enhancements
   - EDR on all endpoints
   - Immutable/offline backups
   - Security awareness training

3. **Policy Updates**:
   - Incident response plan
   - Backup and recovery procedures
   - Disaster recovery plans
   - Security policies

4. **Tabletop Exercises**:
   - Regular ransomware simulations
   - Test IR procedures
   - Practice backup restoration

## Investigation Steps

1. **Initial Access**: How did the attacker get in? (Phishing, RDP, VPN, exploit?)
2. **Execution Timeline**: Map every action from compromise to encryption
3. **Tools Used**: What malware, frameworks, utilities? (Cobalt Strike, Mimikatz, etc.)
4. **Lateral Movement**: Which systems, what credentials, what protocols?
5. **Data Exfiltration**: What data, where sent, how much?
6. **Encryption Scope**: How many files, which systems, what file types?
7. **Attacker Attribution**: TTPs, IOCs, ransomware family, known group?
8. **Business Impact**: Downtime, data loss, financial impact, regulatory?

## Ransomware Families & Characteristics

| Family | Characteristics | TTPs |
|--------|----------------|------|
| **LockBit 3.0** | Fast encryption, self-spreading, affiliate model | Double extortion, AD compromise |
| **BlackCat (ALPHV)** | Rust-based, cross-platform, customizable | Exfiltration before encryption, cloud-aware |
| **Royal** | No affiliates, targeted attacks | Direct communication, manual operations |
| **Cl0p** | Mass exploitation campaigns | Zero-day exploits, supply chain attacks |
| **Akira** | VPN/remote access focus | Credential abuse, minimal tooling |
| **BlackBasta** | Double extortion, fast | QakBot delivery, print bombing |
| **Play** | Targeted, stealthy | Long dwell time, thorough exfiltration |

## Decryption Options

1. **Restore from Backup** (BEST)
   - Clean, known-good backups
   - Test restore first
   - Verify no malware

2. **Free Decryptor** (IF AVAILABLE)
   - Check nomoreransom.org
   - Ransomware variant specific
   - Not always available

3. **Payment** (LAST RESORT)
   - No guarantee of decryption
   - Funds criminal operations
   - Regulatory/legal implications
   - Requires executive approval
   - Engage legal counsel

4. **Accept Data Loss**
   - If non-critical data
   - If backups unavailable
   - If payment not feasible

## Prevention Measures

### Technical Controls
- Multi-Factor Authentication (MFA) on all remote access
- Email security (anti-phishing, attachment scanning, sandbox)
- Endpoint Detection & Response (EDR) on all systems
- Network segmentation (VLANs, micro-segmentation)
- Privileged Access Management (PAM)
- Application whitelisting (AppLocker, Windows Defender Application Control)
- Patch management (priority on internet-facing systems)
- Disable PowerShell/macros where not needed
- Immutable backups (3-2-1 rule + offline/air-gapped)

### Administrative Controls
- Security awareness training (phishing simulations)
- Incident response plan (tested quarterly)
- Disaster recovery plan (tested annually)
- Third-party risk management
- Access reviews (quarterly)
- Least privilege principle
- Regular vulnerability assessments

### Detective Controls
- SIEM with advanced correlation (this use case!)
- 24/7 SOC monitoring
- Threat hunting program
- User and Entity Behavior Analytics (UEBA)
- Deception technology (honeypots, honey tokens)

## Business Continuity

**RTO (Recovery Time Objective)**: 24-72 hours for critical systems
**RPO (Recovery Point Objective)**: < 1 hour for critical data

**Critical Systems Priority**:
1. Domain Controllers
2. Email systems
3. Financial systems
4. Customer-facing applications
5. Employee productivity systems

## Legal & Compliance

**Notification Requirements**:
- Law enforcement (FBI, local)
- Cyber insurance provider
- Regulatory bodies (GDPR, HIPAA, PCI-DSS)
- Affected customers (data breach notification laws)
- Board of directors
- Media (if public company)

**Evidence Preservation**:
- Forensic images of affected systems
- Memory dumps
- Log files
- Network captures
- Ransom notes
- Communication with attackers
- Chain of custody documentation

## Cost Estimation

**Typical Ransomware Incident Costs**:
- Ransom payment: $100K - $10M+ (if paid)
- Business downtime: $500K - $50M+
- Incident response: $100K - $1M
- Legal fees: $50K - $500K
- Regulatory fines: $0 - $20M+
- Reputation damage: Incalculable
- **Total**: $1M - $100M+ for major organizations

## References
- MITRE ATT&CK: Ransomware Tactics
- NIST Cybersecurity Framework
- CISA Ransomware Guide
- SANS Ransomware Response Checklist
- Veeam Ransomware Trends Report

## Notes
- This correlation rule is extremely high-fidelity due to requiring all 7 stages
- Every alert requires immediate investigation - assume breach
- Speed of response is critical - every hour matters
- Backups are the #1 defense against ransomware
- Do NOT pay ransom without exhausting all other options
- Ransomware is "when not if" - preparation is everything
- Regular testing of backups and IR procedures is essential
- Consider ransomware as a symptom of broader security gaps
