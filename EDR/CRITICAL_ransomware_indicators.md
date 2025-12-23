# EDR - Ransomware Indicators Detected

## Severity
**CRITICAL**

## Description
Detects ransomware activity based on behavioral indicators such as rapid file encryption, mass file modifications, and ransom note creation.

## MITRE ATT&CK
- **Tactic**: Impact (TA0040)
- **Technique**: Data Encrypted for Impact (T1486), Inhibit System Recovery (T1490), Defacement (T1491)

## DEVO Query

```sql
from edr.events, edr.file_activity
where (event_type = "file_modification"
  and (file_extension_change = true
    or file_entropy > 7.5
    or filename like "%.encrypted"
    or filename like "%.locked"
    or filename like "%.crypto"
    or filename like "%.crypt%"
    or filename like "%README%"
    or filename like "%DECRYPT%"
    or filename like "%HOW_TO_RECOVER%"))
  or (process_name in ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe")
    and command_line like "%delete%shadow%")
  or (command_line like "%cipher%/w%"
    or command_line like "%vssadmin%delete%shadows%all%")
select
  eventdate,
  hostname,
  username,
  process_name,
  parent_process,
  command_line,
  file_path,
  file_extension,
  count(file_path) as files_modified,
  countdistinct(file_extension) as unique_extensions,
  avg(file_entropy) as avg_entropy
group by hostname, process_name
every 5m
having files_modified > 50 or unique_extensions > 10
```

## Alert Configuration
- **Trigger**: > 50 files modified OR > 10 file extensions changed in 5 minutes
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Isolate affected systems from network
2. Do NOT shut down systems (may trigger encryption completion)
3. Suspend backup processes to prevent encrypted backup
4. Identify ransomware variant
5. Block C2 domains/IPs
6. Kill malicious processes
7. Check for lateral movement
8. Assess scope of infection
9. Contact ransomware response team
10. Preserve forensic evidence
11. Do NOT pay ransom without executive approval
12. Engage legal team
13. Activate business continuity plan

## False Positive Considerations
- Legitimate bulk file encryption tools
- Backup/compression software
- Antivirus full system scans
- Software updates/installations
- Data migration activities

**Tuning Recommendations**:
- Whitelist approved encryption tools
- Exclude backup processes
- Adjust file count threshold by system type
- Filter system maintenance windows
- Baseline normal entropy patterns

## Enrichment Opportunities
- Identify ransomware family
- Check ransom note content
- Review execution timeline
- Correlate with email security (delivery method)
- Check network traffic for C2
- Review process tree
- Analyze persistence mechanisms
- Check for data exfiltration before encryption

## Response Playbook
1. **Immediate Containment** (0-15 minutes):
   - Network isolation (disable network adapter)
   - Do NOT power off
   - Stop running backups
   - Alert security team
   - Activate incident response

2. **Assessment** (15-60 minutes):
   - Identify ransomware variant
   - Determine patient zero
   - Map scope of infection
   - Check if decryptor available
   - Assess backup integrity
   - Document timeline
   - Preserve evidence

3. **Containment** (1-4 hours):
   - Isolate all infected systems
   - Block C2 infrastructure
   - Hunt for additional infections
   - Disable compromised accounts
   - Check domain controllers
   - Segment network
   - Block lateral movement paths

4. **Eradication** (4-24 hours):
   - Remove ransomware
   - Clear persistence
   - Patch vulnerabilities
   - Reset credentials
   - Rebuild if necessary
   - Verify backups

5. **Recovery** (1-7 days):
   - Restore from clean backups
   - Use decryptor if available
   - Rebuild critical systems
   - Staged return to production
   - Enhanced monitoring
   - User communication

6. **Lessons Learned**:
   - Root cause analysis
   - Update security controls
   - Training and awareness
   - Improve backups
   - Tabletop exercises

## Investigation Steps
- Identify initial access vector
- Map infection timeline
- List all affected systems
- Identify ransomware family
- Check for available decryptors
- Review backup status and integrity
- Analyze ransom note
- Document file encryption patterns
- Review network logs for lateral movement
- Check for data exfiltration

## Ransomware Indicators

**File System**:
- Mass file renaming
- Extension changes (.encrypted, .locked, etc.)
- High file entropy (> 7.5 = encrypted)
- Ransom notes (README.txt, HOW_TO_DECRYPT.html)
- Deleted shadow copies

**Process Behavior**:
- vssadmin.exe delete shadows
- bcdedit /set {default} recoveryenabled no
- wmic shadowcopy delete
- cipher /w (secure delete)
- Rapid file access patterns
- Network share enumeration

**Network**:
- C2 communications
- SMB lateral movement
- RDP brute force
- Unusual outbound connections

**Registry**:
- Boot configuration changes
- Wallpaper changes
- Autorun modifications

## Common Ransomware Families
- **LockBit**: Fast encryption, affiliate model
- **BlackCat/ALPHV**: Rust-based, cross-platform
- **Royal**: Targeted attacks, no affiliates
- **Cl0p**: Mass exploitation campaigns
- **Akira**: VPN exploitation
- **BlackBasta**: Double extortion
- **REvil/Sodinokibi**: Defunct but variants exist

## Ransomware Kill Chain
1. **Initial Access**: Phishing, RDP, vulnerability
2. **Execution**: Malicious document, exploit
3. **Persistence**: Registry, scheduled tasks
4. **Privilege Escalation**: Exploit, credential theft
5. **Defense Evasion**: Disable AV, delete logs
6. **Credential Access**: Mimikatz, LSASS dump
7. **Discovery**: Network/domain enumeration
8. **Lateral Movement**: PsExec, WMI, RDP
9. **Collection**: Identify high-value data
10. **Exfiltration**: Steal data (double extortion)
11. **Impact**: Delete backups, encrypt files

## Initial Access Vectors
- Phishing emails
- RDP brute force
- VPN vulnerabilities
- Unpatched systems
- Supply chain compromise
- Compromised credentials
- Drive-by downloads

## Decryption Options
1. **Backups**: Restore from clean backups (best option)
2. **Free Decryptors**: Check nomoreransom.org
3. **Ransomware Keys**: If keys leaked/released
4. **Payment**: Last resort, not guaranteed
5. **Data Loss**: Accept loss if not critical

## Ransom Payment Decision
Only consider if:
- No backups available
- Critical business data
- Downtime cost exceeds ransom
- Executive approval
- Legal counsel consulted
- Law enforcement notified
- Understand no guarantee

## Prevention Measures
- Regular offline backups (3-2-1 rule)
- Patch management
- Email security (anti-phishing)
- Endpoint protection (EDR)
- Network segmentation
- MFA on all remote access
- Privileged access management
- User awareness training
- Application whitelisting
- Disable unnecessary services (RDP, SMB)
- Immutable backups

## Forensic Artifacts
- Process execution logs
- File modification timeline
- Network connection logs
- Ransom note samples
- Encrypted file samples
- Memory dumps
- Registry changes
- Event logs (if not deleted)

## Business Impact Assessment
- Number of systems affected
- Critical systems impacted
- Data loss estimation
- Recovery time objective (RTO)
- Recovery point objective (RPO)
- Financial impact
- Regulatory reporting requirements
- Reputation damage

## Legal/Compliance
- Notify law enforcement (FBI, local)
- GDPR/data breach notification
- Regulatory reporting (HIPAA, PCI, etc.)
- Cyber insurance claim
- Legal counsel involvement
- Document all decisions
- Preserve evidence

## Communication Plan
- Executive leadership
- IT staff
- Affected users
- Customers (if data compromised)
- Partners/vendors
- Regulators
- Law enforcement
- Media (if public disclosure needed)

## Notes
- Ransomware is a "when not if" threat
- Backups are critical defense
- Speed of response matters
- Isolation prevents spread
- Do NOT pay without exhausting options
- Recovery can take weeks
- Prevention cheaper than recovery
