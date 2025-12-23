# EDR - Credential Dumping Detected

## Severity
**HIGH**

## Description
Detects attempts to dump credentials from memory (LSASS), registry (SAM), or domain controllers, commonly used for lateral movement and privilege escalation.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006)
- **Technique**: OS Credential Dumping (T1003), LSASS Memory (T1003.001), Security Account Manager (T1003.002), NTDS (T1003.003)

## DEVO Query

```sql
from edr.events
select eventdate
select hostname
select username
select process_name
select parent_process
select command_line
select target_process
select file_path
select registry_path
select process_hash
where (`in`("mimikatz.exe", "procdump.exe", "pwdump.exe", "gsecdump.exe", process_name)
  or (weakhas(process_name, "rundll32.exe") and command_line like "%comsvcs.dll%MiniDump%")
  or (weakhas(target_process, "lsass.exe") and `in`("process_access", "memory_read", event_type))
  or (file_path like "%\\ntds.dit" and weakhas(event_type, "file_access"))
  or (weakhas(registry_path, "SAM\\SAM\\Domains") and weakhas(event_type, "registry_access"))
  or weakhas(command_line, "sekurlsa::logonpasswords")
  or weakhas(command_line, "privilege::debug")
  or weakhas(command_line, "lsadump::sam")
  or weakhas(command_line, "lsadump::secrets"))

group by hostname, username, process_name
```

## Alert Configuration
- **Trigger**: Any credential dumping indicator
- **Throttling**: Real-time, no throttling
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Isolate affected endpoint immediately
2. Identify compromised accounts
3. Reset credentials for affected users
4. Check for lateral movement
5. Review recent activities from affected account
6. Block attacker tools/hashes
7. Hunt for similar activity across environment
8. Review domain controller access
9. Enable Credential Guard if not present
10. Escalate to incident response team

## False Positive Considerations
- Legitimate administrative tools
- Security testing (approved)
- Password managers
- Backup software
- System diagnostics

**Tuning Recommendations**:
- Whitelist approved security tools
- Exclude authorized penetration testing
- Filter approved administrative processes
- Low false positive rate for LSASS access

## Enrichment Opportunities
- Check user's privilege level
- Review recent authentication history
- Correlate with lateral movement
- Check for remote connections to host
- Review parent process legitimacy
- Analyze file hash reputation
- Check for known attack tool signatures

## Response Playbook
1. **Immediate Actions**:
   - Isolate endpoint
   - Kill suspicious process
   - Alert security team
2. **Assessment**:
   - What credentials were accessed?
   - Which tool was used?
   - User context of attack
   - Privilege level
3. **Containment**:
   - Reset all potentially compromised credentials
   - Disable affected accounts temporarily
   - Block lateral movement paths
   - Hunt for attacker presence
4. **Investigation**:
   - How did attacker get initial access?
   - What credentials were dumped?
   - Check for lateral movement
   - Review domain admin access
   - Analyze attack timeline
5. **Eradication**:
   - Remove attacker tools
   - Clear persistence mechanisms
   - Patch vulnerabilities
   - Harden systems
6. **Recovery**:
   - Restore from clean state
   - Re-enable accounts with new credentials
   - Enhanced monitoring
   - Reset Kerberos keys if domain-wide

## Investigation Steps
- Identify credential dumping technique used
- Review process execution timeline
- Check parent process chain
- Analyze command line parameters
- Review accounts logged into system
- Check for remote connections
- Verify legitimate tool vs. attack tool
- Hunt for attacker tools across environment
- Review recent privilege escalations

## Credential Dumping Techniques

**LSASS Memory Dumping**:
- Mimikatz
- ProcDump
- comsvcs.dll MiniDump
- Task Manager (manual)
- PowerSploit
- Custom dumpers

**SAM Database**:
- Registry hive export
- Volume Shadow Copy
- Offline access
- Mimikatz lsadump::sam

**NTDS.dit (Domain)**:
- DCSync attack
- NTDSUtil
- Volume Shadow Copy
- Mimikatz lsadump::dcsync

**Other Methods**:
- LSA Secrets
- Cached credentials
- Credential Manager
- Web browser passwords

## Common Tools

**Mimikatz**:
- sekurlsa::logonpasswords
- lsadump::sam
- lsadump::secrets
- kerberos::golden
- DCSync

**Native Tools Abused**:
- procdump.exe -ma lsass.exe
- rundll32 comsvcs.dll MiniDump
- taskmgr.exe (manual dump)
- ntdsutil.exe

**PowerShell**:
- Invoke-Mimikatz
- Out-Minidump
- Get-GPPPassword

## Detection Patterns

**Process Access**:
```
GrantedAccess: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
TargetImage: C:\\Windows\\System32\\lsass.exe
```

**File Access**:
```
C:\\Windows\\NTDS\\ntds.dit
C:\\Windows\\System32\\config\\SAM
```

**Command Line**:
```
procdump -ma lsass.exe lsass.dmp
rundll32.exe comsvcs.dll, MiniDump
reg save HKLM\\SAM sam.hive
```

## Indicators of Compromise
- Unusual LSASS access
- Memory dump files (*.dmp)
- Known tool hashes
- Suspicious process chains
- Registry SAM access
- NTDS.dit copying
- DCSync network traffic
- Mimikatz artifacts

## Lateral Movement Indicators
After credential dumping, look for:
- New remote logins
- PsExec usage
- WMI remote execution
- RDP sessions
- SMB connections
- Pass-the-hash attacks
- Golden ticket usage

## Prevention Measures
- Credential Guard (Windows 10+)
- Protected Process Light for LSASS
- Restrict local admin rights
- Disable WDigest authentication
- LSA Protection
- Monitor LSASS access
- Application whitelisting
- Endpoint protection
- Privileged Access Workstations (PAW)
- Just-in-time admin access

## Domain-Wide Credential Reset
If domain compromise suspected:
1. Reset krbtgt account (twice)
2. Reset all service account passwords
3. Reset all user passwords
4. Reset computer accounts
5. Review all admin accounts
6. Enable multi-factor authentication
7. Review domain trust relationships

## Forensic Artifacts
- Process creation logs (Event ID 4688)
- LSASS access events (Sysmon Event ID 10)
- File creation logs
- Registry access logs
- Network connections
- Memory dumps for analysis
- Command history

## Enhanced Detection
```sql
-- Detect LSASS memory access
from edr.events
where target_process = "lsass.exe"
  and event_type = "process_access"
  and granted_access in ("0x1410", "0x1FFFFF", "0x1010")
  and process_name not in ("svchost.exe", "wmiprvse.exe", "csrss.exe")
```

## Compliance Impact
- Unauthorized credential access
- Potential data breach
- Requires incident reporting
- Audit logging requirements

## Notes
- Credential dumping indicates active attack
- Often precedes lateral movement
- Domain admin compromise is critical
- Requires domain-wide response
- Prevention is key (Credential Guard)
- Assume credentials compromised
