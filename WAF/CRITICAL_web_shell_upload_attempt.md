# WAF - Web Shell Upload Attempt

## Severity
**CRITICAL**

## Description
Detects attempts to upload web shells to web applications, which would allow attackers persistent remote access and control of the web server.

## MITRE ATT&CK
- **Tactic**: Persistence (TA0003), Initial Access (TA0001)
- **Technique**: Server Software Component: Web Shell (T1505.003)
- **OWASP**: A01:2021 - Broken Access Control, A03:2021 - Injection

## DEVO Query

```sql
from waf.logs
where (filename like "%.php%"
    or filename like "%.asp%"
    or filename like "%.aspx%"
    or filename like "%.jsp%"
    or filename like "%.jspx%")
  and (content like "%eval(%"
    or content like "%base64_decode%"
    or content like "%system(%"
    or content like "%exec(%"
    or content like "%shell_exec%"
    or content like "%passthru%"
    or content like "%cmd.exe%"
    or content like "%powershell%"
    or content like "%ProcessStartInfo%"
    or content like "%Runtime.getRuntime%")
  and http_method = "POST"
  and uri like "%upload%"
select
  eventdate,
  srcip,
  dstip,
  http_host,
  uri,
  filename,
  file_hash,
  http_method,
  http_user_agent,
  waf_action,
  threat_score,
  geolocation
group by srcip, filename, uri
```

## Alert Configuration
- **Trigger**: Any web shell upload attempt
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Verify WAF blocked the upload
2. Check web server for successful uploads
3. Scan upload directories for suspicious files
4. Review web application logs
5. Block source IP immediately
6. Check for other upload attempts from same source
7. Review file upload functionality
8. Conduct web server compromise assessment
9. Patch vulnerable upload functionality
10. Hunt for existing web shells
11. Review all file uploads in last 30 days

## False Positive Considerations
- Legitimate PHP/ASP file uploads (rare)
- Developer testing
- Security scanning tools
- Code deployment processes

**Tuning Recommendations**:
- Whitelist approved deployment IPs
- Exclude security scanning activities
- Very low false positive rate for web shells
- Focus on eval, exec, system commands in uploads

## Enrichment Opportunities
- Check source IP reputation
- Review file hash in VirusTotal
- Analyze file content
- Check for successful uploads
- Review historical activity from IP
- Correlate with vulnerability scans
- Check web server logs

## Response Playbook
1. **Immediate Verification**:
   - Confirm WAF blocked upload
   - Check if file reached server
   - Verify no bypass occurred
2. **Web Server Assessment**:
   - Scan upload directories
   - Check for recently modified files
   - Review web server access logs
   - Look for suspicious requests
   - Check for backdoor indicators
3. **If Web Shell Found**:
   - Full incident response protocol
   - Isolate web server
   - Capture forensic image
   - Remove web shell
   - Identify entry point
   - Patch vulnerability
   - Hunt for other shells
   - Review for data exfiltration
4. **Containment**:
   - Block attacking IP
   - Restrict file upload functionality
   - Enable enhanced logging
   - Deploy additional WAF rules
5. **Recovery**:
   - Patch vulnerable code
   - Harden file upload
   - Update WAF rules
   - Monitor for reinfection

## Investigation Steps
- Analyze uploaded file content
- Review HTTP POST parameters
- Check for obfuscation techniques
- Examine file headers
- Review filename patterns
- Check upload directory permissions
- Analyze web server configurations
- Review application code for vulnerability

## Common Web Shell Indicators

**Filename Patterns**:
- c99.php, r57.php, shell.php
- cmd.asp, cmdasp.asp
- jsp-reverse.jsp
- Random names: a.php, 1.aspx, test.jsp
- Image files with script extensions: logo.php.jpg

**Content Patterns**:
- eval($_POST['cmd'])
- base64_decode
- system($cmd)
- exec($_REQUEST)
- passthru()
- Runtime.getRuntime().exec()
- WScript.Shell

**Behavioral Indicators**:
- Execute system commands
- File browsing capabilities
- Database access
- Network scanning
- Password cracking
- Privilege escalation

## Web Shell Types
1. **Command Execution**: Run OS commands
2. **File Management**: Upload/download/edit files
3. **Database Access**: Query databases
4. **Network Scanning**: Scan internal network
5. **Backdoor**: Persistent remote access
6. **Multi-functional**: Comprehensive control panels

## File Upload Vulnerabilities
- No file type validation
- Client-side validation only
- Insufficient MIME type checking
- Double extension bypass (.php.jpg)
- Null byte injection (.php%00.jpg)
- Case sensitivity bypass (.PhP)
- Content-Type header manipulation
- Zip file upload with traversal

## Web Shell Detection on Server
```bash
# Find recently modified PHP files
find /var/www -name "*.php" -mtime -7 -type f

# Search for suspicious functions
grep -r "eval(" /var/www/
grep -r "base64_decode" /var/www/
grep -r "system(" /var/www/

# Check for unusual file permissions
find /var/www -perm 777 -type f

# Monitor web server logs
grep "POST" /var/log/apache2/access.log | grep "upload"
```

## WAF Rules to Implement
- Block files with double extensions
- Validate MIME types
- Check file content signatures
- Block suspicious functions in uploads
- Rate limit file uploads
- Restrict upload file sizes
- Validate file extensions
- Scan uploaded files

## Application Hardening
- Whitelist allowed file types
- Validate file content, not just extension
- Store uploads outside webroot
- Rename uploaded files
- Disable script execution in upload directories
- Implement virus scanning
- Use Content Security Policy
- Principle of least privilege

## Incident Indicators
If web shell was successfully uploaded:
- Unusual outbound connections
- Processes spawned by web server
- Abnormal CPU/memory usage
- New user accounts created
- Scheduled tasks/cron jobs
- Modified system files
- Data exfiltration
- Lateral movement attempts

## Forensic Artifacts
- Web server access logs
- Application logs
- File system timeline
- Process execution logs
- Network connection logs
- IDS/IPS alerts
- WAF logs
- Firewall logs

## Prevention Measures
- Secure file upload implementation
- WAF with upload inspection
- Application security testing
- Code review for upload functions
- Regular security scanning
- Least privilege file permissions
- Disable unnecessary upload functionality
- Input validation
- Anti-virus on web servers

## Legal/Compliance Impact
- PCI-DSS: Web application security
- May constitute a breach
- Requires investigation and reporting
- Document all evidence

## Notes
- Web shells are extremely dangerous
- Provide full server compromise
- Often used for data exfiltration
- Persistent threat if not removed
- Priority investigation required
- Assume breach if upload successful
