# WAF - Multiple OWASP Top 10 Violations

## Severity
**HIGH**

## Description
Detects when a source generates multiple different OWASP Top 10 attack patterns, indicating active exploitation attempts or vulnerability scanning.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Discovery (TA0007)
- **Technique**: Exploit Public-Facing Application (T1190), Active Scanning (T1595)
- **OWASP**: Multiple OWASP Top 10 categories

## DEVO Query

```sql
from waf.logs
select eventdate
select srcip
select http_host
select countdistinct(attack_type) as unique_attack_types
select collectdistinct(attack_type) as attack_types_list
select count() as total_violations
select countdistinct(uri) as unique_uris
select geolocation.country
select http_user_agent
select waf_action
select mm2country(srcip) as src_country
where `in`("sql-injection", "xss", "rce", "lfi", "rfi", "xxe", "ssrf", "command-injection", "path-traversal", "ldap-injection", attack_type)
  or owasp_category is not null

every 30m
having unique_attack_types >= 3 or total_violations >= 20
```

## Alert Configuration
- **Trigger**: 3+ different attack types OR 20+ total violations in 30 minutes
- **Throttling**: 1 alert per srcip per 2 hours
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Block source IP immediately
2. Verify WAF is blocking attacks
3. Review all violation types
4. Check for any successful exploits
5. Identify targeted application/URLs
6. Review web application logs for breaches
7. Assess web application vulnerabilities
8. Schedule vulnerability scan if not recent
9. Patch identified vulnerabilities
10. Consider geo-blocking if applicable

## False Positive Considerations
- Authorized vulnerability scans
- Security testing
- Penetration testing
- Application security assessments
- Scanner misconfigurations

**Tuning Recommendations**:
- Whitelist approved security scanner IPs
- Exclude penetration testing activities
- Require pre-approval for security scans
- Adjust thresholds for web application traffic volume
- Filter false WAF positives

## Enrichment Opportunities
- Check source IP reputation
- Review threat intelligence
- Correlate with vulnerability scan schedules
- Check if IP is known scanner
- Review targeted application's patch status
- Analyze attack sophistication
- Check for custom exploit patterns

## OWASP Top 10 Attack Types

1. **A01: Broken Access Control**
   - Path traversal (../)
   - Forced browsing
   - Missing authorization checks

2. **A02: Cryptographic Failures**
   - Sensitive data exposure
   - Weak encryption

3. **A03: Injection**
   - SQL Injection
   - Command Injection
   - LDAP Injection
   - XPath Injection

4. **A04: Insecure Design**
   - Business logic flaws
   - Missing security controls

5. **A05: Security Misconfiguration**
   - Default credentials
   - Unnecessary features enabled

6. **A06: Vulnerable Components**
   - Using known vulnerable libraries
   - Outdated frameworks

7. **A07: Authentication Failures**
   - Credential stuffing
   - Brute force

8. **A08: Software and Data Integrity**
   - Insecure deserialization
   - CI/CD pipeline attacks

9. **A09: Logging Failures**
   - Insufficient logging
   - Missing monitoring

10. **A10: Server-Side Request Forgery (SSRF)**
    - Internal resource access
    - Cloud metadata exploitation

## Response Playbook
1. **Immediate Triage**:
   - How many different attack types?
   - Are attacks being blocked?
   - Any successful exploitation indicators?
   - Is this automated scanning or targeted?
2. **Block Source**:
   - IP blocking at WAF/firewall
   - Geo-blocking if appropriate
   - Rate limiting
3. **Application Assessment**:
   - Review WAF logs for patterns
   - Check application logs for anomalies
   - Verify no successful exploits
   - Test for vulnerabilities
4. **If Authorized Testing**:
   - Verify with security/IT teams
   - Confirm proper approval
   - Document for audit
5. **If Malicious**:
   - Threat intelligence submission
   - Hunt for similar IPs
   - Review historical access
   - Assess damage
   - Patch vulnerabilities

## Investigation Steps
- Map all attack types attempted
- Timeline of violation attempts
- Identify most frequently targeted URIs
- Analyze attack payload sophistication
- Check for exploit framework signatures
- Review user agent for scanner tools
- Assess geographic origin
- Check for distributed attack (multiple IPs)

## Attack Pattern Analysis

**Automated Scanner Indicators**:
- Rapid sequential requests
- Systematic URI enumeration
- Known scanner user agents (Nikto, SQLMap, etc.)
- Predictable attack patterns
- High volume, low sophistication

**Targeted Attack Indicators**:
- Focused on specific functionality
- Custom payloads
- Slower, deliberate attempts
- Evasion techniques
- Polymorphic patterns

## Common Exploit Tools to Detect
- SQLMap (SQL injection)
- Burp Suite (various)
- OWASP ZAP (various)
- Nikto (scanner)
- Acunetix (scanner)
- Nessus (scanner)
- Metasploit (exploitation)
- Havij (SQL injection)

## WAF Effectiveness Check
Verify WAF is properly:
- Detecting attacks
- Blocking malicious requests
- Logging all violations
- Not allowing bypasses
- Properly configured
- Updated signatures

## Application Security Actions
1. Emergency patching if critical
2. Virtual patching via WAF
3. Vulnerability assessment
4. Code review for identified issues
5. Security testing
6. Implement input validation
7. Update security headers
8. Review authentication/authorization

## Enhanced Detection
```sql
-- Detect WAF bypass attempts
from waf.logs
where action = "allow"
  and attack_type is not null
select
  srcip,
  attack_type,
  uri,
  payload,
  count() as bypass_attempts
group by srcip, attack_type
```

## Geo-Blocking Considerations
If attacks from specific regions:
- No business presence in region
- High volume from region
- Known attack origin
- Compliance requirements
- Consider blocking at firewall

## Prevention Measures
- Regular vulnerability scanning
- Security code reviews
- WAF with updated rules
- Input validation
- Output encoding
- Prepared statements (SQL)
- Least privilege
- Security headers
- Rate limiting
- IP reputation blocking

## Reporting Metrics
- Top attacking IPs
- Most targeted applications
- Attack type distribution
- Block effectiveness
- Trends over time
- Geographic distribution

## Compliance Impact
- PCI-DSS: Web application protection required
- Document attack attempts
- May require vendor notification
- Audit trail maintenance

## Notes
- Multiple attack types indicate serious threat
- Automated scanning is common
- Even blocked attacks warrant investigation
- Pattern recognition important
- May precede successful breach
