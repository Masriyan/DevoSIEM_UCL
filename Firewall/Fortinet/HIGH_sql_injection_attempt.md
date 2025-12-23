# Fortinet - SQL Injection Attempt

## Severity
**HIGH**

## Description
Detects SQL injection attack attempts identified by FortiGuard IPS/WAF signatures targeting web applications.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001)
- **Technique**: Exploit Public-Facing Application (T1190)
- **OWASP**: A03:2021 - Injection

## DEVO Query

```sql
from firewall.fortinet.ips
select eventdate
select srcaddr
select dstaddr
select dstport
select proto
select attack_name
select attack_id
select severity
select action
select url
select http_method
select http_host
select msg
select mm2country(srcaddr) as src_country
select mm2country(dstaddr) as dst_country
select count() as attempt_count
where (weakhas(attack_name, "SQL.Injection")
  or weakhas(attack_name, "SQLi")
  or weakhas(signature_subclass, "sql-injection"))
  and `in`("detected", "blocked", "dropped", action)
group by srcaddr, dstaddr, attack_name, url
having attempt_count >= 1
```

## Alert Configuration
- **Trigger**: Any SQL injection attempt
- **Throttling**: 1 alert per srcip+dstip per 20 minutes
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Identify targeted web application
2. Review if injection attempt was successful
3. Check application logs for unauthorized database queries
4. Verify web application firewall is blocking attacks
5. Review source IP reputation and geo-location
6. Check for successful logins from same source
7. Conduct code review of affected application
8. Implement parameterized queries if not present
9. Consider blocking attacking IP
10. Review database audit logs

## False Positive Considerations
- Legitimate queries with SQL keywords in URLs
- Security testing by authorized teams
- WAF learning mode
- API calls with complex parameters

**Tuning Recommendations**:
- Whitelist approved security testing IPs
- Exclude specific URLs that trigger false positives
- Adjust sensitivity for specific applications
- Create exceptions for API endpoints with complex queries

## Enrichment Opportunities
- Correlate with web application logs
- Check against vulnerability scan results
- Review SSL certificate of target
- Verify application version and known vulnerabilities
- Cross-reference with threat intelligence

## Common SQL Injection Patterns
- Union-based: `' UNION SELECT`
- Boolean-based: `' OR '1'='1`
- Time-based: `'; WAITFOR DELAY`
- Error-based: `' AND 1=CONVERT(int,@@version)--`
- Stacked queries: `'; DROP TABLE users--`

## Response Playbook
1. Verify attack was blocked
2. Review application code for SQL injection vulnerability
3. Check database logs for suspicious queries
4. Scan application with web vulnerability scanner
5. Implement input validation and sanitization
6. Deploy/tune WAF rules
7. Apply security patches if available
8. Consider blocking attacking source network
9. Monitor for continued attempts

## Vulnerable Application Indicators
- Reflected SQL errors in HTTP responses
- Timing differences in responses
- Different responses for true/false conditions
- Database version disclosure

## Prevention Measures
- Use parameterized queries/prepared statements
- Implement input validation
- Apply principle of least privilege for database accounts
- Use ORM frameworks
- Enable WAF with updated rulesets
- Regular security testing

## Notes
- Even blocked attempts warrant investigation
- Successful SQLi can lead to full database compromise
- May be automated attack or targeted
- Review all applications on same server
