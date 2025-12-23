# Threat Intelligence - Access to Newly Registered Domains

## Severity
**MEDIUM**

## Description
Detects access to recently registered domains (< 30 days old), which are commonly used in phishing campaigns, malware distribution, and C2 infrastructure.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Command and Control (TA0011)
- **Technique**: Phishing (T1566), Drive-by Compromise (T1189), Application Layer Protocol (T1071)

## DEVO Query

```sql
from proxy.logs, dns.logs
select eventdate
select user
select srcaddr
select domain
select url
select http_status
select mm2country(srcaddr) as src_country
select count() as access_count
where not `in`(select domain from approved_domains, domain)
  and (domain_age <= 30
    or `in`(select domain from threatintel.newly_registered, domain))
group by user, domain, srcaddr
every 1h
having access_count >= 1
```

## Alert Configuration
- **Trigger**: Access to domain registered within last 30 days
- **Throttling**: 1 alert per user+domain per 4 hours
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Review domain registration details
2. Check domain reputation across sources
3. Verify legitimate business need for access
4. Review URL content (if safe)
5. Check for phishing indicators
6. Scan for malware if file downloaded
7. Review user's other web activity
8. Check email for related phishing attempts
9. Block domain if malicious
10. User awareness if phishing attempt

## False Positive Considerations
- Legitimate new websites
- New vendor/partner domains
- Marketing campaigns
- Newly launched cloud services
- Website migrations
- CDN subdomains
- Legitimate startups

**Tuning Recommendations**:
- Whitelist known legitimate new domains
- Exclude major cloud providers (AWS, Azure, GCP)
- Filter CDN and infrastructure domains
- Adjust age threshold (30, 60, 90 days)
- Combine with other suspicious indicators
- Exclude internal company domain registrations

## Enrichment Opportunities
- WHOIS lookup for registration details
- Check domain reputation (VirusTotal, etc.)
- SSL certificate analysis
- Passive DNS history
- Website content analysis
- Similar domain search (typosquatting)
- Check registrar reputation
- Review hosting provider
- Analyze DNS records

## Response Playbook
1. **Domain Analysis**:
   - Registration date and age
   - Registrar and hosting provider
   - Registrant details (if available)
   - SSL certificate age and validity
   - DNS configuration
   - Similar domains (typosquatting?)

2. **Content Review**:
   - Website screenshot (safe sandbox)
   - Page content analysis
   - Forms requesting credentials?
   - Malware hosting indicators
   - Brand impersonation?
   - Grammatical errors?

3. **User Context**:
   - How did user access? (email link, direct, search)
   - Business justification?
   - Data entered on site?
   - Files downloaded?
   - Credentials entered?

4. **Risk Assessment**:
   - Domain appears malicious? (Block)
   - Phishing attempt? (User training, block)
   - Legitimate but new? (Monitor, document)
   - Unclear? (Research further)

5. **Action Decision**:
   - **Malicious**: Block, scan user system, credential reset
   - **Suspicious**: Enhanced monitoring, user notification
   - **Legitimate**: Whitelist, document
   - **Unclear**: Continue monitoring, gather more data

## Investigation Steps
- Review complete WHOIS information
- Check domain on VirusTotal, URLhaus, PhishTank
- Analyze SSL certificate details
- Review website screenshots
- Check for look-alike domains
- Verify business legitimacy
- Review user's email for related messages
- Check if multiple users accessed
- Analyze HTTP response codes
- Review website technologies used

## Newly Registered Domain Risks

**Phishing Campaigns**:
- Brand impersonation
- Login page clones
- Urgent action requests
- Similar to legitimate domains
- Free SSL certificates
- Generic content

**Malware Distribution**:
- Exploit kits
- Drive-by downloads
- Fake software updates
- Trojanized applications
- Malicious documents

**C2 Infrastructure**:
- Botnet communication
- RAT callbacks
- Data exfiltration
- Command execution
- Ransomware C2

**Scams**:
- Tech support scams
- Gift card fraud
- Fake services
- Investment schemes

## Domain Age Thresholds

- **< 7 days**: Very high risk, likely malicious
- **7-30 days**: High risk, common for phishing
- **30-90 days**: Medium risk, monitor closely
- **90-180 days**: Lower risk but still monitor
- **> 180 days**: Generally established

## Suspicious Domain Indicators

**Registration Red Flags**:
- Privacy protection enabled
- Registrant country mismatch
- Recent registration + old content claims
- Bulk registration patterns
- Known bad registrar
- Free hosting services

**Technical Red Flags**:
- New domain + short TTL
- Multiple IP changes
- Cloudflare proxying (hiding origin)
- Fast flux DNS
- Bullet-proof hosting
- Free SSL certificate only

**Content Red Flags**:
- Brand impersonation
- Login forms on new domain
- Typosquatting
- Lookalike domains
- Urgent language
- Poor grammar/spelling

## Typosquatting Detection

Common patterns:
- Character substitution (micros0ft.com)
- Character omission (gogle.com)
- Character addition (bankofamericaa.com)
- Homograph attacks (аpple.com using Cyrillic 'а')
- Wrong TLD (amazon.co vs .com)
- Hyphenation (pay-pal.com)

## Enhanced Detection

```sql
-- Detect newly registered domain similar to corporate domain
from dns.logs
where domain in (
  select domain from threatintel.newly_registered
  where levenshtein_distance(domain, 'companydomain.com') <= 3
    and domain_age <= 30
)
select
  domain,
  domain_age,
  similarity_score,
  count() as query_count
```

## Domain Reputation Checks

**Automated Checks**:
- VirusTotal domain report
- URLhaus database
- PhishTank
- Google Safe Browsing
- Cisco Talos
- AlienVault OTX
- AbuseIPDB (for hosting IP)

**Manual Analysis**:
- WHOIS lookup
- DNS history (PassiveTotal, SecurityTrails)
- SSL certificate transparency logs
- Archive.org snapshots
- Similar domain search

## Legitimate New Domains

**Indicators of Legitimacy**:
- Matches company brand/product launch
- Corporate registrant information
- Established hosting provider
- Professional website design
- Valid business contact info
- Social media presence
- Press releases/announcements
- Extended validation SSL cert

## Email Correlation

Check if domain appeared in:
- Phishing emails
- Spam campaigns
- Email attachments
- Link shorteners
- QR codes in emails

## User Education Opportunities

If phishing attempt detected:
- Send security awareness reminder
- Provide real-world example
- Reinforce reporting procedures
- Explain red flags
- Phishing simulation follow-up

## Blocking Strategy

**Immediate Block**:
- Confirmed phishing
- Malware distribution
- Known malicious campaign
- High confidence threat intel

**Monitor Only**:
- Unclear legitimacy
- Possible false positive
- Gathering more intel
- Low-risk access

**Whitelist**:
- Verified legitimate
- Business-approved
- Known vendor/partner
- Internal company domain

## Prevention Measures
- DNS filtering with new domain detection
- Email security with URL analysis
- Browser isolation for unknown sites
- User awareness training
- Phishing-resistant MFA
- DNS security extensions (DNSSEC)
- Threat intelligence integration
- Web proxy with reputation filtering

## Automation Opportunities
- Auto-submit to VirusTotal
- Automated WHOIS enrichment
- Screenshot capture (sandboxed)
- Similar domain detection
- Automated reputation checks
- Integration with threat intel platforms
- Auto-block high-confidence malicious

## Reporting Metrics
- New domains accessed per day
- Blocked vs allowed
- Phishing campaigns detected
- User training effectiveness
- Time to detection
- False positive rate

## Notes
- Not all new domains are malicious
- Context is critical
- Combine with other indicators
- Monitor rather than block by default
- User education is key
- Regular tuning required
- 30-day window is common but adjustable
