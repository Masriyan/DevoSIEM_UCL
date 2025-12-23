# Network - DNS Tunneling Detection

## Severity
**HIGH**

## Description
Detects DNS tunneling used for data exfiltration or C2 communication by identifying unusual DNS query patterns, long domain names, and high query volumes.

## MITRE ATT&CK
- **Tactic**: Command and Control (TA0011), Exfiltration (TA0010)
- **Technique**: Application Layer Protocol: DNS (T1071.004), Exfiltration Over C2 Channel (T1041)

## DEVO Query

```sql
from network.dns
select domain from approved_dynamic_dns))
  or entropy(domain) > 4.5
select
  eventdate,
  srcip,
  domain,
  query_type,
  length(domain) as domain_length,
  subdomain_count,
  entropy(domain) as domain_entropy,
  count() as query_count,
  sum(response_bytes) as total_response_bytes,
  countdistinct(domain) as unique_domains
where `in`("TXT", "NULL", "CNAME", "MX", query_type)
  or length(domain) > 60
  or (subdomain_count > 5
    and domain not in (
every 10m
```

## Alert Configuration
- **Trigger**: > 100 DNS queries OR > 50 unique domains OR domain length > 60 in 10 minutes
- **Throttling**: 1 alert per srcip per hour
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Identify source system generating queries
2. Block suspicious domains at DNS resolver
3. Isolate affected system
4. Check for malware/C2 communication
5. Review process making DNS queries
6. Analyze domain registration details
7. Block domain at firewall
8. Check for data exfiltration
9. Hunt for similar activity
10. Review other DNS anomalies from same source

## False Positive Considerations
- Legitimate dynamic DNS services
- CDN with many subdomains
- Cloud services (AWS, Azure, GCP)
- Security tools with many lookups
- Monitoring/health check systems

**Tuning Recommendations**:
- Whitelist approved dynamic DNS (dyndns.org, etc.)
- Exclude CDN providers
- Adjust query count threshold by network size
- Filter known cloud service domains
- Baseline normal DNS behavior

## Enrichment Opportunities
- Check domain registration date (WHOIS)
- Review domain reputation
- Analyze DNS response patterns
- Check source process on endpoint
- Review network traffic to resolved IPs
- Correlate with threat intelligence
- Check for DGA (Domain Generation Algorithm)

## Response Playbook
1. **Initial Analysis**:
   - Review domain characteristics
   - Check query volume and pattern
   - Analyze response types
   - Verify source system
2. **Domain Investigation**:
   - WHOIS lookup
   - Domain age
   - Reputation check
   - Threat intelligence
   - Passive DNS
3. **Host Investigation**:
   - Identify process making queries
   - Check for malware
   - Review recent activities
   - Scan with EDR/AV
4. **If Malicious**:
   - Block domain globally
   - Isolate affected system
   - Remove malware
   - Hunt for IOCs
   - Reset credentials
5. **If Tunneling Confirmed**:
   - Forensic analysis
   - Data loss assessment
   - Identify exfiltrated data
   - Full incident response

## Investigation Steps
- Capture sample DNS queries
- Decode potential encoded data
- Analyze subdomain patterns
- Review query timing
- Check TXT record contents
- Verify resolved IP addresses
- Review client process
- Check for encryption/encoding
- Analyze traffic volume

## DNS Tunneling Indicators

**Query Patterns**:
- Unusually long domain names (> 60 chars)
- High entropy/randomness
- Many subdomains
- Sequential subdomain patterns
- Regular query intervals (beaconing)
- Unusual query types (TXT, NULL)
- No corresponding HTTP/HTTPS traffic

**Domain Characteristics**:
- Recently registered
- Uncommon TLD
- Random-looking characters
- Base32/Base64 patterns
- Hexadecimal strings
- No legitimate website

**Volume Indicators**:
- High query frequency
- Large TXT responses
- Many unique subdomains
- Consistent query timing
- Unusual query:response ratio

## DNS Tunneling Tools
- **Iodine**: Popular DNS tunnel
- **DNSCat2**: C2 over DNS
- **DNS2TCP**: TCP over DNS
- **OzymanDNS**: Data exfiltration
- **DNSExfiltrator**: PowerShell-based

## Example Patterns
```
# Base64 encoded data in subdomain
dGVzdCBkYXRh.attacker.com

# Chunked data exfiltration
chunk1.sessionid.attacker.com
chunk2.sessionid.attacker.com

# C2 beaconing
beacon-12345678.c2domain.com

# TXT record response
"encoded_command_or_data"
```

## Detection Heuristics

**Domain Length**:
- Normal: < 30 characters
- Suspicious: 30-60 characters
- Very suspicious: > 60 characters

**Entropy**:
- Normal: < 3.5
- Suspicious: 3.5-4.5
- Very suspicious: > 4.5

**Query Types**:
- Normal: A, AAAA (90%+)
- Suspicious: TXT, NULL, CNAME (high %)

## Enhanced Detection
```sql
-- Detect potential DGA domains
from network.dns
where length(domain) > 15
  and entropy(domain) > 4.0
  and domain_age < 30
  and query_count > 1
select
  domain,
  entropy(domain) as ent,
  length(domain) as len,
  domain_age,
  count() as queries
```

## Data Exfiltration Estimation
If tunneling confirmed:
- Query count × average subdomain length
- TXT record size × response count
- Estimate data volume exfiltrated
- Identify time range of exfiltration
- Assess data sensitivity

## Prevention Measures
- DNS filtering/blacklisting
- Block unusual DNS query types (TXT, NULL)
- Rate limiting DNS queries
- DNS traffic inspection
- Allow only authorized DNS servers
- Monitor DNS query lengths
- Implement DNS security extensions (DNSSEC)
- Network segmentation
- Data Loss Prevention (DLP)
- Endpoint protection

## DNS Security Controls
- Recursive query restrictions
- Response rate limiting (RRL)
- DNS firewall/RPZ
- Query logging and analysis
- Block dynamic DNS (if not needed)
- DNS over HTTPS (DoH) monitoring
- Split-horizon DNS

## Legitimate Use Cases to Exclude
- Cloud service discovery
- SRV record lookups
- Certificate transparency logs
- SPF/DKIM/DMARC lookups
- CDN/load balancer rotation
- Service discovery protocols

## Forensic Analysis
Collect:
- Full DNS query logs
- PCAP of DNS traffic
- Endpoint process logs
- Network flow data
- Threat intelligence matches
- Decoded tunnel data (if possible)

## Command Examples
```bash
# Analyze DNS log for long domains
cat dns.log | awk '{print length($1), $1}' | sort -rn | head -20

# Calculate domain entropy
echo "domain.com" | awk '{for(i=1;i<=length;i++){a[substr($0,i,1)]++}}END{for(c in a){p=a[c]/length;e-=p*log(p)/log(2)}print e}'

# Extract TXT records
dig TXT suspicious-domain.com

# Monitor DNS queries in real-time
tcpdump -i any -n port 53
```

## Compliance Impact
- Data exfiltration = breach
- May require notification
- Forensic investigation required
- Document all findings

## Notes
- DNS tunneling bypasses many controls
- Detection requires baseline
- Combine multiple indicators
- Low-and-slow tunneling harder to detect
- Prevention is key (block at resolver)
- Monitor for encoding patterns
