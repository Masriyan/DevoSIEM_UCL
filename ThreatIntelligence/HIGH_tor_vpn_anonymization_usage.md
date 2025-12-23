# Threat Intelligence - TOR/VPN/Anonymization Network Usage

## Severity
**HIGH**

## Description
Detects when internal users connect to TOR exit nodes, anonymous VPNs, or proxy networks, which may indicate data exfiltration, insider threat, or policy violation.

## MITRE ATT&CK
- **Tactic**: Command and Control (TA0011), Defense Evasion (TA0005)
- **Technique**: Proxy: Multi-hop Proxy (T1090.003), Encrypted Channel (T1573)

## DEVO Query

```sql
from firewall.traffic, proxy.logs, network.connections
where (dstip in (select ip from threatintel.tor_exit_nodes)
  or dstip in (select ip from threatintel.vpn_services where category = "anonymous")
  or dstip in (select ip from threatintel.proxy_networks)
  or domain like "%.onion"
  or domain in (select domain from threatintel.anonymization_services))
  and srcip in (select ip from internal_networks)
select
  eventdate,
  srcip,
  srchost,
  user,
  dstip,
  dstport,
  domain,
  threatintel.tor_exit_nodes.country as tor_exit_country,
  threatintel.vpn_services.service_name,
  threatintel.vpn_services.privacy_rating,
  bytes_sent,
  bytes_received,
  protocol,
  application,
  geolocation
group by srcip, user, dstip
```

## Alert Configuration
- **Trigger**: Any connection to TOR/anonymous VPN/proxy network
- **Throttling**: 1 alert per user per 2 hours
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Identify user and system connecting to anonymization network
2. Contact user to verify legitimate business need
3. Review data transfer volumes
4. Check for data exfiltration indicators
5. Review user's recent activities
6. Assess risk based on user's role and access
7. Block anonymization networks if not approved
8. Review acceptable use policy
9. Document business justification if legitimate
10. Escalate to HR/Legal if policy violation

## False Positive Considerations
- Approved security research
- Legitimate privacy tools for specific roles
- International staff using VPNs for geo-restrictions
- IT security team testing
- Approved remote access solutions

**Tuning Recommendations**:
- Whitelist approved VPN services
- Exclude security team testing activities
- Document approved anonymization use cases
- Different thresholds for different user roles
- Consider geo-location and business travel

## Enrichment Opportunities
- Check user's HR profile and role
- Review historical network usage patterns
- Correlate with data access logs
- Check for concurrent suspicious activities
- Review user's privilege level
- Verify device compliance status
- Check for resignation/disciplinary status
- Review recent data downloads

## Response Playbook
1. **Initial Assessment**:
   - Who is the user?
   - What anonymization service?
   - Data transfer volume?
   - Time of day (business hours?)
   - User's role and access level?

2. **User Contact**:
   - Call user directly
   - Verify business justification
   - Explain policy if violation
   - Document conversation

3. **Risk Assessment**:
   - High privilege user? (Escalate)
   - Sensitive data access?
   - Large data transfers? (Exfiltration?)
   - After-hours usage?
   - Departing employee?

4. **For Policy Violations**:
   - Document incident
   - Notify manager
   - HR involvement
   - Review data accessed
   - Check for data loss
   - Potential disciplinary action

5. **For Legitimate Use**:
   - Document approval
   - Update policy/whitelist
   - Monitor for patterns
   - User education

## Investigation Steps
- Review complete session details
- Check data transfer volumes (upload vs download)
- Verify user's normal behavior baseline
- Review data accessed during session
- Check for file downloads/uploads
- Analyze timing patterns
- Review other anonymization attempts
- Check endpoint for TOR browser installation
- Review browser history
- Check for encrypted containers/files

## Anonymization Services

**TOR (The Onion Router)**:
- Onion routing for anonymity
- .onion dark web sites
- TOR Browser
- Exit node IP lists
- Used for privacy and dark web access

**Anonymous VPN Services**:
- NordVPN
- ExpressVPN
- ProtonVPN
- Mullvad
- IVPN
- Privacy-focused VPNs
- Cryptocurrency payment accepted

**Proxy Networks**:
- Public SOCKS proxies
- HTTP/HTTPS proxies
- Proxy chains
- Residential proxy networks
- Mobile proxy services

**Other Anonymization**:
- I2P (Invisible Internet Project)
- Freenet
- JonDonym
- Psiphon
- Lantern

## Legitimate Use Cases

**Acceptable Reasons**:
- Security research (approved)
- Threat intelligence gathering
- Adversary infrastructure investigation
- Privacy for executives in high-risk regions
- Journalist/legal protection (specific roles)
- Accessing blocked content for business (regional)

**Unacceptable Reasons**:
- Bypassing corporate security
- Hiding malicious activity
- Data exfiltration
- Accessing prohibited content
- Circumventing monitoring
- Personal privacy on corporate network

## High-Risk Scenarios

Escalate to CRITICAL if:
- Privileged/admin user
- Access to sensitive data
- Large data uploads (> 1 GB)
- After-hours usage
- Departing employee
- Recent disciplinary action
- Multiple anonymization services
- Concurrent data access anomalies
- Encrypted file transfers
- Dark web (.onion) access

## Data Exfiltration Indicators

Red flags for data theft:
- High upload volumes to TOR
- Access to databases before TOR usage
- File compression/encryption
- Multiple anonymization methods
- After-hours data access + TOR
- Systematic file downloads then TOR
- Cloud storage + anonymization
- USB activity + TOR usage

## TOR Detection Methods

**Network Indicators**:
- Connections to known TOR entry/exit nodes
- TOR directory authority connections
- .onion domain queries
- TOR bridge connections
- Obfuscated TOR traffic (obfs4)

**Endpoint Indicators**:
- TOR Browser installation
- TOR processes (tor.exe)
- TOR configuration files
- Vidalia, Tails, Whonix
- Browser plugins for TOR

**Traffic Patterns**:
- Multi-hop connections
- Encrypted traffic to known nodes
- Regular beacon patterns
- Non-standard TLS usage

## VPN vs Anonymous VPN

**Corporate VPN** (Low Risk):
- Company-approved
- Managed by IT
- Logged and monitored
- Business use documented
- Split tunneling configured

**Anonymous VPN** (High Risk):
- Privacy-focused marketing
- No-logs policy
- Cryptocurrency payments
- Offshore jurisdictions
- Unknown security posture
- Defeats corporate monitoring

## Enhanced Detection

```sql
-- Detect pattern of anonymization with data access
from proxy.logs
where dstip in (select ip from threatintel.tor_exit_nodes)
  and user in (
    select user from data_access_logs
    where data_classification = "confidential"
    and eventdate between now() - 1h and now()
  )
select
  user,
  srcip,
  dstip,
  sum(bytes_sent) as total_uploaded,
  count() as tor_connections
group by user
```

## Dark Web Access

.onion sites may indicate:
- Marketplace access (stolen data, tools)
- Hacking forums
- Credential dumps
- Ransomware payment sites
- Illegal content
- Whistleblowing platforms

**Legitimate Dark Web**:
- Threat intelligence research
- Brand monitoring
- Credential monitoring
- Security research

## Prevention Measures
- Block TOR exit nodes at firewall
- DNS filtering for .onion domains
- Proxy blocking of anonymization services
- Application control (block TOR Browser)
- Acceptable use policy
- User awareness training
- DLP for data exfiltration
- Endpoint detection for TOR
- Network behavioral analytics

## Policy Recommendations

**Acceptable Use Policy should cover**:
- Prohibition of anonymization tools
- Exceptions for approved roles
- Approval process
- Monitoring disclosure
- Consequences of violations
- Reporting requirements

**Technical Controls**:
- Block by default
- Whitelist approved services
- Alert on any usage
- Require manager approval
- Document all exceptions
- Regular access reviews

## User Roles Analysis

**High Risk Roles**:
- Database administrators
- System administrators
- Developers with code access
- Finance/accounting
- HR (employee data)
- Executive assistants
- Sales (customer data)

**Lower Risk Roles**:
- Security researchers (approved)
- Threat intelligence analysts
- Journalists/communications
- Legal team (case-specific)

## Geographic Considerations

**Higher Risk Locations**:
- Countries with strict internet controls
- High censorship regions
- Data protection concerns
- VPN may be business necessary

**Verify Legitimate Need**:
- Business operations in region?
- Geo-blocked content needed?
- Safety concerns for user?
- Approved by management?

## Incident Severity Matrix

| User Role | Data Access | Volume | Time | Severity |
|-----------|-------------|--------|------|----------|
| Admin | Sensitive | High | After-hours | CRITICAL |
| Admin | Sensitive | Low | Business hours | HIGH |
| Regular | Public | Low | Business hours | MEDIUM |
| Security Team | Any | Any | Any | LOW (if approved) |

## Compliance Impact
- Acceptable use policy violation
- Data protection concerns
- Regulatory compliance (data residency)
- Audit logging requirements
- May indicate insider threat

## Notes
- Not all anonymization is malicious
- Context and user role matter
- Legitimate use cases exist
- Document everything
- Balance security with privacy
- Clear policies essential
- Regular review needed
