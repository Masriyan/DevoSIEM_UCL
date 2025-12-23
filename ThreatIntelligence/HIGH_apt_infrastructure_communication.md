# Threat Intelligence - APT Infrastructure Communication

## Severity
**HIGH**

## Description
Detects communication with infrastructure associated with Advanced Persistent Threat (APT) groups, indicating potential targeted attack or espionage campaign.

## MITRE ATT&CK
- **Tactic**: Command and Control (TA0011), Reconnaissance (TA0043)
- **Technique**: Application Layer Protocol (T1071), Multi-Stage Channels (T1104)

## DEVO Query

```sql
from firewall.traffic, proxy.logs, dns.logs
select eventdate
select srcaddr
select dstaddr
select domain
select url
select application
select bytes_sent
select bytes_received
select user
select mm2country(srcaddr) as src_country
select mm2country(dstaddr) as dst_country
select purpose(dstaddr) as dst_purpose
where (`in`(select ioc from threatintel.apt_infrastructure, dstaddr)
  or `in`(select domain from threatintel.apt_domains, domain))
  and weakhas(action, "allow")
group by srcaddr, dstaddr, domain
```

## Alert Configuration
- **Trigger**: Any communication with APT infrastructure
- **Throttling**: Real-time, no throttling
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. **IMMEDIATE**: Isolate affected system
2. Activate incident response team
3. Identify APT group and campaign
4. Review threat actor profile and TTPs
5. Assess targeted data/systems
6. Check for data exfiltration
7. Hunt for lateral movement
8. Search for additional compromised systems
9. Collect forensic evidence
10. Review initial access vector
11. Notify executive leadership
12. Consider law enforcement/government notification
13. Engage threat intelligence partners
14. Document all findings

## False Positive Considerations
- Threat intelligence research
- Security vendor testing
- Sinkholed domains (researcher-controlled)
- Shared infrastructure (cloud providers)
- Outdated threat intelligence

**Tuning Recommendations**:
- Verify IOC is currently active
- Exclude security research IPs
- Cross-reference multiple TI sources
- Whitelist authorized research activities
- Age out old APT infrastructure (90+ days)
- Verify attribution confidence level

## Enrichment Opportunities
- Review comprehensive APT group profile
- Analyze historical campaigns
- Check industry targeting patterns
- Review malware families used
- Correlate with recent advisories
- Check for similar activity in sector
- Review geopolitical context
- Analyze threat actor motivations
- Check for related IOCs

## Response Playbook
1. **Immediate Containment** (0-15 min):
   - Network isolation of affected system
   - Alert executive leadership
   - Activate war room
   - Block IOC across all controls
   - Preserve evidence
   - Disable compromised accounts

2. **Threat Actor Analysis** (15-60 min):
   - Identify APT group (APT28, APT29, Lazarus, etc.)
   - Review threat actor profile
   - Understand motivations (espionage, financial, etc.)
   - Review typical TTPs
   - Check targeted industries/regions
   - Analyze historical campaigns
   - Review known malware families
   - Understand dwell time expectations

3. **Scope Assessment** (1-4 hours):
   - Hunt for additional compromised systems
   - Review authentication logs
   - Check for lateral movement
   - Identify data accessed
   - Search for persistence mechanisms
   - Review domain controller logs
   - Check for credential theft
   - Assess data exfiltration

4. **Investigation** (4-24 hours):
   - Full forensic analysis
   - Timeline reconstruction
   - Initial infection vector
   - Complete kill chain mapping
   - All affected systems
   - Data compromise assessment
   - Malware analysis
   - Attribution verification

5. **Eradication** (1-7 days):
   - Remove all malware
   - Clear persistence mechanisms
   - Patch vulnerabilities
   - Reset all credentials
   - Rebuild compromised systems
   - Update security controls
   - Deploy enhanced monitoring

6. **Recovery & Hardening** (Ongoing):
   - Staged system restoration
   - Enhanced detection rules
   - Improved security posture
   - Threat hunting program
   - Intelligence sharing
   - Lessons learned
   - Tabletop exercises

## Investigation Steps
- Map complete attack timeline
- Identify patient zero
- Review all communications with APT infrastructure
- Analyze data transfer patterns
- Check for encrypted channels
- Review process execution logs
- Examine registry modifications
- Check scheduled tasks
- Review service creation
- Analyze file system changes
- Check for rootkits
- Review network connections
- Examine email for spearphishing

## Known APT Groups

**China-Attributed**:
- APT1 (Comment Crew)
- APT10 (MenuPass)
- APT40 (Leviathan)
- APT41 (Double Dragon)
- Winnti Group
- Stone Panda

**Russia-Attributed**:
- APT28 (Fancy Bear)
- APT29 (Cozy Bear)
- Turla
- Sandworm
- Gamaredon

**North Korea-Attributed**:
- Lazarus Group
- APT37
- APT38
- Kimsuky

**Iran-Attributed**:
- APT33
- APT34 (OilRig)
- APT35 (Charming Kitten)
- MuddyWater

**Other Notable Groups**:
- Equation Group
- DarkHotel
- OceanLotus (APT32)

## APT Tactics and Techniques

**Initial Access**:
- Spear phishing with malicious attachments
- Watering hole attacks
- Supply chain compromise
- Stolen credentials
- Zero-day exploitation

**Persistence**:
- Bootkit/rootkit installation
- Registry run keys
- Scheduled tasks
- Service creation
- DLL hijacking
- Web shells

**Privilege Escalation**:
- Zero-day exploits
- Credential theft
- Kerberos attacks
- Token manipulation

**Defense Evasion**:
- Code signing with stolen certificates
- Rootkits
- Process injection
- DLL side-loading
- Timestomping
- Log deletion

**Credential Access**:
- Keylogging
- Credential dumping (Mimikatz)
- Network sniffing
- Kerberoasting
- DCSync

**Lateral Movement**:
- Pass-the-hash
- Remote services
- WMI
- PsExec
- Remote desktop

**Collection**:
- Screen capture
- Keylogging
- Email collection
- File harvesting
- Database queries

**Exfiltration**:
- Encrypted C2 channels
- DNS tunneling
- Steganography
- Cloud storage
- Physical media

## Targeted Sectors by APT Groups

**Common Targets**:
- Government agencies
- Defense contractors
- Critical infrastructure
- Energy sector
- Financial services
- Healthcare
- Technology companies
- Research institutions
- Telecommunications
- Aerospace
- Manufacturing

## Data Typically Targeted

- Intellectual property
- Trade secrets
- Government secrets
- Personal information
- Financial data
- Military technology
- Research and development
- Strategic plans
- Merger and acquisition info
- Competitive intelligence

## APT vs. Commodity Malware

**APT Characteristics**:
- Targeted and persistent
- Custom malware
- Low-and-slow approach
- Long dwell times (months/years)
- Stealthy operations
- Specific objectives
- Well-resourced
- Sophisticated techniques

**Commodity Malware**:
- Opportunistic
- Mass distribution
- Quick operations
- Shorter dwell time
- Less sophisticated
- Financial motivation
- Widely available tools

## Enhanced Detection

```sql
-- Detect multiple APT IOC types from same source
from network.traffic
where (dstip in (select ioc from threatintel.apt_infrastructure)
  or domain in (select ioc from threatintel.apt_domains))
select
  srcip,
  countdistinct(apt_group) as unique_apt_groups,
  countdistinct(ioc_type) as ioc_types,
  collectdistinct(apt_group) as groups_detected,
  sum(bytes_sent) as total_exfiltrated
group by srcip
every 24h
having unique_apt_groups >= 1 or ioc_types >= 2
```

## Threat Intelligence Sources for APT

- **Government**: CISA, NSA, FBI, NCSC
- **Vendors**: CrowdStrike, FireEye, Kaspersky, Palo Alto
- **ISACs**: Sector-specific sharing
- **MITRE ATT&CK**: APT group profiles
- **Commercial TI**: Recorded Future, Anomali

## Attribution Challenges

Consider:
- False flag operations
- Infrastructure sharing
- Tool reuse across groups
- Misattribution risks
- Insufficient evidence
- Overlapping TTPs

Focus on:
- Response and containment
- Not attribution during active incident
- Protecting critical assets
- Evidence preservation

## Communication Plan

**Internal**:
- Executive leadership (immediate)
- Board of directors (within 24h)
- Legal counsel
- IT/Security teams
- Affected business units

**External** (as appropriate):
- Law enforcement (FBI, CISA)
- Incident response partners
- Cyber insurance
- Industry peers (ISAC)
- Customers (if data compromised)
- Regulators (if required)

## Legal and Compliance

- Preserve chain of custody
- Document everything
- Legal hold on data
- Regulatory reporting (varies by sector)
- Customer notification (data breach laws)
- Insurance claim filing
- Law enforcement coordination
- International implications

## Long-Term Actions

- Threat hunting program
- Enhanced monitoring
- Red team exercises
- Architecture review
- Zero trust implementation
- Threat intelligence program
- Incident response plan updates
- Security awareness (APT tactics)
- Third-party risk review
- Supply chain security

## Notes
- APT detection is high-priority
- Assume prolonged compromise
- Professional incident response recommended
- Government notification may be required
- Long-term remediation needed
- Threat hunting is essential
- Intelligence sharing benefits community
- May require complete infrastructure rebuild
