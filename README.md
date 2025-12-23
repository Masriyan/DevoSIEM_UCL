# DEVO SIEM Use Case Library

![DEVO SIEM Use Case Library](devosiem_banner.png)

A comprehensive collection of SIEM detection rules and use cases for DEVO Security Operations Platform.

> **⚠️ Important Notice:** This is a community-driven project and is **NOT officially affiliated with, sponsored by, or endorsed by DEVO Technology**. This library is independently created and maintained for educational and professional use by security practitioners.

## Overview

This repository contains **43 production-ready SIEM use cases** covering multiple security domains and technologies. Each use case is designed to detect specific threats, suspicious activities, or policy violations with detailed response playbooks and MITRE ATT&CK mappings.

## 📊 Statistics

- **Total Use Cases**: 43 production-ready detection rules
- **CRITICAL Severity**: 18 use cases
- **HIGH Severity**: 16 use cases
- **MEDIUM Severity**: 7 use cases
- **LOW Severity**: 2 use cases

## 🆕 What's New in v1.1.0

### Threat Intelligence Category (NEW!)
- IOC Match with Known Malware (CRITICAL)
- APT Infrastructure Communication (HIGH)
- TOR/VPN/Anonymization Network Usage (HIGH)
- Newly Registered Domain Access (MEDIUM)

### Expanded Cloud Coverage
- **AWS**: Lambda Backdoor Detection, Secrets Manager Monitoring (2 new use cases)
- **Azure**: Service Principal Credential Tracking (1 new use case)
- **GCP**: External IP Exposure Detection (1 new use case)

## Structure

```
DevoSIEM_UCL/
├── Firewall/
│   ├── PaloAlto/          # 4 use cases
│   ├── Fortinet/          # 4 use cases
│   └── Checkpoint/        # 3 use cases
├── Cloud/
│   ├── AWS/               # 6 use cases (Expanded!)
│   ├── Azure/             # 5 use cases (Expanded!)
│   └── GCP/               # 4 use cases (Expanded!)
├── ThreatIntelligence/    # 4 use cases (NEW!)
├── IAM/                   # 3 use cases
├── Correlation/           # 1 use case
├── ImpossibleTravel/      # 2 use cases
├── InsiderThreat/         # 2 use cases
├── WAF/                   # 2 use cases
├── EDR/                   # 2 use cases
├── EmailSecurity/         # 1 use case
├── Network/               # 1 use case
├── DLP/                   # 1 use case
└── WebProxy/              # Infrastructure
```

## Severity Levels

Each use case is categorized by severity:

- **CRITICAL**: Immediate threat requiring urgent response (e.g., active exploitation, data exfiltration, ransomware)
- **HIGH**: Serious security concern requiring prompt investigation (e.g., privilege escalation, malware detection)
- **MEDIUM**: Notable security event requiring attention (e.g., policy violations, suspicious activities)
- **LOW**: Informational alerts for monitoring and compliance (e.g., configuration changes, baseline deviations)

## Use Case Categories

### Firewall (11 use cases)
- **Palo Alto Networks**: Threat prevention, URL filtering, WildFire malware alerts, C2 detection
- **Fortinet**: IPS events, botnet detection, SQL injection, network anomaly detection
- **Checkpoint**: Threat emulation, IPS critical attacks, anti-bot detection

### Cloud Security (17 use cases)
- **AWS**: GuardDuty findings, CloudTrail anomalies, S3 security, Lambda backdoors, Secrets Manager monitoring, root account usage
- **Azure**: Security Center alerts, identity protection, admin consent tracking, service principal abuse, MFA failures, conditional access changes
- **GCP**: Security Command Center, VPC flow anomalies, IAM changes, service account keys, external IP exposure, firewall modifications

### Threat Intelligence (4 use cases) 🆕
- **IOC Matching**: Correlate network traffic with malicious IP, domain, and file hash databases
- **APT Detection**: Identify Advanced Persistent Threat group infrastructure and campaigns
- **Anonymization Networks**: Detect TOR, VPN, and proxy usage for insider threat and data exfiltration
- **Domain Reputation**: Track access to newly registered domains used in phishing and malware campaigns

### Identity & Access Management (3 use cases)
- Brute force and credential stuffing detection
- Privilege escalation detection
- Suspicious authentication patterns
- Password spray attack detection
- Account compromise indicators
- After-hours privileged access

### Correlation Rules (1 use case)
- Multi-stage attack detection
- Lateral movement patterns
- Kill chain progression (initial compromise → credential theft → lateral movement)
- Cross-source threat correlation

### Impossible Travel (2 use cases)
- Geographic anomaly detection with velocity calculations
- Simultaneous logins from distant locations
- Concurrent sessions from different countries
- VPN/proxy abuse detection

### Insider Threat (2 use cases)
- Mass data exfiltration detection
- Abnormal user behavior
- Access to sensitive data before resignation
- After-hours access anomalies
- Privilege abuse patterns

### Web Application Firewall (2 use cases)
- Web shell upload attempts
- SQL injection attempts
- XSS attacks
- OWASP Top 10 violations
- Multiple attack pattern detection

### Endpoint Detection & Response (2 use cases)
- Ransomware behavior indicators
- Credential dumping detection (Mimikatz, LSASS access)
- Living-off-the-land techniques
- Process injection detection

### Email Security (1 use case)
- Business Email Compromise (BEC) detection
- Phishing detection
- Email forwarding rule abuse
- Display name spoofing
- Domain impersonation

### Network Security (1 use case)
- DNS tunneling detection
- DDoS indicators
- C2 communication patterns
- Data exfiltration via DNS

### Data Loss Prevention (1 use case)
- Sensitive data upload to personal cloud storage
- Policy violations
- Unauthorized data transfers

## Usage

Each use case file contains:
1. **Rule Name**: Descriptive name of the detection
2. **Severity**: CRITICAL, HIGH, MEDIUM, or LOW
3. **Description**: What the rule detects and why it matters
4. **MITRE ATT&CK Mapping**: Relevant tactics and techniques
5. **DEVO Query**: The actual LINQ query for DEVO SIEM
6. **Alert Configuration**: Trigger conditions, throttling, and priority
7. **Recommended Actions**: Step-by-step response procedures
8. **False Positive Considerations**: Common false positives and tuning guidance
9. **Response Playbook**: Detailed incident response procedures
10. **Investigation Steps**: Forensic guidance
11. **Prevention Measures**: Security controls to prevent the threat

## Implementation

To implement these rules in DEVO SIEM:

1. **Select a use case** from the [INDEX.md](INDEX.md) based on priority
2. **Review the query** - All queries use official DEVO LINQ syntax
3. **Verify table names** - Confirm the table exists in your DEVO environment
4. **Navigate to Alerts** in the DEVO platform
5. **Create new alert** - Choose "Custom Query" or "Correlation Rule"
6. **Copy the LINQ query** from the use case file
7. **Test in Query mode** - Run with small time window (last 5-10 minutes)
8. **Validate results** - Ensure query returns expected data
9. **Configure alert settings**:
   - Set severity level
   - Configure notifications (email, webhook, SOAR)
   - Set throttling/deduplication
   - Define alert priority
10. **Tune thresholds** - Adjust based on your environment baseline
11. **Deploy to production** - Enable the alert
12. **Monitor and refine** - Track false positives and adjust as needed

## Implementation Roadmap

### Phase 1 - Critical Threats (Week 1-2)
Focus on CRITICAL severity use cases:
- Ransomware indicators
- Malware detection (WildFire, Threat Emulation, IOC matching)
- Business Email Compromise
- Impossible Travel
- Mass Data Exfiltration
- Kill Chain Lateral Movement
- Lambda/Serverless backdoors
- APT infrastructure communication

### Phase 2 - High Impact (Week 3-4)
Implement HIGH severity use cases:
- Credential dumping
- Root/privileged account monitoring
- SQL injection and exploit attempts
- DNS tunneling
- Data upload to cloud storage
- Secrets Manager access anomalies
- TOR/Anonymization detection
- Service principal abuse

### Phase 3 - Comprehensive Coverage (Month 2)
Deploy MEDIUM and LOW severity use cases:
- Policy violations
- Configuration changes
- Anomaly detection
- Compliance monitoring
- Newly registered domain tracking

### Phase 4 - Threat Intelligence Integration (Month 2-3)
Integrate threat intelligence feeds:
- Configure IOC feeds (AlienVault OTX, Abuse.ch, commercial feeds)
- Implement APT tracking
- Enable domain reputation checking
- Set up anonymization network blocking

## Threat Intelligence Integration

The Threat Intelligence category enables proactive defense through:

**IOC Matching**:
- Correlate network traffic, DNS, and file hashes with threat intelligence
- Support for multiple feed sources (commercial and open-source)
- Automated blocking of known malicious infrastructure

**APT Detection**:
- Identify communication with Advanced Persistent Threat groups
- Track campaigns targeting your industry
- Understand threat actor TTPs and motivations

**Behavioral Analytics**:
- Detect anomalous anonymization network usage
- Track newly registered domains (phishing, malware distribution)
- Identify insider threats using privacy tools

**Recommended Threat Intelligence Feeds**:
- **Commercial**: Recorded Future, Anomali ThreatStream, CrowdStrike Falcon Intelligence
- **Open Source**: AlienVault OTX, MISP, Abuse.ch (Feodo, URLhaus, ThreatFox)
- **Government**: CISA, US-CERT, FBI FLASH, NCSC
- **Community**: Industry-specific ISACs and sharing groups

## Cloud Security Features

Comprehensive multi-cloud security coverage:

**AWS**:
- GuardDuty findings correlation
- Lambda function abuse detection
- Secrets Manager access monitoring
- Root account usage tracking
- S3 bucket exposure detection
- Security group change monitoring

**Azure**:
- Admin consent tracking
- Global Administrator role monitoring
- Service principal credential abuse
- MFA failure detection
- Conditional Access policy changes

**GCP**:
- Service account key creation
- Compute instance external IP exposure
- IAM policy modifications
- VPC firewall rule changes

## MITRE ATT&CK Coverage

All use cases are mapped to the MITRE ATT&CK framework:
- **Tactics**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact
- **Techniques**: 50+ specific techniques covered
- **Sub-techniques**: Detailed mappings for precision detection

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

New use cases should include:
- Clear description
- Working DEVO LINQ query
- MITRE ATT&CK mapping
- Tuning guidance
- Response playbook
- Investigation steps
- Prevention measures

## Quick Start

1. **Browse** the [INDEX.md](INDEX.md) to find relevant use cases
2. **Review** the use case file for your technology stack
3. **Copy** the DEVO LINQ query
4. **Test** in non-production DEVO environment
5. **Tune** based on false positive guidance
6. **Deploy** to production with appropriate notifications
7. **Document** any customizations for your environment

## Documentation

- **[INDEX.md](INDEX.md)** - Complete index of all use cases organized by category and severity
- **[DEVO_QUERY_SYNTAX_GUIDE.md](DEVO_QUERY_SYNTAX_GUIDE.md)** - Comprehensive guide to align queries with actual DEVO LINQ syntax
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guidelines for adding new use cases
- **[BANNER_INFO.md](BANNER_INFO.md)** - Information about creating the repository banner image
- Individual use case files with detailed documentation

## Disclaimer

### Community Project Notice

**This project is NOT officially affiliated with, sponsored by, or endorsed by DEVO Technology or any DEVO-related entity.**

- This is an **independent, community-driven project** created by security professionals for security professionals
- The author is **not employed by or representing DEVO Technology**
- DEVO SIEM® is a registered trademark of DEVO Technology Inc.
- All use cases and content are provided **"as-is"** without any warranty or official support from DEVO
- For official DEVO documentation, please visit: [https://docs.devo.com/](https://docs.devo.com/)
- For official DEVO support, contact DEVO Technology directly

### Use Case Disclaimer

These use cases are provided as templates and should be tested and tuned for your specific environment. Always validate rules in a non-production environment first. Detection effectiveness may vary based on:
- Data source availability and quality
- Environment-specific configurations
- Baseline normal behavior
- Threat landscape evolution
- DEVO platform version and features

**✅ DEVO LINQ Syntax - Production Ready:**
All 45 queries in this library have been written using **official DEVO LINQ syntax** including:

- **Multiple SELECT statements** - One select statement per field/expression
- **DEVO-specific functions** - `weakhas()`, `mm2country()`, `mm2city()`, `purpose()`
- **Backtick list operations** - `` `in`() `` for list membership
- **Geographic enrichment** - Automatic IP-to-country/city mapping
- **IP classification** - `purpose()` function for IP type identification

**⚠️ Environment-Specific Validation Required:**
While queries use official DEVO syntax, you must verify:

- **Table names** - Confirm tables exist in your DEVO environment (e.g., `firewall.paloalto.traffic`, `cloud.aws.cloudtrail`)
- **Field names** - Verify field names match your data source schema
- **Data availability** - Ensure required fields are populated in your environment
- **Threshold tuning** - Adjust alert thresholds based on your baseline
- **Test before deployment** - Always test in non-production first

**📖 DEVO Syntax Guide:** See [DEVO_QUERY_SYNTAX_GUIDE.md](DEVO_QUERY_SYNTAX_GUIDE.md) for comprehensive DEVO LINQ reference and examples.

**📋 Syntax Analysis:** See [SYNTAX_ANALYSIS_REPORT.md](SYNTAX_ANALYSIS_REPORT.md) for detailed analysis of query structure and best practices.

**No Warranty:** The author provides these use cases without any warranty, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

## Support

For questions, issues, or contributions:
- **GitHub Issues**: https://github.com/Masriyan/DevoSIEM_UCL/issues
- **Discussions**: https://github.com/Masriyan/DevoSIEM_UCL/discussions
- **Author**: Masriyan

## Author

Created and maintained by Masriyan

Repository: https://github.com/Masriyan/DevoSIEM_UCL

## License

MIT License - Feel free to use and modify for your security operations.

See [LICENSE](LICENSE) file for details.

## Version History

- **v1.1.0** (Current) - Added Threat Intelligence category (4 use cases) + Expanded Cloud coverage (7 new use cases)
  - Total: 43 use cases
  - New: IOC matching, APT detection, TOR/VPN monitoring, newly registered domains
  - Expanded: AWS Lambda, Secrets Manager, Azure Service Principals, GCP External IPs

- **v1.0.0** - Initial Release
  - Total: 32 use cases
  - Coverage: Firewall, Cloud, IAM, Impossible Travel, Insider Threat, WAF, EDR, Email, Network, DLP

## Acknowledgments

- MITRE ATT&CK Framework for threat taxonomy
- DEVO Technology for the security operations platform
- Security community for threat intelligence sharing
- Contributors and users of this library

---

**Star this repository** ⭐ if you find it useful!

**Contribute** by submitting new use cases or improvements!

**Share** with your security operations team!

---

## 🎨 Repository Banner

The repository banner image (`devosiem_banner.png`) should be created and placed in the root directory. See [BANNER_INFO.md](BANNER_INFO.md) for design guidelines, specifications, and tools to create a professional banner for this repository.

**Note:** Ensure the banner does not use official DEVO Technology branding to maintain clear distinction as a community project.
