# DEVO SIEM Use Case Library

A comprehensive collection of SIEM detection rules and use cases for DEVO Security Operations Platform.

## Overview

This repository contains production-ready SIEM use cases covering multiple security domains and technologies. Each use case is designed to detect specific threats, suspicious activities, or policy violations.

## Structure

```
DevoSIEM_UCL/
├── Firewall/
│   ├── PaloAlto/
│   ├── Fortinet/
│   └── Checkpoint/
├── Cloud/
│   ├── AWS/
│   ├── Azure/
│   └── GCP/
├── IAM/
├── Correlation/
├── ImpossibleTravel/
├── InsiderThreat/
├── WAF/
├── EDR/
├── EmailSecurity/
├── Network/
├── DLP/
└── WebProxy/
```

## Severity Levels

Each use case is categorized by severity:

- **CRITICAL**: Immediate threat requiring urgent response (e.g., active exploitation, data exfiltration)
- **HIGH**: Serious security concern requiring prompt investigation (e.g., privilege escalation, malware detection)
- **MEDIUM**: Notable security event requiring attention (e.g., policy violations, suspicious activities)
- **LOW**: Informational alerts for monitoring and compliance (e.g., configuration changes, baseline deviations)

## Use Case Categories

### Firewall
- **Palo Alto**: Threat prevention, URL filtering, wildfire alerts
- **Fortinet**: IPS events, botnet detection, anomaly detection
- **Checkpoint**: Threat prevention, compliance violations

### Cloud Security
- **AWS**: GuardDuty findings, CloudTrail anomalies, S3 security
- **Azure**: Security Center alerts, identity protection, resource changes
- **GCP**: Security Command Center, VPC flow anomalies, IAM changes

### Identity & Access Management (IAM)
- Privilege escalation detection
- Suspicious authentication patterns
- Account compromise indicators
- Service account abuse

### Correlation Rules
- Multi-stage attack detection
- Lateral movement patterns
- Kill chain progression
- Cross-source threat correlation

### Impossible Travel
- Geographic anomaly detection
- Simultaneous logins from distant locations
- VPN/proxy abuse detection

### Insider Threat
- Data exfiltration attempts
- Abnormal user behavior
- After-hours access
- Privilege abuse

### Web Application Firewall (WAF)
- SQL injection attempts
- XSS attacks
- OWASP Top 10 violations
- API abuse

### Endpoint Detection & Response (EDR)
- Malware detection
- Ransomware indicators
- Living-off-the-land techniques
- Process injection

### Email Security
- Phishing detection
- Business Email Compromise (BEC)
- Malicious attachments
- Domain spoofing

### Network Security
- Port scanning
- DDoS indicators
- Tunneling detection
- DNS exfiltration

### Data Loss Prevention (DLP)
- Sensitive data exposure
- Policy violations
- Unauthorized transfers

### Web Proxy
- C2 communication
- Malicious downloads
- Policy violations

## Usage

Each use case file contains:
1. **Rule Name**: Descriptive name of the detection
2. **Severity**: CRITICAL, HIGH, MEDIUM, or LOW
3. **Description**: What the rule detects
4. **DEVO Query**: The actual LINQ query for DEVO SIEM
5. **Recommended Actions**: Response procedures
6. **False Positive Considerations**: Common false positives and tuning guidance
7. **MITRE ATT&CK Mapping**: Relevant techniques and tactics

## Implementation

To implement these rules in DEVO SIEM:

1. Navigate to the Alerts section in DEVO
2. Create a new alert/correlation rule
3. Copy the LINQ query from the use case file
4. Configure severity, notifications, and response actions
5. Test and tune based on your environment

## Contributing

Contributions are welcome! Please ensure new use cases follow the established format and include:
- Clear description
- Working DEVO LINQ query
- MITRE ATT&CK mapping
- Tuning guidance

## Disclaimer

These use cases are provided as templates and should be tested and tuned for your specific environment. Always validate rules in a non-production environment first.

## Author

Created by Masriyan
Repository: https://github.com/Masriyan/DevoSIEM_UCL

## License

MIT License - Feel free to use and modify for your security operations.

## Version

v1.0.0 - Initial Release
