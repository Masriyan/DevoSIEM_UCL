# DEVO SIEM Use Case Library - Index

Comprehensive index of all detection rules organized by category and severity.

## Quick Navigation
- [Firewall](#firewall)
- [Cloud Security](#cloud-security)
- [Threat Intelligence](#threat-intelligence)
- [Identity & Access Management](#identity--access-management)
- [Impossible Travel](#impossible-travel)
- [Insider Threat](#insider-threat)
- [Web Application Firewall](#web-application-firewall)
- [Endpoint Detection & Response](#endpoint-detection--response)
- [Email Security](#email-security)
- [Network Security](#network-security)
- [Correlation Rules](#correlation-rules)
- [Data Loss Prevention](#data-loss-prevention)

---

## Firewall

### Palo Alto Networks
| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | WildFire Malware Detection | `Firewall/PaloAlto/CRITICAL_wildfire_malware_detected.md` |
| HIGH | Threat Prevention Exploit Attempt | `Firewall/PaloAlto/HIGH_threat_prevention_exploit_attempt.md` |
| MEDIUM | Command and Control Communication | `Firewall/PaloAlto/MEDIUM_c2_communication_detected.md` |
| LOW | Policy Violation - Denied Traffic | `Firewall/PaloAlto/LOW_policy_violation_denied_traffic.md` |

### Fortinet
| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | IPS Botnet Detection | `Firewall/Fortinet/CRITICAL_ips_botnet_detected.md` |
| HIGH | SQL Injection Attempt | `Firewall/Fortinet/HIGH_sql_injection_attempt.md` |
| MEDIUM | Network Anomaly Detection | `Firewall/Fortinet/MEDIUM_anomaly_detection.md` |
| LOW | Geographic Location Policy Violation | `Firewall/Fortinet/LOW_geo_location_policy_violation.md` |

### Checkpoint
| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Threat Emulation Malware Detection | `Firewall/Checkpoint/CRITICAL_threat_emulation_malware.md` |
| HIGH | IPS Critical Attack Prevention | `Firewall/Checkpoint/HIGH_ips_critical_attack.md` |
| MEDIUM | Anti-Bot Detection | `Firewall/Checkpoint/MEDIUM_anti_bot_detection.md` |

---

## Cloud Security

### AWS
| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | GuardDuty Cryptocurrency Mining | `Cloud/AWS/CRITICAL_guardduty_cryptocurrency_mining.md` |
| CRITICAL | Lambda Function Backdoor/Persistence | `Cloud/AWS/CRITICAL_lambda_backdoor_persistence.md` |
| HIGH | Root Account Usage Detection | `Cloud/AWS/HIGH_root_account_usage.md` |
| HIGH | Secrets Manager Secret Access Spike | `Cloud/AWS/HIGH_secrets_manager_secret_access.md` |
| MEDIUM | S3 Bucket Public Exposure | `Cloud/AWS/MEDIUM_s3_public_bucket_exposure.md` |
| LOW | Security Group Configuration Changes | `Cloud/AWS/LOW_security_group_changes.md` |

### Azure
| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Admin Consent Granted to Application | `Cloud/Azure/CRITICAL_admin_consent_granted.md` |
| HIGH | Global Administrator Role Assigned | `Cloud/Azure/HIGH_global_admin_role_assigned.md` |
| HIGH | Service Principal Credential Added | `Cloud/Azure/HIGH_service_principal_credential_added.md` |
| MEDIUM | Multiple Failed MFA Challenges | `Cloud/Azure/MEDIUM_failed_mfa_challenges.md` |
| LOW | Conditional Access Policy Changes | `Cloud/Azure/LOW_conditional_access_policy_changes.md` |

### Google Cloud Platform
| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Service Account Key Created | `Cloud/GCP/CRITICAL_service_account_key_created.md` |
| CRITICAL | Compute Instance with External IP | `Cloud/GCP/CRITICAL_compute_instance_external_ip.md` |
| HIGH | IAM Policy Modification | `Cloud/GCP/HIGH_iam_policy_modification.md` |
| MEDIUM | VPC Firewall Rule Changes | `Cloud/GCP/MEDIUM_firewall_rule_changes.md` |

---

## Threat Intelligence

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | IOC Match with Known Malware | `ThreatIntelligence/CRITICAL_ioc_match_known_malware.md` |
| HIGH | APT Infrastructure Communication | `ThreatIntelligence/HIGH_apt_infrastructure_communication.md` |
| HIGH | TOR/VPN/Anonymization Network Usage | `ThreatIntelligence/HIGH_tor_vpn_anonymization_usage.md` |
| MEDIUM | Access to Newly Registered Domains | `ThreatIntelligence/MEDIUM_newly_registered_domain_access.md` |

---

## Identity & Access Management

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Multiple Failed Logins Followed by Success | `IAM/CRITICAL_multiple_failed_logins_followed_by_success.md` |
| HIGH | Privileged Account Login Outside Business Hours | `IAM/HIGH_privileged_account_login_outside_hours.md` |
| MEDIUM | Password Spray Attack Detection | `IAM/MEDIUM_password_spray_attack.md` |

---

## Impossible Travel

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Impossible Travel Detected | `ImpossibleTravel/CRITICAL_impossible_travel_detected.md` |
| HIGH | Concurrent Sessions from Different Countries | `ImpossibleTravel/HIGH_concurrent_sessions_different_countries.md` |

---

## Insider Threat

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Mass Data Exfiltration | `InsiderThreat/CRITICAL_mass_data_exfiltration.md` |
| HIGH | Sensitive Data Access Before Resignation | `InsiderThreat/HIGH_access_to_sensitive_data_before_resignation.md` |

---

## Web Application Firewall

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Web Shell Upload Attempt | `WAF/CRITICAL_web_shell_upload_attempt.md` |
| HIGH | Multiple OWASP Top 10 Violations | `WAF/HIGH_multiple_owasp_violations.md` |

---

## Endpoint Detection & Response

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Ransomware Indicators Detected | `EDR/CRITICAL_ransomware_indicators.md` |
| HIGH | Credential Dumping Detected | `EDR/HIGH_credential_dumping_detected.md` |

---

## Email Security

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Business Email Compromise (BEC) | `EmailSecurity/CRITICAL_business_email_compromise.md` |

---

## Network Security

| Severity | Use Case | File |
|----------|----------|------|
| HIGH | DNS Tunneling Detection | `Network/HIGH_dns_tunneling_detected.md` |

---

## Correlation Rules

| Severity | Use Case | File |
|----------|----------|------|
| CRITICAL | Kill Chain Lateral Movement | `Correlation/CRITICAL_killchain_lateral_movement.md` |

---

## Data Loss Prevention

| Severity | Use Case | File |
|----------|----------|------|
| HIGH | Sensitive Data Upload to Personal Cloud Storage | `DLP/HIGH_sensitive_data_upload_to_cloud.md` |

---

## Statistics

### By Severity
- **CRITICAL**: 18 use cases
- **HIGH**: 16 use cases
- **MEDIUM**: 7 use cases
- **LOW**: 2 use cases

**Total**: 43 production-ready use cases

### By Category
- **Firewall**: 11 use cases (Palo Alto: 4, Fortinet: 4, Checkpoint: 3)
- **Cloud**: 17 use cases (AWS: 6, Azure: 5, GCP: 4)
- **Threat Intelligence**: 4 use cases (NEW!)
- **IAM**: 3 use cases
- **Impossible Travel**: 2 use cases
- **Insider Threat**: 2 use cases
- **WAF**: 2 use cases
- **EDR**: 2 use cases
- **Email Security**: 1 use case
- **Network**: 1 use case
- **Correlation**: 1 use case
- **DLP**: 1 use case

---

## Recent Additions (v1.1.0)

### Threat Intelligence (NEW Category!)
- IOC Match with Known Malware (CRITICAL)
- APT Infrastructure Communication (HIGH)
- TOR/VPN/Anonymization Usage (HIGH)
- Newly Registered Domain Access (MEDIUM)

### Expanded Cloud Coverage
- **AWS**: Lambda Backdoor, Secrets Manager Access
- **Azure**: Service Principal Credential Addition
- **GCP**: Compute Instance External IP

---

## How to Use This Index

1. **By Threat Severity**: Start with CRITICAL and HIGH severity use cases for immediate security wins
2. **By Category**: Navigate to your technology stack (AWS, Azure, Palo Alto, etc.)
3. **By Use Case**: Search for specific threats (ransomware, BEC, credential dumping, etc.)
4. **New Category**: Leverage Threat Intelligence for proactive defense

## Implementation Priority

### Phase 1 - Critical Threats (Week 1-2)
Focus on CRITICAL severity use cases:
- Ransomware indicators
- Malware detection (WildFire, Threat Emulation, IOC matching)
- Business Email Compromise
- Impossible Travel
- Mass Data Exfiltration
- Kill Chain Lateral Movement
- Lambda/Function backdoors
- APT infrastructure communication

### Phase 2 - High Impact (Week 3-4)
Implement HIGH severity use cases:
- Credential dumping
- Root/privileged account monitoring
- SQL injection and exploit attempts
- DNS tunneling
- Data upload to cloud
- Secrets access anomalies
- TOR/Anonymization detection
- Service principal abuse

### Phase 3 - Comprehensive Coverage (Month 2)
Deploy MEDIUM and LOW severity use cases:
- Policy violations
- Configuration changes
- Anomaly detection
- Compliance monitoring
- Newly registered domains

### Phase 4 - Threat Intelligence Integration (Month 2-3)
Integrate threat intelligence feeds:
- Configure IOC feeds
- Implement APT tracking
- Enable domain reputation checking
- Set up anonymization network blocking

## Additional Resources

- **Main README**: `/README.md` - Overview and usage instructions
- **CONTRIBUTING**: `/CONTRIBUTING.md` - How to add new use cases
- **MITRE ATT&CK Mapping**: Each use case includes relevant tactics and techniques
- **Tuning Guidance**: False positive considerations and tuning recommendations in each file
- **Response Playbooks**: Step-by-step incident response procedures

## Threat Intelligence Integration

The new Threat Intelligence category enables:
- **Proactive Defense**: Block known threats before they cause damage
- **IOC Matching**: Correlate with malicious IP, domain, hash databases
- **APT Detection**: Identify sophisticated threat actor infrastructure
- **Behavioral Analytics**: Detect anomalous anonymization network usage
- **Early Warning**: Catch phishing domains before they're widely known

### Recommended TI Feeds
- Commercial: Recorded Future, Anomali, CrowdStrike
- Open Source: AlienVault OTX, MISP, Abuse.ch
- Government: CISA, US-CERT, NCSC
- Community: ISACs, industry sharing groups

## Cloud Security Enhancements

Expanded cloud coverage now includes:
- **Serverless Security**: Lambda/Functions abuse detection
- **Secrets Management**: Credential access monitoring
- **Network Exposure**: External IP tracking
- **Identity Management**: Service principal and IAM monitoring
- **Multi-Cloud**: Comprehensive AWS, Azure, GCP coverage

## Contributing

To add new use cases:
1. Follow the established format in existing files
2. Include all required sections (Description, DEVO Query, Response Playbook, etc.)
3. Map to MITRE ATT&CK framework
4. Provide tuning recommendations
5. Update this INDEX.md file

## Version Control

- v1.0.0 - Initial release with 32 use cases
- v1.1.0 - Added Threat Intelligence (4 use cases) + Expanded Cloud (7 use cases)
- Repository: https://github.com/Masriyan/DevoSIEM_UCL

---

## Support

For questions, issues, or contributions:
- GitHub Issues: https://github.com/Masriyan/DevoSIEM_UCL/issues
- Author: Masriyan

## License

MIT License - See LICENSE file for details
