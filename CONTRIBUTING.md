# Contributing to DEVO SIEM Use Case Library

Thank you for your interest in contributing to this library! This document provides guidelines for adding new use cases and improving existing ones.

## Use Case Template

Each use case should follow this standard format:

```markdown
# [Category] - [Use Case Name]

## Severity
**[CRITICAL|HIGH|MEDIUM|LOW]**

## Description
[Clear, concise description of what this rule detects and why it matters]

## MITRE ATT&CK
- **Tactic**: [Tactic Name] ([Tactic ID])
- **Technique**: [Technique Name] ([Technique ID])

## DEVO Query
```sql
[DEVO LINQ query that implements the detection]
```

## Alert Configuration
- **Trigger**: [Conditions that trigger the alert]
- **Throttling**: [Alert throttling/deduplication strategy]
- **Severity**: [Alert severity level]
- **Priority**: [Incident priority]

## Recommended Actions
1. [Immediate action items]
2. [Investigation steps]
3. [Containment measures]
4. [Remediation steps]

## False Positive Considerations
[Common scenarios that may cause false positives]

**Tuning Recommendations**:
- [How to reduce false positives]
- [Whitelisting guidance]
- [Threshold adjustments]

## Enrichment Opportunities
[Additional data sources or context to correlate]

## Response Playbook
[Detailed step-by-step incident response procedures]

## Investigation Steps
[Forensic and investigation guidance]

## Prevention Measures
[Security controls to prevent this threat]

## Notes
[Additional context, tips, or considerations]
```

## File Naming Convention

Use this pattern: `SEVERITY_short_descriptive_name.md`

Examples:
- `CRITICAL_ransomware_indicators.md`
- `HIGH_credential_dumping_detected.md`
- `MEDIUM_unusual_login_pattern.md`
- `LOW_policy_violation.md`

## Severity Guidelines

### CRITICAL
- Immediate threat to confidentiality, integrity, or availability
- Active exploitation or compromise
- Requires immediate response (within minutes)
- Examples: Ransomware, data exfiltration, malware execution

### HIGH
- Serious security concern requiring prompt investigation
- Potential compromise or significant policy violation
- Response within hours
- Examples: Privilege escalation, credential theft, exploit attempts

### MEDIUM
- Notable security event requiring attention
- Suspicious activity or policy violations
- Response within 24 hours
- Examples: Password sprays, anomalies, failed attacks

### LOW
- Informational alerts for monitoring and compliance
- Baseline deviations or minor policy violations
- Review periodically or aggregated
- Examples: Configuration changes, denied traffic, compliance monitoring

## DEVO Query Requirements

1. **Syntax**: Use official DEVO LINQ syntax (see examples below)
2. **Performance**: Optimize for large-scale data processing
3. **Structure**: Multiple SELECT statements, one per field/expression
4. **Functions**: Use DEVO-specific functions (`weakhas()`, `mm2country()`, `purpose()`, `` `in`() ``)
5. **Enrichment**: Include geographic and IP classification where applicable
6. **Testing**: Verify query runs without errors in your DEVO environment

### DEVO LINQ Syntax Example:

```sql
from siem.logins
select eventdate
select username
select srcaddr
select mm2country(srcaddr) as src_country
select mm2city(srcaddr) as src_city
select count() as failed_attempts
where `in`("failed", "failure", result)
  and not weakhas(username, "service_account")
group by username, srcaddr
every 10m
having failed_attempts >= 5
```

### Key DEVO Syntax Elements:

**Multiple SELECT Statements:**
```sql
select eventdate
select srcaddr
select dstaddr
select mm2country(dstaddr) as dst_country
```

**DEVO-Specific Functions:**
```sql
-- Flexible string matching
where weakhas(action, "ACCEPT")

-- Geographic enrichment
select mm2country(srcaddr) as src_country
select mm2city(dstaddr) as dst_city

-- IP classification
select purpose(srcaddr) as src_purpose

-- List membership (note backticks)
where `in`("value1", "value2", "value3", field_name)
```

**Field Naming:**
- Use `srcaddr`/`dstaddr` for IP addresses (not `srcip`/`dstip`)
- Cloud-specific fields keep their names (e.g., `userIdentity.arn`, `eventSource`)

### Complete Query Template:

```sql
from [data.source.table]
select eventdate
select srcaddr
select dstaddr
select [other_fields]
select mm2country(srcaddr) as src_country
select mm2country(dstaddr) as dst_country
select purpose(srcaddr) as src_purpose
select purpose(dstaddr) as dst_purpose
where weakhas([field], "pattern")
  and `in`("value1", "value2", [field])
  and [condition] >= [threshold]
group by [field1], [field2]
every [time_window]
having [aggregate_condition]
```

## MITRE ATT&CK Mapping

Always include:
- **Tactic**: High-level adversary goal
- **Technique**: Specific method used
- **Sub-technique**: If applicable

Reference: https://attack.mitre.org/

## Response Playbook Structure

Include these sections:
1. **Immediate Actions** (0-15 min)
2. **Assessment** (15-60 min)
3. **Containment** (1-4 hours)
4. **Investigation** (4-24 hours)
5. **Eradication** (varies)
6. **Recovery** (varies)
7. **Lessons Learned** (post-incident)

## Required Sections

Every use case MUST include:
- ✅ Description
- ✅ Severity
- ✅ MITRE ATT&CK mapping
- ✅ DEVO Query
- ✅ Alert Configuration
- ✅ Recommended Actions
- ✅ False Positive Considerations
- ✅ Response Playbook

## Optional but Recommended Sections

- Investigation Steps
- Prevention Measures
- Enhanced Detection (additional queries)
- Forensic Artifacts
- Compliance Impact
- Integration Points
- Automation Opportunities
- Notes

## Categories

Place your use case in the appropriate category:

### Existing Categories
- `Firewall/` - Firewall vendor-specific rules
  - `PaloAlto/` (4 use cases)
  - `Fortinet/` (4 use cases)
  - `Checkpoint/` (3 use cases)
- `Cloud/` - Cloud platform security
  - `AWS/` (6 use cases)
  - `Azure/` (5 use cases)
  - `GCP/` (4 use cases)
- `ThreatIntelligence/` - Threat intelligence and IOC matching (4 use cases) 🆕
- `IAM/` - Identity and authentication (3 use cases)
- `ImpossibleTravel/` - Geographic anomalies (2 use cases)
- `InsiderThreat/` - Insider threat detection (2 use cases)
- `WAF/` - Web application firewall (2 use cases)
- `EDR/` - Endpoint detection (2 use cases)
- `EmailSecurity/` - Email threats (1 use case)
- `Network/` - Network security (1 use case)
- `Correlation/` - Multi-source correlation (1 use case)
- `DLP/` - Data loss prevention (1 use case)
- `WebProxy/` - Web proxy logs
- `DNS/` - DNS security

### Adding New Categories
If you need a new category:
1. Create the folder: `mkdir -p NewCategory`
2. Update `README.md` structure section
3. Update `INDEX.md` with new category

## Pull Request Process

1. **Fork** the repository
2. **Create a branch**: `git checkout -b new-use-case-name`
3. **Add your use case** following the template
4. **Update INDEX.md** with your new use case
5. **Test** the DEVO query if possible
6. **Commit**: `git commit -m "Add: [Category] - [Use Case Name]"`
7. **Push**: `git push origin new-use-case-name`
8. **Create Pull Request** with description

## Pull Request Checklist

- [ ] Follows the template format
- [ ] Includes all required sections
- [ ] DEVO query is syntactically correct
- [ ] MITRE ATT&CK mapping is accurate
- [ ] File naming convention followed
- [ ] Placed in correct category folder
- [ ] INDEX.md updated
- [ ] No spelling/grammar errors
- [ ] Clear and actionable recommendations

## Quality Standards

### Good Use Case Characteristics
✅ **Specific**: Detects a well-defined threat
✅ **Actionable**: Clear response steps
✅ **Practical**: Can be implemented in production
✅ **Tested**: Query logic is validated
✅ **Documented**: Includes tuning and context
✅ **Maintainable**: Easy to understand and modify

### Avoid
❌ Generic, catch-all detections
❌ Untested or theoretical queries
❌ Missing context or tuning guidance
❌ Incomplete response procedures
❌ Overly complex without explanation

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Collaborate openly
- Share knowledge freely
- Credit sources appropriately

## Review Process

1. Maintainers review for:
   - Adherence to template
   - Query correctness
   - Completeness
   - Quality and clarity
2. Feedback provided within 7 days
3. Revisions may be requested
4. Approval and merge

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in the use case file
- Acknowledged in release notes

## Questions or Help?

- Open an issue for questions
- Tag maintainers for urgent matters
- Join discussions on existing issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Example Contributions

Great contributions:
- New detection use cases
- Improved DEVO queries
- Additional response playbooks
- Tuning recommendations
- Real-world examples
- Documentation improvements
- Bug fixes and corrections

## Resources

- [DEVO Documentation](https://docs.devo.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls)

Thank you for contributing to the DEVO SIEM Use Case Library!
