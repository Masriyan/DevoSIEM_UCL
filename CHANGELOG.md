# Changelog

All notable changes to the DEVO SIEM Use Case Library will be documented in this file.

## [v1.2.0] - 2024-12-23

### 🎉 Major Update: Official DEVO LINQ Syntax

#### ✅ Query Syntax Overhaul
- **Updated all 45 queries** to use official DEVO LINQ syntax
- Converted from generic SQL to production-ready DEVO queries
- Added DEVO-specific functions throughout

#### 🔧 DEVO LINQ Features Implemented
- **Multiple SELECT statements** - One statement per field (DEVO standard)
- **weakhas() function** - Flexible string matching for better detection
- **Geographic enrichment** - `mm2country()` and `mm2city()` for all IP fields
- **IP classification** - `purpose()` function to identify IP types
- **Backtick list operations** - `` `in`() `` for proper list membership
- **Field naming** - Updated to use `srcaddr`/`dstaddr` where applicable

#### 📚 Documentation Enhancements
- **DEVO_QUERY_SYNTAX_GUIDE.md** - Comprehensive DEVO LINQ reference
- **SYNTAX_ANALYSIS_REPORT.md** - Detailed migration analysis
- **README.md** - Updated with query syntax status
- **CONTRIBUTING.md** - Added DEVO query examples and templates
- **INDEX.md** - Added syntax readiness notes

#### 🎯 Categories Updated (45 files)
- ✅ **Firewall** (11): Palo Alto (4), Fortinet (4), Checkpoint (3)
- ✅ **Cloud** (15): AWS (6), Azure (5), GCP (4)
- ✅ **Threat Intelligence** (4): IOC matching, APT, TOR/VPN, domains
- ✅ **IAM** (3): Brute force, privilege escalation, password spray
- ✅ **Impossible Travel** (2): Geographic anomaly detection
- ✅ **Insider Threat** (2): Data exfiltration, sensitive access
- ✅ **WAF** (2): Web shell, OWASP violations
- ✅ **EDR** (2): Ransomware, credential dumping
- ✅ **Email Security** (1): BEC detection
- ✅ **Network** (1): DNS tunneling
- ✅ **Correlation** (1): Kill chain lateral movement
- ✅ **DLP** (1): Cloud storage uploads

#### 🔍 Query Improvements
**Before:**
```sql
from firewall.traffic
where action in ("allow", "permit")
select
  srcip,
  dstip,
  application
```

**After:**
```sql
from firewall.traffic
select eventdate
select srcaddr
select dstaddr
select application
select mm2country(srcaddr) as src_country
select mm2country(dstaddr) as dst_country
select purpose(srcaddr) as src_purpose
where `in`("allow", "permit", action)
```

#### ⚠️ Breaking Changes
- **Field names**: Queries now use `srcaddr`/`dstaddr` instead of `srcip`/`dstip`
- **Syntax structure**: Multiple SELECT statements required (DEVO LINQ standard)
- **Function usage**: Must have DEVO functions available (`weakhas`, `mm2country`, `purpose`)

#### 📝 Migration Notes
- All queries are now **production-ready** for DEVO SIEM
- Verify **table names** exist in your DEVO environment before deployment
- Test queries with **small time windows** first (5-10 minutes)
- Adjust **thresholds** based on your environment baseline
- See **DEVO_QUERY_SYNTAX_GUIDE.md** for detailed migration guidance

---

## [v1.1.0] - 2024-12-22

### Added
- **Threat Intelligence category** (4 new use cases)
  - IOC Match with Known Malware (CRITICAL)
  - APT Infrastructure Communication (HIGH)
  - TOR/VPN/Anonymization Network Usage (HIGH)
  - Newly Registered Domain Access (MEDIUM)

### Expanded
- **Cloud coverage** (7 new use cases)
  - AWS: Lambda Backdoor Detection, Secrets Manager Monitoring
  - Azure: Service Principal Credential Tracking
  - GCP: External IP Exposure Detection

### Improved
- Enhanced cloud security detection capabilities
- Added threat intelligence integration guidance
- Expanded MITRE ATT&CK coverage

### Statistics
- Total use cases: 43 → 45
- Categories: 11 → 13
- CRITICAL severity: 16 → 18
- HIGH severity: 15 → 17

---

## [v1.0.0] - 2024-12-20

### Initial Release
- **32 production-ready use cases** across 11 categories
- Comprehensive MITRE ATT&CK mappings
- Detailed response playbooks
- Tuning recommendations
- Implementation roadmap

### Categories
- Firewall (11): Palo Alto, Fortinet, Checkpoint
- Cloud (11): AWS, Azure, GCP
- IAM (3): Authentication and access control
- Impossible Travel (2): Geographic anomaly detection
- Insider Threat (2): Data exfiltration and abuse
- WAF (2): Web application attacks
- EDR (2): Endpoint threats
- Email Security (1): BEC and phishing
- Network (1): DNS tunneling
- DLP (1): Data loss prevention

### Features
- LINQ query templates
- Alert configuration guidance
- False positive tuning
- Investigation procedures
- Prevention measures

---

## Version Comparison

| Version | Use Cases | Categories | Query Syntax | Key Features |
|---------|-----------|------------|--------------|--------------|
| v1.2.0 | 45 | 13 | ✅ Official DEVO LINQ | Production-ready queries |
| v1.1.0 | 43 | 13 | ⚠️ Generic templates | Added Threat Intel |
| v1.0.0 | 32 | 11 | ⚠️ Generic templates | Initial release |

---

## Upgrade Path

### From v1.1.0 to v1.2.0
1. **All queries updated** - No manual conversion needed
2. **Verify table names** in your DEVO environment
3. **Test queries** with small time windows
4. **Deploy** to production after validation

### From v1.0.0 to v1.2.0
1. **Review new categories** - Threat Intelligence added
2. **All queries updated** to DEVO LINQ syntax
3. **Follow implementation roadmap** for deployment priority
4. **Consult DEVO_QUERY_SYNTAX_GUIDE.md** for syntax reference

---

## Contributors
- **Masriyan** - Creator and maintainer
- Community contributors - Issue reports and feedback

## Support
- GitHub Issues: https://github.com/Masriyan/DevoSIEM_UCL/issues
- Discussions: https://github.com/Masriyan/DevoSIEM_UCL/discussions

## License
MIT License - See LICENSE file for details
