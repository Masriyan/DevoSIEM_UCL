# DLP - Sensitive Data Upload to Personal Cloud Storage

## Severity
**HIGH**

## Description
Detects when sensitive or confidential data is uploaded to personal cloud storage services (Dropbox, Google Drive personal, OneDrive personal), indicating potential data exfiltration or policy violation.

## MITRE ATT&CK
- **Tactic**: Exfiltration (TA0010)
- **Technique**: Exfiltration to Cloud Storage (T1567.002)

## DEVO Query

```sql
from dlp.events
select eventdate
select username
select srcip
select destination_url
select application
select filename
select file_size
select file_hash
select data_classification
select dlp_policy_matched
select content_categories
select count() as files_uploaded
select sum(file_size) as total_bytes_uploaded
select mm2country(srcip) as src_country
where (`in`("upload", "file_upload", "cloud_upload", action)
  and (`in`("Dropbox", "Google Drive", "OneDrive Personal", "Box", "iCloud", "WeTransfer", "Mega", application)
    or weakhas(url, "dropbox.com") or weakhas(url, "drive.google.com")
    or weakhas(url, "onedrive.live.com") or weakhas(url, "wetransfer.com")
    or weakhas(url, "mega.nz") or weakhas(url, "mediafire.com"))
  and (`in`("confidential", "secret", "restricted", "pii", "phi", "pci", data_classification)
    or weakhas(content_type, "financial")
    or weakhas(content_type, "customer")
    or weakhas(filename, "confidential")
    or dlp_policy_matched is not null))

having files_uploaded > 0
```

## Alert Configuration
- **Trigger**: Any sensitive data upload to personal cloud storage
- **Throttling**: 1 alert per user per 30 minutes
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Contact user immediately to verify upload
2. Review uploaded file content and classification
3. Request user to delete from personal cloud
4. Check user's account access to cloud service
5. Review user's recent activities
6. Assess potential data exposure
7. Block personal cloud services if not approved
8. Document business justification if legitimate
9. Review DLP policy effectiveness
10. Escalate to HR/Legal if policy violation

## False Positive Considerations
- Approved business use of cloud storage
- BYOD policies allowing personal accounts
- Legitimate file sharing for collaboration
- Approved cloud services for specific departments

**Tuning Recommendations**:
- Whitelist approved cloud services/accounts
- Exclude corporate-managed cloud storage
- Document approved use cases
- Adjust classification sensitivity
- Filter false DLP pattern matches

## Enrichment Opportunities
- Check user's HR status (departure, discipline)
- Review historical cloud usage patterns
- Verify file classification accuracy
- Check for concurrent suspicious activities
- Review user's data access history
- Correlate with VPN/remote access
- Check for email of same files

## Response Playbook
1. **Immediate Assessment**:
   - What data was uploaded?
   - Verify data classification
   - Is cloud service approved?
   - Business justification?
2. **User Contact**:
   - Call user (do not email)
   - Verify upload was intentional
   - Explain policy if violation
   - Request deletion if unauthorized
3. **Risk Assessment**:
   - Data sensitivity level
   - Potential exposure
   - Regulatory implications
   - Business impact
4. **For Policy Violations**:
   - Document incident
   - Notify manager
   - HR involvement
   - Potential disciplinary action
   - Legal review if serious
5. **For Legitimate Use**:
   - Document approval
   - Update policy/whitelist
   - Monitor for patterns
   - User education

## Investigation Steps
- Identify exact files uploaded
- Verify data classification
- Review file content (if accessible)
- Check cloud service account ownership
- Review upload timing and frequency
- Check for systematic uploading
- Verify user's data access authorization
- Review other exfiltration methods
- Check for concurrent red flags

## Data Classification Levels

**Critical/Secret**:
- Trade secrets
- M&A information
- Unreleased financials
- Source code
- Strategic plans

**Confidential/Restricted**:
- Customer PII
- Employee data
- Financial records
- Proprietary research
- Internal communications

**Internal**:
- Business documents
- Process documentation
- Non-public information

**Public**:
- Marketing materials
- Published information

## Cloud Storage Services

**Personal Accounts** (High Risk):
- Dropbox personal
- Google Drive personal
- OneDrive personal (non-corporate)
- iCloud
- Mega
- MediaFire
- WeTransfer

**Corporate Accounts** (Managed):
- Microsoft OneDrive for Business
- Google Workspace Drive
- Dropbox Business
- Box Enterprise

## DLP Policy Patterns
- Credit card numbers (PCI)
- Social security numbers
- Bank account numbers
- Health records (PHI/HIPAA)
- Passport numbers
- API keys/credentials
- Proprietary keywords
- Customer databases
- Financial data
- Source code patterns

## High-Risk Scenarios
Escalate to CRITICAL if:
- Departing employee
- Large volume uploads
- After-hours uploads
- Trade secrets or IP
- Customer database
- Financial records
- Competitive intelligence
- Multiple cloud services
- Encryption before upload
- VPN to hide location

## User Behavior Patterns

**Insider Threat Indicators**:
- Systematic data collection
- Access to unrelated data
- After-hours uploads
- Using VPN/proxy
- Multiple cloud services
- Encrypting before upload
- Deleting local copies
- Resignation submitted

**Legitimate Use**:
- Business collaboration
- Approved file sharing
- Work from home
- Vendor collaboration
- Approved backup

## Prevention Measures
- Block personal cloud services
- CASB (Cloud Access Security Broker)
- DLP with cloud integration
- Application control
- DNS filtering
- Proxy blocking
- User awareness training
- Clear acceptable use policy
- Approved cloud service alternatives
- Data classification program

## Cloud Service Blocking
Options:
- DNS blocking
- Proxy/firewall blocking
- Application control
- CASB enforcement
- Network segmentation
- Conditional access

## Enhanced Detection
```sql
-- Detect multiple cloud services by same user
from dlp.events
where action = "upload"
select
  username,
  countdistinct(application) as unique_cloud_services,
  sum(file_size) as total_uploaded,
  count() as upload_count
group by username
every 1d
having unique_cloud_services >= 3
```

## Approved Cloud Usage Policy
Document:
- Approved cloud services
- Data classification allowed
- Approval process
- Monitoring/logging
- Retention requirements
- Compliance requirements
- Encryption requirements
- Access controls

## DLP Tuning
- Validate classification accuracy
- Reduce false positive patterns
- Update content inspection
- Train ML models
- Regular policy review
- User feedback integration
- Whitelist legitimate flows

## Regulatory Considerations
- GDPR: Personal data protection
- HIPAA: PHI security
- PCI-DSS: Cardholder data
- SOX: Financial data
- May require breach notification
- Document all incidents

## User Education
- Approved cloud services
- Data classification
- Policy compliance
- Reporting procedures
- Consequences of violations
- Secure alternatives

## Forensic Artifacts
- DLP event logs
- Proxy/firewall logs
- CASB logs
- File metadata
- Upload timestamps
- User authentication
- Email logs (if shared)

## Business Impact
- Data exposure risk
- Regulatory penalties
- Competitive disadvantage
- Reputation damage
- Customer trust loss
- Legal liability

## Notes
- Cloud upload is common exfiltration method
- Often legitimate business use
- Context is critical
- Balance security with productivity
- Clear policies essential
- User training is key
