# Insider Threat - Mass Data Exfiltration

## Severity
**CRITICAL**

## Description
Detects large-scale data downloads or transfers by internal users, which may indicate insider threat, data theft, or preparation for departure.

## MITRE ATT&CK
- **Tactic**: Collection (TA0009), Exfiltration (TA0010)
- **Technique**: Data from Network Shared Drive (T1039), Exfiltration Over Web Service (T1567), Data Transfer Size Limits (T1030)

## DEVO Query

```sql
from siem.dataaccess, cloud.storage.access, dlp.events
where action in ("download", "export", "copy", "sync", "transfer")
  and result = "success"
select
  eventdate,
  username,
  srcip,
  filename,
  filepath,
  filesize,
  destination,
  application,
  dataclassification,
  sum(filesize) as total_bytes,
  count() as file_count,
  countdistinct(filepath) as unique_paths,
  countdistinct(destination) as unique_destinations
group by username
every 1h
having total_bytes > 10737418240  -- 10 GB
  or file_count > 1000
  or unique_paths > 100
```

## Alert Configuration
- **Trigger**: > 10 GB downloaded OR > 1000 files OR > 100 different folders in 1 hour
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Suspend user account
2. Block user's network access
3. Contact user's manager immediately
4. Review all data accessed/downloaded
5. Check data classification and sensitivity
6. Review transfer destinations (cloud storage, USB, email)
7. Collect forensic evidence
8. Check for data deletion after download
9. Review user's recent activities and communications
10. Coordinate with HR and Legal
11. Preserve all logs and evidence
12. Check for accomplices or similar patterns

## False Positive Considerations
- Legitimate bulk data migrations
- Backup operations
- Analytics/reporting workflows
- Software deployments
- Approved data science projects
- System administrators performing maintenance

**Tuning Recommendations**:
- Whitelist approved bulk transfer accounts
- Exclude backup service accounts
- Adjust thresholds based on user roles
- Document approved large transfers
- Require change management for bulk operations
- Consider user's normal data access patterns

## Enrichment Opportunities
- Check user's HR status (resignation, termination notice?)
- Review recent performance issues
- Check access to sensitive projects
- Correlate with USB usage
- Review email for file attachments
- Check cloud storage uploads (Dropbox, OneDrive personal)
- Analyze printing activities
- Review VPN usage patterns

## Response Playbook
1. **Immediate Containment**:
   - Suspend user account
   - Block network access
   - Disable VPN access
   - Revoke cloud app access
   - Collect computer if on-site
2. **Notification**:
   - Alert security leadership
   - Notify HR department
   - Contact Legal team
   - Inform user's manager
   - Consider law enforcement
3. **Investigation**:
   - Full forensic analysis
   - Review all data accessed (30-90 days)
   - Check email/chat for evidence
   - Analyze file types downloaded
   - Verify data classification
   - Check for external collaborators
   - Review badge access/physical security
   - Check personal device connections
4. **Evidence Preservation**:
   - Preserve all logs
   - Image user's workstation
   - Capture network traffic
   - Save cloud activity logs
   - Document timeline
   - Chain of custody
5. **Follow-up**:
   - Assess damage and exposure
   - Data recovery if deleted
   - Update DLP policies
   - Employee termination procedures
   - Legal action if warranted
   - Lessons learned review

## Investigation Steps
- Map exactly what data was accessed
- Identify data sensitivity/classification
- Determine transfer destinations
- Review timeline of activities
- Check for reconnaissance (searching, browsing)
- Analyze after-hours activity
- Review user's access history
- Check for systematic collection
- Look for data staging areas
- Verify if data was encrypted/compressed

## High-Risk Indicators
Escalate urgency if:
- **Employee under review**: Performance issues, disciplinary action
- **Resignation notice**: Active or pending
- **Access to trade secrets**: IP, customer data, financial data
- **Unusual timing**: After hours, weekends
- **External destinations**: Personal cloud, personal email
- **Data deletion**: Covering tracks
- **Compression/encryption**: Preparing for transfer
- **Multiple methods**: USB + cloud + email
- **Privileged access**: Admin accounts, elevated permissions
- **Competitive intelligence**: Accessing competitor-related data

## Data Categories to Flag
- **Intellectual Property**: Source code, patents, designs
- **Customer Data**: PII, contact lists, sales data
- **Financial Data**: Revenue, forecasts, pricing
- **Strategic Plans**: M&A, business strategies
- **Credentials**: Passwords, API keys, certificates
- **Proprietary Research**: R&D data, formulas
- **Employee Data**: HR records, salaries

## Common Exfiltration Methods
- Email attachments to personal accounts
- Cloud storage (Dropbox, Google Drive, OneDrive personal)
- USB drives
- Mobile devices
- FTP/SFTP transfers
- Screen captures/photos
- Printing
- Code repositories (GitHub personal)
- Instant messaging file transfers
- External hard drives

## Behavioral Patterns
Insider threat often shows:
- Gradual increase in data access
- Access to non-job-related data
- After-hours abnormal activity
- Downloading documentation/processes
- Accessing HR/personnel data
- Collecting competitive intelligence
- Using personal accounts/devices
- Attempting to cover tracks

## Enhanced Detection
```sql
-- Detect systematic folder enumeration before download
from siem.fileaccess
where action in ("list", "enumerate", "search")
select
  username,
  count() as enumeration_count,
  countdistinct(filepath) as folders_searched
group by username
every 1h
having folders_searched > 50 and enumeration_count > 200
```

## Forensic Artifacts to Collect
- Full activity logs (30-90 days)
- Email archives
- Chat/IM logs
- Browser history
- Cloud service logs
- VPN logs
- USB device history
- Printing logs
- Badge access records
- Workstation forensic image
- Mobile device logs (if corporate)

## Legal Considerations
- Consult legal before investigation
- Follow corporate policies
- Maintain chain of custody
- Document everything
- Privacy laws compliance
- Termination procedures
- Non-compete/NDA enforcement
- Potential criminal charges
- Civil litigation preparation

## Prevention Measures
- Data Loss Prevention (DLP) tools
- User behavior analytics (UBA)
- Insider threat program
- Regular access reviews
- Least privilege principle
- Data classification
- Egress filtering
- USB device controls
- Email monitoring
- Cloud access security broker (CASB)
- Exit interview processes
- Employee monitoring disclosure
- Security awareness training

## HR/Legal Coordination
- HR involvement for personnel action
- Legal for evidence handling
- Document all communications
- Follow termination procedures
- Secure departing employee access
- Exit interview questions
- Non-disclosure reminders
- Return of company property
- Post-employment restrictions

## Notes
- Insider threats cause massive damage
- Often undetected until too late
- Requires multi-departmental response
- Legal implications are significant
- Prevention is key
- Document everything meticulously
