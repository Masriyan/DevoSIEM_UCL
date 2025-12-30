# SaaS Security - Shadow IT and Unauthorized SaaS Application Usage

## Severity
**HIGH**

## Description
Detects unauthorized Software-as-a-Service (SaaS) applications and shadow IT usage within the organization. Identifies employees using unapproved cloud services for file sharing, collaboration, communication, or data storage, which bypass security controls and create data exfiltration and compliance risks.

## MITRE ATT&CK
- **Tactic**: Exfiltration (TA0010), Command and Control (TA0011), Initial Access (TA0001)
- **Technique**: Exfiltration Over Web Service (T1567), Exfiltration to Cloud Storage (T1567.002), Web Service (T1102)

## DEVO Query

```sql
from network.proxy
select eventdate
select user
select src_ip
select dst_domain
select dst_category
select url
select http_method
select bytes_uploaded
select bytes_downloaded
select user_agent
select count() as access_count
select sum(bytes_uploaded) as total_uploaded
select sum(bytes_downloaded) as total_downloaded
select countdistinct(dst_domain) as unique_saas_domains
where (
    -- Unauthorized file sharing services
    weakhas(dst_domain, "wetransfer.com")
    or weakhas(dst_domain, "sendspace.com")
    or weakhas(dst_domain, "mega.nz")
    or weakhas(dst_domain, "mediafire.com")
    or weakhas(dst_domain, "rapidshare.com")
    or weakhas(dst_domain, "4shared.com")
    or weakhas(dst_domain, "uploadfiles.io")

    -- Personal cloud storage (if not approved)
    or weakhas(dst_domain, "dropbox.com")
       and not weakhas(dst_domain, "business.dropbox.com")
    or weakhas(dst_domain, "drive.google.com")
       and not `in`(approved_google_workspace_users, user)
    or weakhas(dst_domain, "onedrive.live.com")
       and not `in`(approved_onedrive_users, user)
    or weakhas(dst_domain, "icloud.com")
    or weakhas(dst_domain, "box.com")
       and not `in`(approved_box_users, user)
    or weakhas(dst_domain, "sync.com")
    or weakhas(dst_domain, "pcloud.com")

    -- Unapproved collaboration tools
    or weakhas(dst_domain, "slack.com")
       and not `in`(approved_slack_users, user)
    or weakhas(dst_domain, "discord.com")
    or weakhas(dst_domain, "telegram.org")
    or weakhas(dst_domain, "whatsapp.com")
    or weakhas(dst_domain, "signal.org")

    -- Code repositories (personal accounts)
    or weakhas(dst_domain, "github.com")
       and `in`("POST", "PUT", http_method)
       and not `in`(approved_github_users, user)
    or weakhas(dst_domain, "gitlab.com")
       and `in`("POST", "PUT", http_method)
    or weakhas(dst_domain, "bitbucket.org")
       and `in`("POST", "PUT", http_method)

    -- Productivity suites (personal)
    or weakhas(dst_domain, "notion.so")
    or weakhas(dst_domain, "evernote.com")
    or weakhas(dst_domain, "onenote.com")
       and not `in`(approved_microsoft365_users, user)

    -- Screenshot/screen recording tools
    or weakhas(dst_domain, "lightshot.com")
    or weakhas(dst_domain, "gyazo.com")
    or weakhas(dst_domain, "loom.com")

    -- Remote access tools (unauthorized)
    or weakhas(dst_domain, "teamviewer.com")
       and not `in`(approved_remote_access_users, user)
    or weakhas(dst_domain, "anydesk.com")
    or weakhas(dst_domain, "logmein.com")

    -- VPN/Proxy services (policy violation)
    or weakhas(dst_domain, "nordvpn.com")
    or weakhas(dst_domain, "expressvpn.com")
    or weakhas(dst_domain, "protonvpn.com")
    or weakhas(dst_domain, "tunnelbear.com")
  )
  and (
    -- Significant data upload (potential exfiltration)
    bytes_uploaded > 104857600  -- 100 MB
    or access_count > 50 in 1h
  )
group by user, dst_domain
every 30m
having total_uploaded > 104857600 or unique_saas_domains > 5
```

## OAuth Token Grant Detection

```sql
from saas.oauth
select eventdate
select user
select application_name
select application_id
select scopes_granted
select redirect_uri
select user_agent
select src_ip
select mm2country(src_ip) as oauth_grant_country
where (
    -- Broad permissions granted
    weakhas(scopes_granted, "full_access")
    or weakhas(scopes_granted, "read_write_all")
    or weakhas(scopes_granted, "admin")

    -- Sensitive data access
    or weakhas(scopes_granted, "contacts")
    or weakhas(scopes_granted, "email")
    or weakhas(scopes_granted, "calendar")
    or weakhas(scopes_granted, "drive")
    or weakhas(scopes_granted, "files")

    -- Unknown/suspicious applications
    or application_name not in (approved_oauth_applications)

    -- Suspicious redirect URIs
    or not (weakhas(redirect_uri, "https://")
            or weakhas(redirect_uri, ".company.com"))
  )
group by user, application_name
every 1h
```

## Browser Extension Monitoring

```sql
from edr.browser_extensions
select eventdate
select hostname
select user
select browser
select extension_id
select extension_name
select extension_permissions
select installation_source
where (
    -- High-risk permissions
    weakhas(extension_permissions, "webRequest")
    or weakhas(extension_permissions, "webRequestBlocking")
    or weakhas(extension_permissions, "proxy")
    or weakhas(extension_permissions, "cookies")
    or weakhas(extension_permissions, "tabs")
    or weakhas(extension_permissions, "activeTab")
    or weakhas(extension_permissions, "<all_urls>")

    -- Unknown extensions
    or extension_id not in (approved_extension_ids)

    -- Sideloaded extensions (not from official store)
    or installation_source != "chrome_web_store"
       and installation_source != "firefox_addons"
  )
group by user, extension_name
every 1h
```

## Alert Configuration
- **Trigger**:
  - Large data upload to unapproved SaaS (>100 MB)
  - Multiple unapproved SaaS applications accessed (>5 unique domains)
  - OAuth grant to unknown application
  - High-risk browser extension installed
- **Throttling**: 30 minute window, group by user and SaaS domain
- **Severity**: High
- **Priority**: P2
- **Enrichment**: User role, department, data classification

## Recommended Actions
1. Contact the user to understand business justification
2. Review what data was uploaded/shared
3. Assess data sensitivity and classification
4. Evaluate the SaaS application security posture
5. If business-critical, initiate SaaS application approval process
6. If policy violation, enforce acceptable use policy
7. Block unapproved SaaS at web proxy/firewall if necessary
8. Implement Cloud Access Security Broker (CASB) if not already deployed
9. Conduct security awareness training on shadow IT risks
10. Review and update approved SaaS application list
11. Implement Data Loss Prevention (DLP) policies
12. Enable OAuth consent policies (admin approval required)

## False Positive Considerations
- Approved business units using sanctioned SaaS applications
- Personal use during break times (if policy allows)
- IT/Security team testing new applications
- Marketing/Sales teams with legitimate external collaboration needs
- Remote workers using approved tools

**Tuning Recommendations**:
- Maintain approved SaaS application whitelist
- Baseline normal SaaS usage per department
- Exclude approved users/service accounts
- Allow small uploads (<10 MB) for personal use if policy permits
- Implement CASB with automated discovery and classification
- Create department-specific policies (Sales vs. Finance vs. Engineering)

## Enrichment Opportunities
- User's role and department (context for business need)
- Data classification of uploaded files (via DLP)
- SaaS application security rating (CASB, vendor assessment)
- Historical SaaS usage patterns for the user
- Peer comparison (is this common in their department?)
- Application reputation and reviews
- OAuth application publisher verification status
- Browser extension developer reputation

## Response Playbook

### Phase 1: Initial Triage (0-30 minutes)
1. **User Context Gathering**:
   ```bash
   # Who is the user?
   ldapsearch -x -b "dc=company,dc=com" "(sAMAccountName=<user>)" department title manager

   # What's their role and data access level?
   # HR system lookup
   ```

2. **Activity Analysis**:
   ```sql
   -- What data was uploaded?
   SELECT url, bytes_uploaded, timestamp
   FROM proxy_logs
   WHERE user = '<user>'
     AND dst_domain = '<saas-domain>'
     AND bytes_uploaded > 0
   ORDER BY timestamp DESC
   LIMIT 100;
   ```

3. **Business Justification**:
   - Contact user: "We noticed you used [SaaS app]. Can you explain the business need?"
   - Contact manager if user unavailable
   - Check for existing approval requests

### Phase 2: Risk Assessment (30 min - 2 hours)
1. **Data Sensitivity**:
   - What data was shared? (DLP classification)
   - Customer data? Financial? Intellectual property?
   - Compliance scope? (PCI, HIPAA, GDPR)

2. **SaaS Application Security Review**:
   ```
   ✓ Is the application SOC 2 certified?
   ✓ Data residency (where is data stored?)
   ✓ Encryption at rest and in transit?
   ✓ Access controls and authentication?
   ✓ Data retention and deletion policies?
   ✓ Vendor reputation and history?
   ✓ Privacy policy review
   ```

3. **Scope of Usage**:
   - How many users are using this SaaS app?
   - How long has it been in use?
   - How much data has been uploaded total?

### Phase 3: Decision & Action (2-8 hours)
**Option A: Approve and Onboard**
```
If legitimate business need + acceptable security posture:
1. Add to approved SaaS list
2. Negotiate enterprise agreement
3. Implement SSO/SAML integration
4. Enable CASB monitoring
5. Configure DLP policies
6. Document in asset inventory
7. Communicate approval to users
```

**Option B: Block and Provide Alternative**
```
If security risk too high or alternative exists:
1. Block at web proxy/firewall
2. Communicate to users
3. Provide approved alternative
4. Migrate data if needed
5. Security awareness training
```

**Option C: Retrieve and Remove Data**
```
If sensitive data was exposed:
1. Work with user to download/delete data from SaaS
2. Request data deletion from SaaS vendor
3. Verify deletion
4. Block future access
5. Incident documentation
```

### Phase 4: Prevention (Ongoing)
1. **Implement CASB**:
   ```
   - Cloud Access Security Broker deployment
   - Shadow IT discovery
   - Automated app risk scoring
   - DLP policy enforcement
   - OAuth app governance
   ```

2. **Update Policies**:
   ```yaml
   acceptable_use_policy:
     saas_usage:
       requires_approval: true
       approval_process: "Submit request to IT Security"
       prohibited_categories:
         - personal_file_sharing
         - unauthorized_cloud_storage
         - unapproved_collaboration_tools
   ```

3. **Security Awareness**:
   ```
   - Shadow IT risks training
   - Approved SaaS catalog publication
   - Easy-to-use SaaS request process
   - Quarterly reminders
   ```

4. **Technical Controls**:
   ```
   - Web proxy with SSL inspection
   - DNS filtering for known shadow IT domains
   - OAuth consent policies (admin approval)
   - Browser extension policies (approved list)
   - DLP on endpoints and network
   ```

## Investigation Steps

1. **Who**: Which user(s) are using unauthorized SaaS?
2. **What**: Which SaaS applications? What data was shared?
3. **When**: How long has this been occurring?
4. **Where**: From which locations/networks?
5. **Why**: Business justification or policy violation?
6. **How**: Method of access (web browser, mobile app, API)?

## Common Shadow IT Scenarios

### Scenario 1: File Sharing for External Collaboration
```
User: "I needed to share a 500 MB file with a client, and corporate email has a 10 MB limit"
Risk: Sensitive file on unapproved service, no access controls
Solution: Approve secure file transfer solution (SFTP, approved file sharing)
```

### Scenario 2: Productivity Tools
```
User: "Our department uses Notion for project management - it's way better than [approved tool]"
Risk: Company data in unapproved SaaS, no SSO, no data governance
Solution: Evaluate Notion security, consider enterprise upgrade, or migrate to approved tool
```

### Scenario 3: Personal Cloud Storage
```
User: "I sync work files to Dropbox to access from home"
Risk: Company data on personal account, no encryption, account compromise risk
Solution: Provide VPN + approved remote access, enable corporate OneDrive
```

### Scenario 4: Communication Tools
```
Team: "We use Discord for team chat - it has better features than Teams"
Risk: Sensitive discussions in unapproved platform, no compliance controls
Solution: Enable requested features in approved platform, or approve Discord with policies
```

## Shadow IT Risks

### Data Exfiltration
- Sensitive data leaves corporate controls
- No DLP enforcement
- Insider threat vector

### Compliance Violations
- GDPR (data processor agreements required)
- HIPAA (BAA required)
- PCI-DSS (card data in unapproved systems)
- SOX (financial data controls)

### Security Gaps
- No SSO/MFA enforcement
- Weak passwords
- No audit logging
- No security monitoring
- No vendor security assessments

### Legal/Contractual
- Vendor agreements not in place
- No data processing agreements
- Intellectual property leakage
- E-discovery challenges

## Prevention Measures

### 1. Cloud Access Security Broker (CASB)
```
- Discover shadow IT automatically
- Risk score SaaS applications
- Enforce DLP policies
- Monitor OAuth grants
- Provide safe SaaS alternatives
```

### 2. Sanctioned SaaS Catalog
```
Publish approved applications:
- File Sharing: Box, Google Drive (corporate)
- Collaboration: Microsoft Teams, Slack (enterprise)
- Code Repos: GitHub Enterprise, GitLab (corporate)
- Productivity: Microsoft 365, Google Workspace
```

### 3. Easy Approval Process
```
1. User submits SaaS request via portal
2. Security reviews application security
3. Legal reviews vendor contract
4. Procurement negotiates enterprise pricing
5. IT implements SSO/provisioning
6. User notified of approval (or alternative)
Timeline: 2-4 weeks (communicate this!)
```

### 4. OAuth Governance
```
Microsoft Azure AD / Google Workspace:
- Require admin consent for OAuth apps
- Block unknown publishers
- Review granted permissions quarterly
- Revoke suspicious OAuth grants
```

### 5. Browser Extension Policies
```
Google Chrome Policy:
{
  "ExtensionInstallBlacklist": ["*"],
  "ExtensionInstallWhitelist": [
    "<approved-extension-id-1>",
    "<approved-extension-id-2>"
  ]
}
```

## Forensic Artifacts
- Web proxy logs (URLs, uploads, downloads)
- DNS query logs (SaaS domain access)
- OAuth consent audit logs
- Browser history and extension lists
- Cloud provider logs (if SaaS was OAuth-connected)
- DLP alerts and file classifications
- User surveys or interviews

## Compliance Impact
- **GDPR**: Art. 28 (Data processor agreements), unauthorized data transfer
- **HIPAA**: BAA required for PHI processing, access controls
- **PCI-DSS**: Cardholder data in unapproved systems (major violation)
- **SOX**: Financial data controls and audit trails
- **ISO 27001**: Supplier management, asset inventory

## Business Impact
- **Data Breach**: Sensitive data exposed in insecure SaaS
- **Compliance Fines**: GDPR violations ($20M or 4% revenue)
- **IP Theft**: Proprietary data in external services
- **Productivity Loss**: Fragmented tooling, no integration
- **Cost Inefficiency**: Duplicate tool spending, no volume discounts
- **Security Incidents**: Account compromise, ransomware delivery

## Tools & Solutions

**CASB (Cloud Access Security Broker)**:
- Microsoft Defender for Cloud Apps
- Netskope
- Zscaler CASB
- Cisco Cloudlock
- McAfee MVISION Cloud

**DLP (Data Loss Prevention)**:
- Symantec DLP
- Microsoft Purview DLP
- Forcepoint DLP
- Digital Guardian

**SaaS Management Platforms**:
- BetterCloud
- Torii
- Zylo
- Productiv

## Related Use Cases
- DLP - Sensitive Data Upload to Cloud
- InsiderThreat - Data Exfiltration
- ThreatIntelligence - TOR/VPN Usage
- APISecurity - API Key Exposure (in unapproved SaaS)

## References
- Gartner: Shadow IT Statistics
- Cloud Security Alliance: SaaS Governance Best Practices
- NIST SP 800-144: Guidelines on Security and Privacy in Public Cloud Computing
- OWASP: SaaS Security Verification Standard

## Notes
- Shadow IT is ubiquitous - 80% of employees use unapproved SaaS
- Balance security with productivity - don't just block everything
- Understand WHY users choose shadow IT (approved tools inadequate?)
- Make SaaS approval process easy and fast
- CASB is essential for modern SaaS governance
- Regular security awareness training reduces shadow IT
- OAuth apps are a major shadow IT vector (phishing risk too)
- Browser extensions can exfiltrate data silently
- Personal cloud storage is the #1 shadow IT category
- Provide secure alternatives to reduce shadow IT usage
