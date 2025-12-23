# Email Security - Business Email Compromise (BEC)

## Severity
**CRITICAL**

## Description
Detects indicators of Business Email Compromise attacks including email forwarding rules, unusual wire transfer requests, executive impersonation, and account compromise.

## MITRE ATT&CK
- **Tactic**: Collection (TA0009), Initial Access (TA0001)
- **Technique**: Email Collection (T1114), Email Forwarding Rule (T1114.003), Phishing (T1566)

## DEVO Query

```sql
from email.logs
select eventdate
select recipient
select sender
select sender_domain
select display_name
select email_subject
select rule_name
select rule_action
select forwarding_address
select srcip
select geolocation
select mm2country(srcip) as src_country
where (weakhas(event_type, "inbox_rule_created")
  and (weakhas(rule_action, "forward")
    or weakhas(rule_action, "redirect")
    or weakhas(rule_action, "delete"))
  and (weakhas(rule_condition, "invoice")
    or weakhas(rule_condition, "payment")
    or weakhas(rule_condition, "wire")
    or weakhas(rule_condition, "transfer")))
  or (email_subject like "%urgent%payment%"
    or email_subject like "%wire%transfer%"
    or weakhas(email_subject, "invoice")
    or weakhas(email_subject, "CEO") or weakhas(email_subject, "CFO"))
  and (sender_domain != recipient_domain
    or display_name != actual_sender)
  or (weakhas(operation, "Set-Mailbox") and weakhas(parameters, "ForwardingSmtpAddress"))

group by recipient, sender, rule_name
```

## Alert Configuration
- **Trigger**: Any BEC indicator detected
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Contact recipient/user via phone (NOT email)
2. Block email forwarding rule if present
3. Verify wire transfer requests through separate channel
4. Check for account compromise indicators
5. Review recent email activities
6. Scan for unusual logins
7. Reset user credentials if compromised
8. Check for sent emails to finance/accounting
9. Review email access from unusual locations
10. Alert finance team about potential fraud
11. Preserve evidence for potential legal action
12. Report to FBI IC3 if financial loss

## False Positive Considerations
- Legitimate vacation/out-of-office forwarding
- Approved assistant access
- Authorized email delegation
- Business travel with legitimate urgent requests

**Tuning Recommendations**:
- Whitelist approved forwarding to internal domains
- Require approval for external forwarding
- Document approved delegation
- Verify legitimate executive requests through policy

## Enrichment Opportunities
- Check user's recent authentication logs
- Review sender IP reputation
- Analyze display name vs. actual email
- Check for similar phishing to other users
- Review historical forwarding rules
- Verify sender domain registration date
- Check for domain lookalikes (typosquatting)
- Correlate with impossible travel

## Response Playbook
1. **Immediate Verification**:
   - Call user directly (voice verify)
   - DO NOT email or use chat
   - Verify if they created forwarding rule
   - Confirm if they sent payment request
2. **If Account Compromised**:
   - Lock account immediately
   - Remove forwarding rules
   - Reset credentials
   - Revoke all active sessions
   - Force MFA re-enrollment
   - Review all sent emails
   - Check for data exfiltration
3. **If Phishing/Impersonation**:
   - Block sender domain/email
   - Delete email from all mailboxes
   - Alert all users
   - Report to email security vendor
   - Submit to anti-phishing authorities
4. **Financial Verification**:
   - Contact finance team
   - Verify no wire transfers initiated
   - Put hold on pending transfers
   - Verify bank account changes
   - Review payment requests
5. **Investigation**:
   - Full email forensics
   - Review compromise timeline
   - Check for other victims
   - Document financial impact
   - Preserve evidence

## Investigation Steps
- Review all inbox rules for user
- Check recent login locations
- Analyze sent folder for suspicious emails
- Review email access permissions
- Check for email delegation changes
- Verify MFA status
- Review mailbox access by non-owner
- Check for deleted items
- Analyze email headers
- Review historical email patterns

## BEC Attack Patterns

**CEO Fraud**:
- Impersonate executive
- Request urgent wire transfer
- Target finance/accounting
- Time pressure tactics
- Outside normal business process

**Account Compromise**:
- Phish employee credentials
- Create forwarding rules
- Monitor for financial emails
- Intercept payments
- Modify bank details

**Attorney Impersonation**:
- Pose as company lawyer
- Confidential/sensitive matter
- Request wire transfer
- Legal urgency

**Vendor Email Compromise**:
- Compromise vendor account
- Send fake invoices
- Change payment details
- Legitimate relationship exploited

**Data Theft**:
- W-2/payroll data requests
- Employee PII collection
- Tax fraud preparation

## Email Forwarding Rule Indicators
- Forward to external email (Gmail, Yahoo, etc.)
- Delete after forwarding (hide evidence)
- Specific keyword targeting (invoice, payment, etc.)
- Hidden/obscure rule names
- Created from unusual location
- Created during off-hours
- Multiple rules created rapidly

## Display Name Spoofing
Check for:
- Display name matches executive
- Actual email address is different
- Free email provider (gmail.com, outlook.com)
- Typosquatting domain (micro-soft.com)
- Look-alike characters (i vs l, 0 vs O)
- Generic email (ceo@domain.com)

## Financial Request Red Flags
- Urgent/time-sensitive
- Unusual request method
- Changes to payment details
- New vendor with immediate payment
- Requests to bypass approval process
- Confidential/secret projects
- Request for gift cards
- Wire transfer to unknown account
- Pressure tactics
- Grammatical errors

## Prevention Measures
- Multi-factor authentication
- Email authentication (SPF, DKIM, DMARC)
- Display name verification
- External email warnings
- Disable auto-forwarding to external domains
- Require approval for forwarding rules
- Wire transfer verification procedures
- Dual authorization for payments
- Verify requests through secondary channel
- Executive impersonation training
- Email security awareness
- Suspicious email reporting

## Wire Transfer Verification Procedure
1. Never act on email alone
2. Verify through phone call (known number)
3. Confirm with multiple parties
4. Check authorization workflow
5. Verify account details independently
6. Document all verifications
7. Flag unusual requests
8. Enforce cooling-off period

## Enhanced Detection
```sql
-- Detect lookalike domains
from email.logs
where sender_domain in (
  select domain from suspicious_domains
  where levenshtein_distance(domain, 'companydomain.com') <= 2
)
and recipient_domain = 'companydomain.com'
```

## Email Header Analysis
Check for:
- SPF/DKIM/DMARC alignment
- Return-Path vs. From address
- Reply-To address differences
- Received headers (routing)
- Message-ID patterns
- X-Originating-IP

## User Training Topics
- BEC attack awareness
- Display name spoofing
- Urgency as manipulation
- Verification procedures
- Reporting suspicious emails
- Wire transfer protocols
- Executive impersonation tactics

## Financial Controls
- Multi-person approval for wire transfers
- Callback verification required
- Daily transfer limits
- Whitelist approved vendors
- Bank account change verification
- Segregation of duties
- Regular account reconciliation

## Legal/Reporting
- Report to FBI IC3
- State attorney general
- Bank fraud department
- Cyber insurance claim
- Document all losses
- Preserve evidence
- Legal counsel involvement

## Forensic Artifacts
- Email headers
- Mail flow logs
- Audit logs (rule creation)
- Authentication logs
- IP address logs
- Forwarding rule details
- Sent items
- Deleted items

## Financial Impact
BEC causes billions in losses:
- Average loss: $100,000+
- Rarely recovered
- Reputational damage
- Regulatory scrutiny
- Insurance implications

## Notes
- BEC is #1 cybercrime by financial impact
- Sophisticated social engineering
- Prevention through process > technology
- Training is critical
- Verification saves millions
- Multi-layered defense required
