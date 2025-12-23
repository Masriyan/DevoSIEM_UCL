# Insider Threat - Sensitive Data Access Before Resignation

## Severity
**HIGH**

## Description
Detects when employees who have submitted resignation access sensitive data or systems they don't normally use, indicating potential data theft before departure.

## MITRE ATT&CK
- **Tactic**: Collection (TA0009), Exfiltration (TA0010)
- **Technique**: Data from Information Repositories (T1213), Data Staged (T1074)

## DEVO Query

```sql
from siem.dataaccess
select username from hr.resignations
where username in (
having access_count > 5 or total_bytes > 1073741824  -- 1 GB
```

## Alert Configuration
- **Trigger**: Resigning employee accessing sensitive data 5+ times or > 1 GB
- **Throttling**: 1 alert per username per day
- **Severity**: High
- **Priority**: P2

## Recommended Actions
1. Review the specific data accessed
2. Contact employee's manager immediately
3. Assess data sensitivity and business impact
4. Check for downloads or exports
5. Review historical access patterns
6. Compare current access to job responsibilities
7. Check for external transfers (email, cloud, USB)
8. Consider immediate termination if suspicious
9. Accelerate access revocation timeline
10. Consult with HR and Legal
11. Monitor continuously until departure
12. Enhanced logging for remaining tenure

## False Positive Considerations
- Knowledge transfer activities
- Transition documentation
- Final project completions
- Approved handover procedures
- Training replacement staff

**Tuning Recommendations**:
- Document approved transition activities
- Whitelist sanctioned knowledge transfer
- Require manager approval for sensitive access
- Adjust based on role and position
- Consider notice period length

## Enrichment Opportunities
- Review resignation circumstances (voluntary/involuntary)
- Check performance review history
- Verify destination employer (competitor?)
- Review recent manager communications
- Check disciplinary history
- Analyze access patterns before resignation
- Review travel/expense reports
- Check for grievances or conflicts

## Response Playbook
1. **Immediate Assessment**:
   - What data was accessed?
   - Is access within job scope?
   - Manager aware of access?
   - Transfer/download detected?
2. **Manager Consultation**:
   - Inform of unusual access
   - Verify if legitimate business need
   - Discuss employee's behavior
   - Get approval for enhanced monitoring
3. **Risk Determination**:
   - Data sensitivity level
   - Employee's access history
   - Resignation circumstances
   - Competitor destination
   - Financial motivation
   - Access timing (after hours?)
4. **Action Decision**:
   - **Low Risk**: Monitor and document
   - **Medium Risk**: Enhanced monitoring, restrict access
   - **High Risk**: Immediate termination consideration
5. **Ongoing Monitoring**:
   - Daily access review
   - Block unnecessary access
   - DLP enhanced rules
   - USB device restrictions
   - Email monitoring
   - Cloud app restrictions

## Investigation Steps
- Map all data accessed during notice period
- Compare to pre-resignation patterns
- Check for first-time access to systems
- Review file downloads
- Analyze search queries
- Check email for forwarding to personal accounts
- Review cloud storage uploads
- Verify USB device connections
- Check printing activity
- Analyze after-hours access

## High-Risk Scenarios
Escalate to CRITICAL if:
- Going to direct competitor
- Accessing trade secrets/IP
- Downloading customer databases
- Accessing strategic plans
- Unusual amount of downloads
- After-hours suspicious access
- Multiple export methods used
- Deleting audit trails
- Accessing others' data
- Using admin privileges

## Types of Sensitive Access to Monitor
- **Customer Data**: CRM, sales databases, contact lists
- **Financial Data**: Revenue, pricing, costs, forecasts
- **Intellectual Property**: Patents, code, designs, formulas
- **Strategic Information**: M&A plans, business strategy
- **Employee Data**: Salaries, personal information
- **Competitive Intelligence**: Market analysis, competitor data
- **Operational Data**: Processes, procedures, vendor lists

## Resignation Risk Factors
- **Notice Period**: Longer notice = more opportunity
- **Destination**: Competitor vs. different industry
- **Role**: Access to sensitive data
- **Departure Type**: Voluntary vs. terminated
- **Relationship**: Disgruntled vs. amicable
- **Access Level**: Privileged vs. standard user
- **Performance**: Recent reviews, conflicts

## Enhanced Monitoring for Departing Employees
- Daily access log review
- Real-time download alerts
- Email attachment monitoring
- Cloud app usage tracking
- USB device blocking
- Printing restrictions
- Screen recording (if legally allowed)
- Mobile device tracking
- VPN usage monitoring
- After-hours access alerts

## Manager Actions Checklist
- [ ] Review and restrict unnecessary access
- [ ] Monitor sensitive data access
- [ ] Supervise knowledge transfer
- [ ] Document approved activities
- [ ] Daily touchbases with employee
- [ ] Coordinate with Security team
- [ ] Plan access revocation
- [ ] Secure critical passwords/credentials
- [ ] Retrieve company property
- [ ] Conduct exit interview

## HR/Legal Coordination
- Inform HR of suspicious activity
- Legal review of non-compete/NDA
- Accelerate departure if high risk
- Document all findings
- Prepare for potential litigation
- Consider garden leave
- Escort from premises if terminated
- Immediate access revocation

## Off-boarding Security Procedures
- Immediate access revocation on last day
- Disable VPN access
- Revoke cloud app access
- Disable email access
- Collect badges/access cards
- Retrieve company devices
- Remote wipe mobile devices
- Change shared passwords
- Remove from groups/distribution lists
- Archive user data
- Exit interview with security questions

## Prevention Measures
- Insider threat program
- Manager training on warning signs
- Clear off-boarding procedures
- Data classification and DLP
- User behavior analytics
- Regular access reviews
- Least privilege principle
- Exit interview process
- Non-compete/NDA enforcement
- Competitive intelligence protection

## Behavioral Warning Signs
- Downloading unusual amounts of data
- After-hours access increases
- Accessing non-job-related systems
- Collecting documentation
- Taking photos/screenshots
- Printing sensitive documents
- Emailing files to personal accounts
- Using personal USB drives
- Reluctant to share knowledge
- Defensive about access

## Legal Considerations
- Follow employment laws
- Respect privacy regulations
- Maintain evidence properly
- Document business justification
- Consult legal before actions
- NDA/non-compete enforcement
- Potential trade secret theft charges
- Civil litigation preparation

## Notes
- Most insider theft occurs during notice period
- Competitor destinations are highest risk
- Preventive monitoring is essential
- Balance security with employee dignity
- Document everything for legal purposes
- Act quickly on suspicious indicators
