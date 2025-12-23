# GCP - Compute Instance with External IP Created

## Severity
**CRITICAL** (for sensitive projects)
**HIGH** (for general projects)

## Description
Detects when GCP Compute Engine instances are created with or assigned external IP addresses, potentially exposing workloads to the internet and creating attack surface.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Persistence (TA0003)
- **Technique**: Exploit Public-Facing Application (T1190), External Remote Services (T1133)

## DEVO Query

```sql
from cloud.gcp.audit
where protoPayload.methodName in ("v1.compute.instances.insert",
                                   "v1.compute.instances.addAccessConfig")
  and (protoPayload.request.networkInterfaces.accessConfigs.type = "ONE_TO_ONE_NAT"
    or protoPayload.request.networkInterfaces.accessConfigs.natIP is not null)
  and (protoPayload.status.code is null or protoPayload.status.code = 0)
select
  eventdate,
  protoPayload.authenticationInfo.principalEmail as creator,
  protoPayload.resourceName as instance_name,
  resource.labels.project_id,
  resource.labels.zone,
  protoPayload.request.networkInterfaces.accessConfigs.natIP as external_ip,
  protoPayload.request.machineType,
  protoPayload.request.disks.source as disk_image,
  protoPayload.request.tags.items as network_tags,
  protoPayload.request.serviceAccounts.email as service_account,
  protoPayload.request.metadata.items as instance_metadata,
  protoPayload.requestMetadata.callerIp as source_ip,
  protoPayload.requestMetadata.callerSuppliedUserAgent
group by creator, instance_name, external_ip
```

## Alert Configuration
- **Trigger**: Any instance created/modified with external IP
- **Throttling**: 1 alert per instance per hour
- **Severity**: Critical (sensitive projects), High (general)
- **Priority**: P1 (sensitive), P2 (general)

## Recommended Actions
1. Verify if external IP is required for business need
2. Review instance configuration and purpose
3. Check firewall rules allowing inbound traffic
4. Assess service account permissions
5. Review startup scripts and metadata
6. Verify image/disk source is trusted
7. Remove external IP if not required
8. Implement Cloud NAT for outbound-only access
9. Enable OS Login for SSH access
10. Apply security patches immediately
11. Configure VPC Service Controls
12. Enable binary authorization if using containers

## False Positive Considerations
- Legitimate bastion/jump hosts
- Public-facing web servers
- VPN endpoints
- Approved external services
- Development/testing environments

**Tuning Recommendations**:
- Whitelist approved external-facing projects
- Exclude bastion host projects
- Document all external IP requirements
- Separate alerting for prod vs non-prod
- Require approval for production external IPs

## Enrichment Opportunities
- Review project's organizational policy
- Check VPC firewall rules
- Analyze IAM permissions for instance
- Review service account permissions
- Check Cloud Armor policies
- Verify GKE cluster (if applicable)
- Review load balancer configuration
- Check for vulnerability scan results

## Response Playbook
1. **Immediate Assessment**:
   - Which project/environment?
   - Production or development?
   - What services running on instance?
   - What firewall rules apply?
   - Business justification?

2. **Security Review**:
   - Scan external IP with Nmap
   - Check open ports
   - Review firewall rules
   - Verify SSH configuration
   - Check for default credentials
   - Review installed software
   - Assess patch level

3. **Risk Evaluation**:
   - Sensitive data on instance?
   - What service account attached?
   - IAM permissions granted?
   - Access to other resources?
   - Compliance requirements?

4. **If Unauthorized**:
   - Remove external IP immediately
   - Implement Cloud NAT
   - Use Cloud VPN/Interconnect
   - Review firewall rules
   - Audit recent activities
   - Check for compromise

5. **If Legitimate**:
   - Document business need
   - Harden instance security
   - Restrict firewall rules
   - Enable security features
   - Schedule security review
   - Monitor continuously

## Investigation Steps
- Review instance creation details
- Check who created the instance
- Verify source IP of creation request
- Review startup scripts
- Check instance metadata
- Analyze service account permissions
- Review VPC firewall rules
- Check for SSH keys in metadata
- Verify image source
- Review instance access logs
- Check for established connections

## External IP Risks

**Attack Surface**:
- Direct internet exposure
- Vulnerability scanning target
- Brute force attacks
- Exploitation attempts
- DDoS target
- Botnet recruitment

**Common Attacks**:
- SSH brute force (port 22)
- RDP brute force (port 3389)
- Web application attacks
- Database exploitation
- Crypto mining
- Botnet malware

## Alternatives to External IP

**Cloud NAT**:
- Outbound internet access only
- No inbound connections
- Managed service
- Scalable
- No external IP needed

**Cloud VPN**:
- Secure access via VPN
- Private connectivity
- No public exposure
- Corporate network integration

**Cloud Interconnect**:
- Dedicated connection
- High bandwidth
- Low latency
- Enterprise use

**Identity-Aware Proxy (IAP)**:
- Secure access without VPN
- Identity-based
- No external IP
- Centralized access control

**Cloud Load Balancer**:
- Single external IP
- Multiple backend instances
- Private instance IPs
- DDoS protection

## Firewall Rule Review

Check for dangerous rules:
- 0.0.0.0/0 source (entire internet)
- Port 22 (SSH) open to all
- Port 3389 (RDP) open to all
- Database ports (3306, 5432, 27017)
- Wide port ranges
- "Allow all" rules

## Service Account Permissions

High-risk if instance has:
- Project Editor or Owner
- Compute Admin
- Storage Admin
- Secret Manager access
- IAM permissions
- Cross-project access

## Startup Script Analysis

Review for:
- Credential harvesting
- Reverse shells
- Unauthorized software
- Crypto miners
- C2 beacons
- Data exfiltration scripts

## Instance Metadata Risks

Metadata can contain:
- SSH keys
- Startup scripts
- Service account tokens
- Configuration secrets
- Environment variables

## Enhanced Detection

```sql
-- Detect external IP on instance with sensitive data access
from cloud.gcp.audit
where protoPayload.methodName = "v1.compute.instances.insert"
  and protoPayload.request.networkInterfaces.accessConfigs.type = "ONE_TO_ONE_NAT"
  and protoPayload.request.serviceAccounts.email in (
    select email from iam.serviceaccounts
    where roles contains "roles/bigquery.dataEditor"
      or roles contains "roles/storage.admin"
  )
```

## Hardening Recommendations

**Network Security**:
- Minimal firewall rules
- Source IP restrictions
- VPC Service Controls
- Cloud Armor (if web-facing)
- DDoS protection
- Private Google Access

**Access Control**:
- OS Login (not SSH keys in metadata)
- IAM-based SSH access
- Temporary elevated access (IAP)
- Service account with least privilege
- Disable serial console
- Require MFA for SSH

**Instance Security**:
- Shielded VMs
- Secure boot
- vTPM enabled
- Integrity monitoring
- Automatic OS patching
- Container-Optimized OS (if applicable)
- Binary Authorization (GKE)

**Monitoring**:
- VPC Flow Logs
- Cloud Logging
- Security Command Center
- Vulnerability scanning
- Intrusion detection
- Anomaly detection

## Organization Policy Controls

Implement constraints:
- compute.vmExternalIpAccess (restrict external IPs)
- compute.requireOsLogin
- compute.requireShieldedVm
- compute.trustedImageProjects
- compute.disableSerialPortAccess

## Security Command Center Findings

Enable detections for:
- Public IP address
- Open firewall rules
- Weak SSH keys
- Missing security features
- Vulnerability scan findings
- Compliance violations

## Compliance Considerations

External IPs may violate:
- PCI-DSS requirements
- HIPAA safeguards
- SOC 2 controls
- Data residency requirements
- Corporate security policies

## Common Legitimate Uses

**Acceptable with Hardening**:
- Load balancer backends (via LB)
- Bastion hosts (highly restricted)
- VPN endpoints (with MFA)
- Public web servers (with WAF)
- API gateways (with authentication)

**Should Use Alternatives**:
- Database servers (use Cloud SQL)
- Application servers (use Cloud NAT)
- Batch processing (use Cloud NAT)
- Internal tools (use IAP)
- Development instances (use VPN)

## Automation Opportunities
- Auto-alert on external IP creation
- Automated firewall rule review
- Vulnerability scanning trigger
- Compliance check automation
- Remediation workflows (remove if unauthorized)
- Change management integration
- Approval workflows for external IPs

## Incident Response

If compromise suspected:
1. Snapshot disk for forensics
2. Isolate instance (remove external IP)
3. Review access logs
4. Check for data exfiltration
5. Analyze running processes
6. Review network connections
7. Scan for malware
8. Reset credentials
9. Rebuild from clean image

## Cost Considerations

External IPs have costs:
- Static IP reservation fees
- Data egress charges
- DDoS protection costs
- Load balancer costs
- Consider Cloud NAT cost vs external IP

## Notes
- External IPs significantly increase risk
- Most workloads don't need them
- Cloud NAT is preferred solution
- Bastion hosts need extreme hardening
- Zero trust model recommends IAP
- Organization policies can prevent
- Regular audit essential
- Remove unused external IPs
