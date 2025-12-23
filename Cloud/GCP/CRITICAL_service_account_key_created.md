# GCP - Service Account Key Created

## Severity
**CRITICAL**

## Description
Detects creation of service account keys in GCP, which provide long-lived credentials and are a common target for attackers seeking persistent access.

## MITRE ATT&CK
- **Tactic**: Persistence (TA0003), Credential Access (TA0006)
- **Technique**: Account Manipulation (T1098), Valid Accounts: Cloud Accounts (T1078.004)

## DEVO Query

```sql
from cloud.gcp.audit
where protoPayload.methodName = "google.iam.admin.v1.CreateServiceAccountKey"
  and protoPayload.status.code is null
  or protoPayload.status.code = 0
select
  eventdate,
  protoPayload.authenticationInfo.principalEmail as creator,
  protoPayload.request.name as service_account,
  protoPayload.resourceName,
  protoPayload.request.privateKeyType as key_type,
  protoPayload.request.keyAlgorithm,
  protoPayload.requestMetadata.callerIp as source_ip,
  protoPayload.requestMetadata.callerSuppliedUserAgent as user_agent,
  resource.labels.project_id
group by creator, service_account, source_ip
```

## Alert Configuration
- **Trigger**: Any service account key creation
- **Throttling**: Real-time, no throttling
- **Severity**: Critical
- **Priority**: P1

## Recommended Actions
1. **IMMEDIATE**: Verify if key creation was authorized
2. Identify who created the key and why
3. Review service account permissions
4. Check if key was downloaded
5. Verify key is stored securely
6. Review service account recent activities
7. Disable key if unauthorized
8. Implement Workload Identity instead
9. Rotate all keys if compromise suspected
10. Review all service accounts for unnecessary keys

## False Positive Considerations
- Legitimate application deployments
- CI/CD pipeline setup
- Approved automation workflows
- Disaster recovery procedures

**Tuning Recommendations**:
- Require change management approval
- Whitelist approved automation accounts
- Exclude specific service accounts with documented need
- Alert on user-created keys vs. GCP-managed

## Enrichment Opportunities
- Review service account IAM bindings
- Check resource access by service account
- Correlate with deployment activities
- Review key usage in audit logs
- Check for key download
- Analyze source IP reputation

## Service Account Key Risks
- **Long-lived credentials**: No automatic rotation
- **Downloadable**: Can be exfiltrated
- **No MFA**: Key alone provides access
- **Hard to revoke**: May be embedded in code
- **Privilege escalation**: If SA has high permissions
- **Lateral movement**: Can access multiple resources

## Response Playbook
1. Verify key creation legitimacy
2. Check change management approval
3. Review service account permissions:
   - What resources can it access?
   - What APIs can it call?
   - Are permissions too broad?
4. If unauthorized or suspicious:
   - Disable key immediately
   - Review audit logs for key usage
   - Check for data exfiltration
   - Rotate all keys for the service account
   - Review and reduce SA permissions
   - Investigate creator's account
5. If legitimate:
   - Ensure key is stored in secret manager
   - Document business justification
   - Set key expiration/rotation schedule
   - Limit service account permissions
   - Monitor key usage

## Investigation Steps
- Who created the key?
- Source IP and geolocation
- Service account's current IAM roles
- Service account's recent API calls
- Has key been used yet?
- Where was key download attempt from?
- Other activities by same principal
- Check for pattern of key creation

## Best Practices
Instead of service account keys, use:
- **Workload Identity**: For GKE workloads
- **Service Account Impersonation**: Short-lived tokens
- **Application Default Credentials**: When running on GCP
- **Workload Identity Federation**: For external workloads
- **Short-lived tokens**: Via gcloud or API

## When Keys Are Necessary
If you must use keys:
- Store in Google Secret Manager
- Rotate regularly (90 days max)
- Use least privilege for service account
- Monitor key usage closely
- Set key expiration policies
- Document and approve creation
- Encrypt keys at rest
- Never commit to version control

## gcloud Commands
```bash
# List service account keys
gcloud iam service-accounts keys list --iam-account=SA_EMAIL

# Disable a key
gcloud iam service-accounts keys disable KEY_ID \
  --iam-account=SA_EMAIL

# Delete a key
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL

# Check service account permissions
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:SA_EMAIL"
```

## High-Risk Service Account Indicators
- Owner or Editor role binding
- Organization-level permissions
- Access to production environments
- Multi-project access
- Data access permissions (BigQuery, Cloud Storage)
- Compute admin permissions

## Compliance Impact
- CIS GCP Benchmark: Key rotation required
- PCI-DSS: Key management controls
- SOC 2: Credential lifecycle management
- May require audit notification

## Automated Prevention
- Organization policy to restrict key creation
- Require approval via Custom workflows
- Automatic key expiration policies
- Alert on key creation
- Regular key audit and cleanup

## Threat Scenarios
1. **Insider Threat**: Malicious employee creates key for persistent access
2. **Compromised Account**: Attacker creates key after gaining access
3. **Privilege Escalation**: Lower-privilege user creates high-privilege SA key
4. **Data Exfiltration**: Key created to access and steal data
5. **Cryptocurrency Mining**: Key for persistent compute access

## Notes
- Service account keys are high-value targets
- Should be extremely rare in modern GCP architectures
- Workload Identity is almost always better option
- Any key creation warrants immediate review
- Keys can live forever if not managed
