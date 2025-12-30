# Container/Kubernetes - Suspicious Secret and ConfigMap Access

## Severity
**HIGH**

## Description
Detects unauthorized or suspicious access to Kubernetes Secrets and ConfigMaps, which often contain sensitive credentials, API keys, certificates, and configuration data. This includes bulk secret enumeration, access to secrets outside normal pod lifecycle, and suspicious ServiceAccount permissions.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006), Discovery (TA0007), Collection (TA0009)
- **Technique**: Unsecured Credentials (T1552), Cloud Service Discovery (T1526), Data from Configuration Repository (T1602)
- **Sub-technique**: Container API (T1552.007), Kubernetes Secrets (Custom)

## DEVO Query

```sql
from kubernetes.audit
select eventdate
select user.username as k8s_user
select user.groups as user_groups
select sourceIPs
select objectRef.namespace as namespace
select objectRef.name as secret_name
select objectRef.resource as resource_type
select verb
select userAgent
select responseStatus.code as status_code
select count() as access_count
select countdistinct(objectRef.name) as unique_secrets_accessed
select mm2country(sourceIPs) as source_country
where (objectRef.resource = "secrets" or objectRef.resource = "configmaps")
  and `in`("get", "list", "watch", verb)
  and responseStatus.code < 300
  and user.username != "system:serviceaccount:kube-system:generic-garbage-collector"
  and user.username not like "system:serviceaccount:kube-system:%"
  and (
    -- Bulk secret enumeration
    verb = "list"
    or objectRef.name = "" -- List all secrets

    -- High-value secrets
    or weakhas(secret_name, "admin")
    or weakhas(secret_name, "root")
    or weakhas(secret_name, "password")
    or weakhas(secret_name, "token")
    or weakhas(secret_name, "key")
    or weakhas(secret_name, "cert")
    or weakhas(secret_name, "credential")
    or weakhas(secret_name, "aws")
    or weakhas(secret_name, "azure")
    or weakhas(secret_name, "gcp")
    or weakhas(secret_name, "database")
    or weakhas(secret_name, "db-")
    or weakhas(secret_name, "api-key")

    -- Access from unexpected user agents
    or not weakhas(userAgent, "kubectl")
       and not weakhas(userAgent, "kubelet")
       and not weakhas(userAgent, "kube-controller")
  )
group by k8s_user, namespace, sourceIPs
every 5m
having unique_secrets_accessed > 3 or access_count > 10
```

## ServiceAccount Token Abuse Detection

```sql
from kubernetes.audit
select eventdate
select user.username
select sourceIPs
select verb
select objectRef.resource
select objectRef.namespace
select responseStatus.code
select userAgent
select count() as api_calls
select countdistinct(objectRef.resource) as unique_resources
where weakhas(user.username, "serviceaccount")
  and responseStatus.code < 300
  and (
    `in`("create", "delete", "patch", "update", verb)
    or `in`("secrets", "configmaps", "roles", "rolebindings", "clusterroles", "clusterrolebindings", objectRef.resource)
  )
group by user.username, sourceIPs
every 5m
having api_calls > 20 or unique_resources > 5
```

## Secret Access Outside Pod Context

```sql
from kubernetes.audit audit_log
left join kubernetes.pods pod_info
  on audit_log.user.username = concat("system:serviceaccount:", pod_info.metadata.namespace, ":", pod_info.spec.serviceAccountName)
select audit_log.eventdate
select audit_log.user.username as sa_name
select audit_log.sourceIPs
select audit_log.objectRef.name as secret_name
select audit_log.objectRef.namespace
select pod_info.metadata.name as pod_name
select pod_info.status.phase as pod_status
where audit_log.objectRef.resource = "secrets"
  and audit_log.verb = "get"
  and audit_log.responseStatus.code < 300
  and weakhas(audit_log.user.username, "serviceaccount")
  and (
    pod_info.metadata.name is null  -- No active pod found
    or pod_info.status.phase != "Running"  -- Pod not running
  )
group by sa_name, secret_name, audit_log.sourceIPs
every 5m
```

## Alert Configuration
- **Trigger**:
  - Bulk secret enumeration (>3 unique secrets in 5 minutes)
  - High-value secret access
  - Secret access from non-pod source
  - ServiceAccount abuse (>20 API calls in 5 minutes)
- **Throttling**: 5 minute window, group by user and namespace
- **Severity**: High
- **Priority**: P2
- **Enrichment**: Correlate with pod creation/deletion events

## Recommended Actions
1. **IMMEDIATE**: Review the user/ServiceAccount accessing secrets
2. Check if the access pattern is legitimate (scheduled job, deployment, etc.)
3. Verify the source IP address (is it within expected range?)
4. List all secrets accessed by the user:
   ```bash
   kubectl get events -A | grep "secrets" | grep "<username>"
   ```
5. Check ServiceAccount token validity and permissions:
   ```bash
   kubectl get sa <sa-name> -n <namespace> -o yaml
   kubectl describe rolebinding,clusterrolebinding -A | grep <sa-name>
   ```
6. If unauthorized, revoke ServiceAccount token and rotate secrets
7. Review RBAC policies for overly permissive secret access
8. Check for credential exfiltration (network logs, S3 uploads, etc.)
9. Hunt for unauthorized pods created with stolen credentials
10. Enable Kubernetes audit log retention for investigation
11. Implement least-privilege RBAC for secret access

## False Positive Considerations
- CI/CD pipelines deploying applications (legitimate secret access)
- Monitoring/security tools reading secrets (Vault sidecar, secret operator)
- Cluster operators performing maintenance
- Helm/Kustomize deployments
- Kubernetes Operators managing secrets
- Backup and disaster recovery tools

**Tuning Recommendations**:
- Whitelist approved CI/CD ServiceAccounts
- Exclude system namespaces for system components
- Baseline normal secret access patterns per namespace
- Allow secret operators (External Secrets Operator, Sealed Secrets)
- Require specific labels on ServiceAccounts with secret access
- Implement time-based exceptions (deployment windows)

## Enrichment Opportunities
- List all secrets accessed in the session
- Check if secrets were created recently (honeypot detection)
- Review secret contents (what type of credential: DB, API key, cert?)
- Correlate with pod lifecycle (was a pod created with these secrets?)
- Check for secret write operations (credential injection)
- Network traffic analysis (was credential used externally?)
- User creation date (newly created SA = suspicious)
- Role/RoleBinding audit (how did user get permission?)
- Historical access patterns for this user

## Response Playbook

### Phase 1: Immediate Assessment (0-10 minutes)
1. **Identify What Was Accessed**:
   ```bash
   # Find all secret access by user
   kubectl get events -A --sort-by='.lastTimestamp' | grep <username> | grep secret

   # Audit log analysis (if using audit log aggregation)
   cat /var/log/kubernetes/audit/audit.log | jq 'select(.user.username=="<username>" and .objectRef.resource=="secrets")'
   ```

2. **Check Current RBAC Permissions**:
   ```bash
   # What can this ServiceAccount do?
   kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa-name>

   # Find role bindings
   kubectl get rolebindings,clusterrolebindings -A -o json | jq -r '.items[] | select(.subjects[]?.name=="<sa-name>")'
   ```

3. **Verify Legitimacy**:
   - Is there a pod currently using this ServiceAccount?
   - Is this during a known deployment or maintenance window?
   - Does the source IP match expected infrastructure?

### Phase 2: Containment (10-30 minutes)

**If Unauthorized Access Confirmed**:

1. **Revoke ServiceAccount Token**:
   ```bash
   # Delete ServiceAccount (recreates token)
   kubectl delete serviceaccount <sa-name> -n <namespace>
   kubectl create serviceaccount <sa-name> -n <namespace>

   # Or delete token secret directly
   kubectl delete secret <sa-token-secret> -n <namespace>
   ```

2. **Remove RBAC Permissions**:
   ```bash
   # Delete suspicious role bindings
   kubectl delete rolebinding <binding-name> -n <namespace>
   kubectl delete clusterrolebinding <cluster-binding-name>
   ```

3. **Rotate All Accessed Secrets**:
   ```bash
   # For each accessed secret, rotate the credential
   # Example for database password:
   kubectl create secret generic db-password --from-literal=password="<new-password>" --dry-run=client -o yaml | kubectl apply -f -

   # Force pods to restart with new secrets
   kubectl rollout restart deployment/<deployment-name> -n <namespace>
   ```

4. **Block Source IP (if external)**:
   ```bash
   # Update firewall/security groups
   # Block source IP from accessing Kubernetes API
   ```

### Phase 3: Investigation (30 min - 4 hours)

1. **Timeline Reconstruction**:
   - When did the ServiceAccount/user first access secrets?
   - How many unique secrets were accessed?
   - Were any secrets created or modified by the user?
   - When was the ServiceAccount created?

2. **Access Vector Analysis**:
   - Was ServiceAccount token stolen from a pod?
   - Was token exposed in logs, artifacts, or source code?
   - Was RBAC misconfigured (overly permissive)?
   - Was there a recent deployment that exposed the token?

3. **Impact Assessment**:
   ```bash
   # What resources were created with potentially stolen credentials?
   kubectl get pods,deployments,jobs -A -o json | jq -r '.items[] | select(.spec.serviceAccountName=="<sa-name>")'

   # Check for unauthorized API calls
   cat /var/log/kubernetes/audit/audit.log | jq 'select(.user.username=="<username>" and .responseStatus.code < 300)'
   ```

4. **Credential Usage Analysis**:
   - Were credentials used outside Kubernetes? (check cloud provider logs)
   - Database access logs (if DB credentials stolen)
   - API gateway logs (if API keys stolen)
   - Cloud IAM logs (if cloud credentials stolen)

### Phase 4: Eradication (2-8 hours)

1. **Rotate All Potentially Compromised Credentials**:
   - Database passwords
   - API keys
   - TLS certificates
   - Cloud provider credentials
   - SSH keys
   - OAuth tokens

2. **Remediate RBAC**:
   ```yaml
   # Implement least-privilege RBAC
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: app-secret-reader
     namespace: production
   rules:
   - apiGroups: [""]
     resources: ["secrets"]
     resourceNames: ["app-specific-secret"]  # Restrict to specific secrets
     verbs: ["get"]  # Only "get", not "list" or "watch"
   ```

3. **Implement Secret Access Auditing**:
   ```bash
   # Enable audit logging for all secret access
   # Update audit policy to log all secret operations
   ```

4. **Remove Malicious Resources**:
   ```bash
   # Delete any pods/deployments created during compromise
   kubectl delete pod <malicious-pod> -n <namespace>
   ```

### Phase 5: Prevention (Ongoing)

1. **Implement RBAC Best Practices**:
   ```yaml
   # Deny secret list by default
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   rules:
   - apiGroups: [""]
     resources: ["secrets"]
     resourceNames: ["app-db-secret"]  # Specific secret only
     verbs: ["get"]
   ```

2. **Use External Secret Management**:
   - Deploy HashiCorp Vault
   - Use External Secrets Operator
   - Implement Sealed Secrets
   - Use cloud provider secret managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)

3. **Enable Pod Security Standards**:
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: production
     labels:
       pod-security.kubernetes.io/enforce: restricted
       pod-security.kubernetes.io/audit: restricted
       pod-security.kubernetes.io/warn: restricted
   ```

4. **Implement Secret Scanning**:
   - Use TruffleHog, GitGuardian, or git-secrets
   - Scan container images for embedded secrets
   - Monitor source code repositories

5. **Service Mesh for Secret Injection**:
   - Use Istio/Linkerd for runtime secret injection
   - Avoid mounting secrets as files when possible
   - Use short-lived tokens

## Investigation Steps

1. **Identify the Actor**:
   - Is it a ServiceAccount or user account?
   - When was the account created?
   - What RBAC permissions does it have?

2. **Map Secret Access**:
   - Which secrets were accessed?
   - What do those secrets contain? (DB creds, API keys, certs?)
   - Were secrets listed or specific secrets requested?

3. **Determine Access Method**:
   - kubectl command from admin workstation?
   - API call from pod?
   - Stolen ServiceAccount token?
   - Compromised kubeconfig file?

4. **Assess Impact**:
   - Were credentials used outside Kubernetes?
   - Were additional resources created?
   - Was lateral movement attempted?
   - Was data exfiltrated?

5. **Find Root Cause**:
   - RBAC misconfiguration?
   - Exposed kubeconfig?
   - Compromised CI/CD pipeline?
   - Container escape?

## Kubernetes Secret Security Best Practices

### 1. Encryption at Rest
```yaml
# Enable etcd encryption
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-key>
      - identity: {}
```

### 2. RBAC Least Privilege
```yaml
# Restrict secret access to specific secrets
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-db-secret"]  # Only this secret
  verbs: ["get"]  # Not "list" or "watch"
```

### 3. External Secret Management
```yaml
# Use External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secret
spec:
  secretStoreRef:
    name: vault-backend
  target:
    name: app-db-secret
  data:
  - secretKey: password
    remoteRef:
      key: database/production
      property: password
```

### 4. Sealed Secrets
```bash
# Encrypt secrets before storing in Git
kubeseal --format=yaml < secret.yaml > sealed-secret.yaml
kubectl apply -f sealed-secret.yaml
```

### 5. Short-Lived Tokens
```yaml
# Use projected volumes for short-lived tokens
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: app-sa
  volumes:
  - name: sa-token
    projected:
      sources:
      - serviceAccountToken:
          expirationSeconds: 3600  # 1 hour
          path: token
```

### 6. Admission Control
```yaml
# Kyverno policy: Deny secret list operations
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-secret-list
spec:
  validationFailureAction: enforce
  rules:
  - name: deny-secret-list
    match:
      resources:
        kinds:
        - Secret
    preconditions:
    - key: "{{request.operation}}"
      operator: In
      value: ["LIST"]
    validate:
      message: "Listing all secrets is not allowed"
      deny: {}
```

## Common Secret Abuse Scenarios

### Scenario 1: CI/CD Pipeline Compromise
- Attacker compromises CI/CD credentials
- Uses pipeline ServiceAccount to list all secrets
- Steals database credentials, API keys
- Deploys backdoor containers with stolen creds

### Scenario 2: Container Escape → Secret Theft
- Attacker escapes from privileged container
- Accesses node file system
- Reads ServiceAccount token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Uses token to enumerate and steal secrets

### Scenario 3: Overly Permissive RBAC
- Developer granted cluster-admin for "testing"
- Developer account compromised via phishing
- Attacker uses cluster-admin to steal all secrets

### Scenario 4: Exposed Kubeconfig
- Kubeconfig file committed to public GitHub repo
- Attacker finds kubeconfig via automated scanning
- Uses credentials to access cluster and steal secrets

## Forensic Artifacts
- Kubernetes audit logs (all secret access operations)
- Pod creation/deletion events
- ServiceAccount creation/modification events
- RBAC changes (RoleBinding, ClusterRoleBinding)
- Network logs (connections from pods using stolen credentials)
- Cloud provider logs (if cloud credentials stolen)
- Application logs (database access, API calls)
- Git commit history (for secret scanning)

## Compliance Impact
- **PCI-DSS**: 7.1 (Limit access to system components and cardholder data)
- **HIPAA**: Access controls for PHI
- **SOC 2**: Access control and monitoring
- **GDPR**: Data protection and access logging
- **ISO 27001**: A.9.4 (System and application access control)

## Business Impact
- **Credential Theft**: Database passwords, API keys, cloud credentials stolen
- **Lateral Movement**: Access to other systems using stolen credentials
- **Data Breach**: Access to sensitive data via stolen DB credentials
- **Cloud Account Takeover**: If cloud provider credentials stolen
- **Regulatory Violations**: Unauthorized access to regulated data
- **Reputation Damage**: Customer trust erosion

## Related Use Cases
- Container/Kubernetes - Privileged Container Escape
- Container/Kubernetes - Unauthorized RBAC Modification
- IAM - Privilege Escalation
- Cloud/AWS - EKS Cluster Role Modification
- Insider Threat - Mass Data Exfiltration

## Threat Intelligence
**Known Attack Patterns**:
- Hildegard: Kubernetes cryptojacking, secret theft
- Siloscape: Windows containers, secret enumeration
- TeamTNT: AWS credential theft from Kubernetes secrets

## References
- Kubernetes Secrets Documentation: https://kubernetes.io/docs/concepts/configuration/secret/
- CIS Kubernetes Benchmark: 5.4 (Secrets Management)
- NIST SP 800-190: Container Security
- OWASP Kubernetes Security Cheat Sheet
- Kubernetes RBAC Good Practices

## Notes
- Secrets in Kubernetes are base64-encoded, NOT encrypted (unless etcd encryption enabled)
- ServiceAccount tokens have no expiration by default (use projected volumes for TTL)
- "list" permission on secrets is extremely dangerous (gives access to ALL secrets)
- External secret management (Vault, AWS Secrets Manager) is best practice
- Kubernetes audit logs are critical for detecting secret abuse
- Rotate secrets immediately upon suspected compromise
- Regular RBAC audits prevent over-permissive access
