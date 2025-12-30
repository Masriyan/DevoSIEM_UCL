# Container/Kubernetes - Privileged Container Escape

## Severity
**CRITICAL**

## Description
Detects attempts to escape from privileged containers or abuse container runtime features to gain access to the host operating system. This includes privileged container creation, host namespace sharing, volume mounts to sensitive host paths, and container breakout attempts.

## MITRE ATT&CK
- **Tactic**: Privilege Escalation (TA0004), Defense Evasion (TA0005), Execution (TA0002)
- **Technique**: Escape to Host (T1611), Privileged Container (T1610), Exploitation for Privilege Escalation (T1068)
- **Sub-technique**: Container Administration Command (T1609)

## DEVO Query

```sql
from kubernetes.audit
select eventdate
select user.username as k8s_user
select sourceIPs
select objectRef.namespace as namespace
select objectRef.name as resource_name
select objectRef.resource as resource_type
select requestObject.spec.containers.securityContext as security_context
select requestObject.spec.hostNetwork as host_network
select requestObject.spec.hostPID as host_pid
select requestObject.spec.hostIPC as host_ipc
select requestObject.spec.containers.volumeMounts as volume_mounts
select requestObject.spec.volumes as volumes
select responseStatus.code as response_code
select mm2country(sourceIPs) as source_country
where verb = "create"
  and objectRef.resource = "pods"
  and (
    requestObject.spec.containers.securityContext.privileged = true
    or requestObject.spec.hostNetwork = true
    or requestObject.spec.hostPID = true
    or requestObject.spec.hostIPC = true
    or weakhas(str(requestObject.spec.volumes), "hostPath")
    or weakhas(str(requestObject.spec.containers.volumeMounts), "/var/run/docker.sock")
    or weakhas(str(requestObject.spec.containers.volumeMounts), "/proc")
    or weakhas(str(requestObject.spec.containers.volumeMounts), "/sys")
    or weakhas(str(requestObject.spec.containers.volumeMounts), "/dev")
    or weakhas(str(requestObject.spec.containers.volumeMounts), "/etc")
    or weakhas(requestObject.spec.containers.securityContext.capabilities.add, "SYS_ADMIN")
    or weakhas(requestObject.spec.containers.securityContext.capabilities.add, "SYS_PTRACE")
    or requestObject.spec.containers.securityContext.allowPrivilegeEscalation = true
  )
  and responseStatus.code < 300
group by k8s_user, namespace, resource_name
every 1m
```

## Container Runtime Query

```sql
from container.runtime
select eventdate
select hostname
select container_id
select container_name
select container_image
select command_line
select process_name
select user
where (
    weakhas(command_line, "nsenter")
    or weakhas(command_line, "runc")
    or weakhas(command_line, "ctr")
    or weakhas(command_line, "crictl")
    or weakhas(command_line, "/var/run/docker.sock")
    or (weakhas(process_name, "sh") and weakhas(command_line, "/host"))
    or weakhas(command_line, "mount -o remount")
    or weakhas(command_line, "pivot_root")
    or weakhas(command_line, "unshare")
  )
every 1m
```

## Alert Configuration
- **Trigger**: Privileged container creation OR container escape attempt detected
- **Throttling**: Real-time, group by user and namespace (1 minute window)
- **Severity**: Critical
- **Priority**: P1
- **SOAR Integration**: Auto-trigger container forensics collection

## Recommended Actions
1. **IMMEDIATE**: Terminate the privileged pod/container
2. Isolate the Kubernetes node from the cluster
3. Disable the user account that created the privileged resource
4. Review audit logs for the user's recent activities
5. Check for unauthorized cluster role bindings
6. Scan container images for malware
7. Review pod security policies/admission controllers
8. Inspect running processes on the affected node
9. Check for persistence mechanisms (DaemonSets, CronJobs)
10. Hunt for lateral movement within the cluster
11. Verify integrity of kubelet and container runtime
12. Document incident timeline
13. Preserve forensic evidence (container logs, audit logs, runtime forensics)

## False Positive Considerations
- Approved privileged workloads (monitoring agents, CNI plugins, CSI drivers)
- System-level DaemonSets (kube-proxy, logging agents)
- Kubernetes platform pods (CoreDNS, metrics-server)
- CI/CD pipeline containers with legitimate privileged requirements
- Infrastructure-as-Code automated deployments

**Tuning Recommendations**:
- Whitelist approved ServiceAccounts for privileged workloads
- Exclude system namespaces (kube-system, kube-public, kube-node-lease)
- Baseline legitimate privileged pods and create exceptions
- Implement PodSecurityPolicy/PodSecurityStandards enforcement
- Require approval workflow for privileged container requests
- Tag approved privileged workloads with specific labels

## Enrichment Opportunities
- User identity and role mappings
- ServiceAccount permissions and role bindings
- Container image provenance and vulnerability scan results
- Historical pod creation patterns for the user
- Network connections from the container
- File system changes on the host
- Correlation with image pull activities
- CI/CD pipeline integration (was this deployed via pipeline?)
- Threat intelligence on container image registry

## Response Playbook
1. **Immediate Containment** (0-5 minutes):
   - Execute `kubectl delete pod <pod-name> -n <namespace> --force --grace-period=0`
   - If container escape suspected, cordon the node: `kubectl cordon <node-name>`
   - Block user access: Disable RBAC bindings
   - Capture container snapshot if forensics needed
   - Enable enhanced audit logging

2. **Investigation** (5-30 minutes):
   - Review complete Kubernetes audit log for the user
   - List all resources created by suspicious ServiceAccount/user:
     ```bash
     kubectl get pods,deployments,daemonsets,cronjobs -A -o json | jq '.items[] | select(.metadata.annotations."created-by" | contains("suspicious-user"))'
     ```
   - Check cluster role bindings:
     ```bash
     kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[].name=="suspicious-user")'
     ```
   - Inspect node for compromise:
     ```bash
     kubectl debug node/<node-name> -it --image=busybox
     # Check for unauthorized processes, files, network connections
     ```
   - Review container image layers and scan results
   - Check admission controller logs (OPA, Kyverno, etc.)

3. **Scope Assessment** (30 min - 2 hours):
   - Identify all pods created by the malicious user
   - Map network connections from suspicious containers
   - Check for lateral movement to other namespaces
   - Review secrets accessed by the ServiceAccount
   - Identify if container registry was compromised
   - Assess if cluster admin privileges were obtained
   - Check for persistence (modified admission webhooks, malicious operators)

4. **Eradication** (2-8 hours):
   - Delete all malicious resources
   - Drain and rebuild compromised nodes
   - Rotate all secrets and ServiceAccount tokens
   - Review and update RBAC policies
   - Strengthen Pod Security Standards
   - Update admission controller policies
   - Patch container runtime vulnerabilities
   - Rebuild from trusted container images

5. **Recovery** (8-24 hours):
   - Redeploy legitimate workloads
   - Validate cluster integrity
   - Re-enable nodes in cluster
   - Restore proper RBAC configurations
   - Enhanced monitoring on affected namespaces
   - Security validation testing

6. **Post-Incident** (Ongoing):
   - Implement PodSecurityPolicy/Standards
   - Deploy runtime security solution (Falco, Sysdig, Aqua)
   - Strengthen admission control (OPA, Kyverno)
   - Regular container image scanning
   - Least-privilege RBAC review
   - Security training for DevOps teams
   - Tabletop exercise for container incidents

## Investigation Steps
- **Timeline Reconstruction**: Map all actions by the suspicious user/ServiceAccount
- **RBAC Analysis**: How did the user get permission to create privileged pods?
- **Image Analysis**: Was the container image from a trusted registry? Any CVEs?
- **Runtime Analysis**: What processes ran inside the container?
- **Network Analysis**: What connections were established from the container?
- **Host Analysis**: Did the container access host file systems? Modify host files?
- **Persistence Check**: Are there DaemonSets, CronJobs, or operators deployed?
- **Lateral Movement**: Did the attacker access other pods or namespaces?
- **Privilege Escalation**: Was cluster-admin access obtained?
- **Data Access**: What secrets, configmaps, or data were accessed?

## Container Escape Techniques

### 1. Docker Socket Mounting
Mounting `/var/run/docker.sock` gives full Docker API access:
```bash
# From inside container
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host
```

### 2. Privileged Container + Host Namespaces
```yaml
hostNetwork: true
hostPID: true
hostIPC: true
securityContext:
  privileged: true
```
Access to all host processes and network interfaces.

### 3. HostPath Volume Mounts
Mounting sensitive host paths:
```yaml
volumeMounts:
  - mountPath: /host-root
    name: host
volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

### 4. Dangerous Linux Capabilities
```yaml
securityContext:
  capabilities:
    add:
      - SYS_ADMIN  # Mount file systems, change namespaces
      - SYS_PTRACE # Debug processes, inject code
      - SYS_MODULE # Load kernel modules
      - DAC_READ_SEARCH # Bypass file read permission checks
```

### 5. Kernel Exploits
Exploiting container runtime or kernel vulnerabilities:
- CVE-2019-5736: runc container escape
- CVE-2022-0185: Linux kernel heap overflow
- Dirty COW variants
- Use tools like `cdk` (Container Develop Kit) to find escape paths

### 6. Kubelet API Abuse
Unauthenticated kubelet API exposure:
```bash
curl -k https://kubelet-ip:10250/run/<namespace>/<pod>/<container> -d "cmd=cat /etc/shadow"
```

## Kubernetes-Specific Attack Vectors

### ServiceAccount Token Abuse
```bash
# From compromised pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN --server=https://kubernetes.default get pods --all-namespaces
```

### Cluster Role Escalation
```bash
# Create cluster-admin binding
kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=default:default
```

### Admission Webhook Bypass
- Modify validating/mutating webhooks
- Deploy malicious admission controllers

### etcd Access
Direct etcd access = full cluster compromise:
```bash
# Access cluster secrets
ETCDCTL_API=3 etcdctl get /registry/secrets --prefix
```

## Prevention Measures

### 1. Pod Security Standards
Enforce restricted Pod Security Standards:
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

### 2. RBAC Least Privilege
```yaml
# Don't grant pod/exec or pods/* permissions broadly
kind: Role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]  # NOT "create" or "*"
```

### 3. Admission Control
Use OPA Gatekeeper or Kyverno:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: enforce
  rules:
  - name: no-privileged
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): false
```

### 4. Runtime Security
Deploy Falco for runtime threat detection:
```yaml
# Detect container escape attempts
- rule: Launch Privileged Container
  desc: Detect privileged container
  condition: container and container.privileged=true
  output: Privileged container started (user=%user.name container=%container.id image=%container.image.repository)
  priority: CRITICAL
```

### 5. Image Security
- Use distroless/minimal base images
- Scan images with Trivy, Clair, Anchore
- Sign images with Cosign
- Implement image admission policies
- Use private, secured registries

### 6. Network Policies
Implement strict network segmentation:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress: []
```

### 7. Resource Limits
Prevent resource-based DoS:
```yaml
resources:
  limits:
    cpu: "1"
    memory: "512Mi"
  requests:
    cpu: "100m"
    memory: "128Mi"
```

## Forensic Artifacts
- Kubernetes audit logs (`/var/log/kubernetes/audit/audit.log`)
- Container runtime logs (containerd, CRI-O, Docker)
- kubelet logs
- Node system logs (`/var/log/syslog`, `/var/log/messages`)
- Container filesystem snapshots
- Network traffic captures from pod
- Process execution logs (auditd, Falco)
- etcd backup snapshots

## Compliance Impact
- **CIS Kubernetes Benchmark**: Violations of 5.2.x (Pod Security Policies)
- **PCI-DSS**: Container isolation requirements
- **SOC 2**: Access control and monitoring requirements
- **NIST 800-190**: Container security guidance
- **ISO 27001**: Access control and monitoring standards

## Threat Intelligence
**Known Attack Campaigns**:
- TeamTNT: Cryptomining via Docker socket access
- Hildegard: Kubernetes targeted cryptojacking
- Siloscape: Windows container escape to Kubernetes cluster
- Doki: Backdoor via exposed Docker API

**IOCs to Monitor**:
- Cryptomining pools in container network traffic
- Known malicious container images
- C2 domains from containerized threats
- Suspicious container registries

## Business Impact
- **Cluster Compromise**: Full Kubernetes cluster takeover
- **Data Breach**: Access to secrets, configmaps, application data
- **Resource Hijacking**: Cryptomining, compute resource theft
- **Service Disruption**: DoS via resource exhaustion or pod deletion
- **Lateral Movement**: Container escape → host compromise → cloud account takeover
- **Compliance Violations**: Failure to meet container security standards

## Related Use Cases
- Container/Kubernetes - Unauthorized Image Pull from Public Registry
- Container/Kubernetes - Suspicious ConfigMap/Secret Access
- Container/Kubernetes - Cryptocurrency Mining in Containers
- Cloud/AWS - EKS Cluster Role Modification
- Cloud/Azure - AKS Privileged Pod Admission

## References
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
- Kubernetes Security Best Practices: https://kubernetes.io/docs/concepts/security/
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- NIST SP 800-190: Application Container Security Guide
- Kubernetes Hardening Guide (NSA/CISA): https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF

## Notes
- Container escapes are rare but devastating when successful
- Prevention through admission control is far better than detection
- Assume any privileged container can escape to the host
- Kubernetes cluster compromise can lead to cloud account takeover
- Runtime security tools (Falco, Sysdig) are essential for detection
- Regular security audits of RBAC and pod security policies
- Container security requires defense-in-depth across build, deploy, and runtime phases
