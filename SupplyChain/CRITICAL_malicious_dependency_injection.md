# Supply Chain - Malicious Dependency Injection

## Severity
**CRITICAL**

## Description
Detects malicious code injection into software dependencies through compromised package repositories, typosquatting, dependency confusion attacks, or backdoored open-source libraries. Monitors for suspicious package downloads, unexpected dependency changes, and known malicious packages in CI/CD pipelines and development environments.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Execution (TA0002), Persistence (TA0003)
- **Technique**: Supply Chain Compromise (T1195), Compromise Software Supply Chain (T1195.001), Compromise Software Dependencies and Development Tools (T1195.001)
- **Sub-technique**: Dependency Confusion, Typosquatting, Package Repository Compromise

## DEVO Query

```sql
from cicd.build
select eventdate
select project_name
select branch
select commit_hash
select build_id
select user
select package_manager
select dependency_name
select dependency_version
select dependency_source
select package_hash
select download_url
select build_logs
select count() as suspicious_packages
where (
    -- Known malicious packages (update from threat intel)
    weakhas(dependency_name, "coa")
    or weakhas(dependency_name, "rc")
    or weakhas(dependency_name, "ua-parser-js")
    or weakhas(dependency_name, "node-ipc")
    or weakhas(dependency_name, "event-stream")
    or weakhas(dependency_name, "eslint-scope")
    or weakhas(dependency_name, "bootstrap-sass")
    or weakhas(dependency_name, "babeljs")
    or weakhas(dependency_name, "crossenv")
    or weakhas(dependency_name, "d3.js")
    or weakhas(dependency_name, "fabric-js")
    or weakhas(dependency_name, "ffmepg")

    -- Typosquatting patterns (similar to popular packages)
    or (weakhas(dependency_name, "colorsss") and package_manager = "npm")
    or (weakhas(dependency_name, "requests") and package_manager = "npm") -- Python package in npm
    or (weakhas(dependency_name, "python-") and package_manager = "npm")
    or (weakhas(dependency_name, "lodsh") or weakhas(dependency_name, "loddash"))
    or (weakhas(dependency_name, "reqeust") or weakhas(dependency_name, "requets"))
    or (weakhas(dependency_name, "nmp") or weakhas(dependency_name, "mnp"))

    -- Dependency confusion (internal namespace in public repo)
    or (weakhas(dependency_source, "public")
        and (weakhas(dependency_name, "@internal/")
             or weakhas(dependency_name, "@private/")
             or weakhas(dependency_name, "@company-")))

    -- Suspicious download sources
    or not (weakhas(download_url, "npmjs.org")
            or weakhas(download_url, "pypi.org")
            or weakhas(download_url, "maven.org")
            or weakhas(download_url, "rubygems.org")
            or weakhas(download_url, "nuget.org")
            or weakhas(download_url, "approved-mirror"))

    -- Newly published packages (< 30 days old)
    or (package_age_days < 30 and package_download_count < 1000)

    -- Suspicious post-install scripts
    or weakhas(build_logs, "postinstall")
       and (weakhas(build_logs, "curl")
            or weakhas(build_logs, "wget")
            or weakhas(build_logs, "chmod +x")
            or weakhas(build_logs, "/tmp/")
            or weakhas(build_logs, "base64")
            or weakhas(build_logs, "eval"))
  )
group by project_name, dependency_name, user
every 5m
```

## Package Repository Monitoring

```sql
from package.downloads
select eventdate
select user
select src_ip
select package_name
select package_version
select package_repository
select download_method
select user_agent
select mm2country(src_ip) as source_country
select count() as download_count
select countdistinct(package_name) as unique_packages
where (
    -- Mass package downloads (reconnaissance)
    download_count > 100
    in 10m

    -- Downloads from unusual locations
    or `in`("CN", "RU", "KP", "IR", mm2country(src_ip))
       and not `in`(approved_users, user)

    -- Automated scanning patterns
    or (user_agent like "%bot%" or user_agent like "%scanner%")
       and package_repository = "internal"

    -- Version enumeration
    or (unique_packages > 50 and download_method = "API")
  )
group by user, src_ip, package_repository
every 10m
```

## Software Composition Analysis (SCA) Alerts

```sql
from sca.scan
select eventdate
select repository_name
select branch
select scan_id
select vulnerability_count
select critical_vulns
select high_vulns
select malicious_package_detected
select license_violation
select outdated_dependencies
select dependency_name
select cve_id
select cvss_score
where (
    malicious_package_detected = true
    or critical_vulns > 0
    or (cvss_score > 9.0 and exploit_available = true)
    or license_violation = true
      and license_type in ("GPL", "AGPL")
      and project_type = "commercial"
  )
group by repository_name, dependency_name
every 30m
```

## Alert Configuration
- **Trigger**:
  - Known malicious package detected
  - Typosquatting pattern match
  - Dependency confusion detected
  - Suspicious post-install script execution
  - Critical vulnerability in dependency (CVSS > 9.0 with exploit)
- **Throttling**: 5 minute window, group by project and dependency
- **Severity**: Critical
- **Priority**: P1
- **Auto-Response**: Block build, quarantine dependency, alert security team

## Recommended Actions
1. **IMMEDIATE**: Stop all affected builds and deployments
2. Quarantine the malicious dependency
3. Block the package from internal package manager
4. Identify all projects using the malicious dependency:
   ```bash
   # For npm
   npm ls <malicious-package>
   # For Python
   pip show <malicious-package>
   # For Maven
   mvn dependency:tree | grep <malicious-package>
   ```
5. Review package install scripts and behavior
6. Check for backdoors, data exfiltration, or credential theft
7. Scan all built artifacts for malware
8. Review source code changes (git diff) after dependency installation
9. Check for unauthorized network connections during build
10. Rotate all credentials accessible during build (API keys, secrets, tokens)
11. Notify development teams and stakeholders
12. Report to package repository maintainers
13. Update dependency scanning rules
14. Implement stricter package approval workflow

## False Positive Considerations
- Legitimate new packages from trusted publishers
- Internal packages with naming conventions similar to public ones
- Development/testing with intentionally outdated packages
- Approved mirrors and proxies
- Packages from approved private registries

**Tuning Recommendations**:
- Whitelist trusted package publishers and maintainers
- Exclude approved internal package namespaces
- Baseline normal package download patterns
- Allow packages with established track record (age > 1 year, downloads > 100k)
- Implement package approval workflow for new dependencies
- Use private package manager with scanning (Artifactory, Nexus)

## Enrichment Opportunities
- Package reputation scoring (Snyk, Socket.dev)
- Maintainer history and trustworthiness
- Package source code review
- Historical vulnerability data
- Package download statistics and trends
- Community feedback and reviews
- License compliance analysis
- Dependency tree analysis (transitive dependencies)
- Code similarity analysis (detect clones of popular packages)

## Response Playbook

### Phase 1: Immediate Containment (0-15 minutes)
1. **Stop All Affected Builds**:
   ```bash
   # CI/CD system commands
   # Jenkins
   curl -X POST http://jenkins/job/<job-name>/stop

   # GitLab CI
   gitlab-ci-multi-runner stop

   # GitHub Actions
   gh run cancel <run-id>
   ```

2. **Block Malicious Package**:
   ```bash
   # npm (private registry)
   npm unpublish <malicious-package> --force

   # Artifactory/Nexus - quarantine the package
   # Add to blocklist
   ```

3. **Alert Development Teams**:
   ```
   SECURITY ALERT: Malicious dependency detected
   Package: <package-name>@<version>
   Risk: [Code execution, data theft, backdoor]
   Action: DO NOT deploy, contact security team
   ```

### Phase 2: Investigation (15 min - 2 hours)
1. **Analyze Package Contents**:
   ```bash
   # Download and inspect package
   npm pack <package-name>
   tar -xzf <package-name>.tgz
   # Review package.json, especially "scripts"
   cat package/package.json | jq '.scripts'

   # Check for obfuscated code
   find package -name "*.js" -exec grep -l "eval\|Function\|atob\|unescape" {} \;
   ```

2. **Review Install Scripts**:
   ```javascript
   // Look for suspicious post-install scripts
   "scripts": {
     "postinstall": "node scripts/install.js"  // Review install.js
   }
   ```

3. **Identify Impact Scope**:
   ```bash
   # Find all projects using the package
   find . -name "package.json" -exec grep -l "<malicious-package>" {} \;

   # Check all git repositories
   for repo in $(find /repos -name .git); do
     cd $(dirname $repo)
     if grep -q "<malicious-package>" package.json 2>/dev/null; then
       echo "Found in: $PWD"
     fi
   done
   ```

4. **Check for Compromise Indicators**:
   - Unauthorized network connections during build
   - Unexpected file modifications
   - Environment variable access (credentials)
   - Suspicious child processes spawned

### Phase 3: Eradication (2-8 hours)
1. **Remove Malicious Dependency**:
   ```bash
   # Remove from package.json
   npm uninstall <malicious-package>

   # Clear cache
   npm cache clean --force

   # Verify removal
   npm ls <malicious-package>
   ```

2. **Replace with Safe Alternative**:
   ```bash
   # Use legitimate package or fork
   npm install <safe-alternative>
   # Or pin to known-good version
   npm install <package-name>@<safe-version> --save-exact
   ```

3. **Scan for Backdoors**:
   ```bash
   # Scan codebase for injected malicious code
   grep -r "suspicious_function_name" .
   git diff HEAD~10..HEAD  # Review recent code changes
   ```

4. **Rotate Credentials**:
   ```bash
   # Rotate all credentials accessible during build
   # - CI/CD secrets
   # - API keys
   # - Database passwords
   # - Cloud provider credentials
   # - SSH keys
   # - NPM/PyPI tokens
   ```

### Phase 4: Recovery (4-24 hours)
1. **Rebuild All Affected Artifacts**:
   ```bash
   # Clean rebuild
   rm -rf node_modules package-lock.json
   npm install
   npm run build
   # Scan artifacts for malware
   ```

2. **Security Scanning**:
   ```bash
   # Run SCA scan
   snyk test
   npm audit
   # Or other tools: Trivy, Grype, OSV-Scanner
   ```

3. **Verify Integrity**:
   ```bash
   # Check package hashes
   npm install --integrity
   # Verify signatures if available
   npm verify <package-name>
   ```

4. **Redeploy Safely**:
   ```bash
   # Deploy clean artifacts
   # Enhanced monitoring for first 24-48 hours
   ```

### Phase 5: Prevention (Ongoing)
1. **Implement Package Approval Workflow**:
   - Require security review for new dependencies
   - Limit who can add dependencies
   - Use dependency review tools (Renovate, Dependabot)

2. **Private Package Manager**:
   ```yaml
   # Configure npm to use private registry
   # .npmrc
   registry=https://private-registry.company.com/
   always-auth=true
   ```

3. **Dependency Pinning**:
   ```json
   // package.json - use exact versions
   {
     "dependencies": {
       "express": "4.18.2",  // Not "^4.18.2"
       "lodash": "4.17.21"
     }
   }
   ```

4. **Automated Scanning**:
   ```yaml
   # GitHub Actions example
   name: Dependency Scan
   on: [push, pull_request]
   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Run Snyk
           uses: snyk/actions/node@master
         - name: Run OSV-Scanner
           uses: google/osv-scanner-action@v1
   ```

5. **Software Bill of Materials (SBOM)**:
   ```bash
   # Generate SBOM
   syft packages . -o cyclonedx > sbom.json
   # Verify SBOM against policy
   grype sbom:sbom.json
   ```

## Investigation Steps

1. **Package Analysis**:
   - When was the package published?
   - Who is the maintainer?
   - What are the package download statistics?
   - Are there GitHub stars/issues/contributors?
   - Is the package name similar to a popular package (typosquatting)?

2. **Code Review**:
   - Deobfuscate any minified/obfuscated code
   - Check for eval(), Function(), base64 encoding
   - Review postinstall/preinstall scripts
   - Analyze network calls
   - Check for file system access

3. **Behavioral Analysis**:
   - What does the package do during installation?
   - Does it download additional payloads?
   - Does it exfiltrate data?
   - Does it modify source code?

4. **Impact Assessment**:
   - How many projects use this package?
   - What environments were affected (dev, staging, production)?
   - Were any secrets exposed?
   - Was malicious code deployed to production?

## Known Supply Chain Attacks

### 1. SolarWinds (2020)
- **Vector**: Build system compromise
- **Impact**: 18,000+ organizations affected
- **Technique**: Trojanized software updates

### 2. Codecov (2021)
- **Vector**: Compromised bash script
- **Impact**: Hundreds of customer credentials stolen
- **Technique**: Modified Codecov Bash Uploader

### 3. ua-parser-js (2021)
- **Vector**: Maintainer account hijacking
- **Impact**: Cryptocurrency miner and credential stealer
- **Technique**: Malicious versions published to npm

### 4. event-stream (2018)
- **Vector**: Social engineering, package takeover
- **Impact**: Bitcoin wallet theft
- **Technique**: Malicious dependency injection

### 5. Dependency Confusion (2021)
- **Vector**: Namespace confusion
- **Impact**: Microsoft, Apple, PayPal, Tesla affected
- **Technique**: Public packages with internal names

### 6. Py Typosquatting (Ongoing)
- **Vector**: Typosquatting Python packages
- **Impact**: Credential theft, backdoors
- **Technique**: Packages like "requets", "urllib2"

## Attack Techniques

### Typosquatting
```
Legitimate: lodash
Malicious: loddash, lodsh, lodas
```

### Dependency Confusion
```
Internal: @company/auth-lib
Attack: Publish "auth-lib" to public npm with higher version
Result: Public package installed instead of internal
```

### Package Takeover
- Maintainer account compromise
- Abandoned package adoption
- Social engineering

### Malicious Updates
- Legitimate package compromised
- New malicious version published
- Auto-update pulls malicious version

### Transitive Dependencies
```
Your Project
 └── Dependency A (clean)
      └── Dependency B (clean)
           └── Dependency C (MALICIOUS)
```

## Prevention Measures

### 1. Private Package Manager
```bash
# Use Artifactory, Nexus, or cloud provider registries
npm config set registry https://private-npm.company.com/
```

### 2. Package Scanning
```bash
# Automated scanning in CI/CD
npm audit
snyk test
osv-scanner scan .
```

### 3. Dependency Pinning
```json
{
  "dependencies": {
    "express": "4.18.2"  // Exact version
  }
}
```

### 4. Subresource Integrity (SRI)
```html
<script src="https://cdn.example.com/script.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxHbUZ68z5cCqKSTFZX/sJlXSGQj1Qy"
        crossorigin="anonymous"></script>
```

### 5. Package Signing
```bash
# Verify signed packages
npm install <package> --verify-signatures
```

### 6. SBOM Generation & Tracking
```bash
# Generate SBOM with CycloneDX
cyclonedx-bom -o sbom.xml
# Track SBOMs in dependency-track
```

### 7. Network Segmentation
```yaml
# Restrict build environment network access
# Only allow approved package repositories
```

## Forensic Artifacts
- Build logs (dependency installation output)
- Package manager lock files (package-lock.json, yarn.lock, Pipfile.lock)
- Downloaded package archives
- Package manager cache
- Network connection logs during build
- File system modification logs
- Environment variables accessed during install
- Git commit history

## Compliance Impact
- **NIST SSDF**: Secure software development framework
- **SLSA**: Supply Chain Levels for Software Artifacts
- **PCI-DSS**: Secure software development lifecycle
- **GDPR**: Data protection by design
- **SOC 2**: Change management and monitoring
- **ISO 27001**: Supplier relationships security

## Business Impact
- **Backdoor Installation**: Persistent access to systems
- **Data Exfiltration**: Customer data, intellectual property theft
- **Credential Theft**: API keys, cloud credentials, database passwords
- **Malware Distribution**: Customers receiving backdoored software
- **Reputation Damage**: Loss of customer trust
- **Legal Liability**: GDPR violations, breach notifications
- **Financial Loss**: Incident response costs, regulatory fines

## Related Use Cases
- Container/Kubernetes - Malicious Container Image
- CICD - Unauthorized Pipeline Modification
- Insider Threat - Source Code Manipulation
- ThreatIntelligence - IOC Match with Known Malware

## Tools & Resources

**Package Scanning**:
- Snyk: https://snyk.io/
- Socket.dev: https://socket.dev/
- OSV-Scanner: https://github.com/google/osv-scanner
- Trivy: https://trivy.dev/

**SBOM Tools**:
- Syft: https://github.com/anchore/syft
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/

**Package Repositories**:
- Artifactory: https://jfrog.com/artifactory/
- Nexus Repository: https://www.sonatype.com/products/nexus-repository
- GitHub Packages: https://github.com/features/packages

## Threat Intelligence
- Sonatype's annual State of the Software Supply Chain report
- Snyk's vulnerability database
- Socket.dev's malicious package feed
- CISA Known Exploited Vulnerabilities Catalog
- NIST National Vulnerability Database

## References
- NIST Secure Software Development Framework (SSDF)
- SLSA (Supply-chain Levels for Software Artifacts)
- OWASP Top 10 - A06:2021 Vulnerable and Outdated Components
- CNCF Software Supply Chain Best Practices
- MITRE ATT&CK T1195: Supply Chain Compromise

## Notes
- Supply chain attacks are increasing dramatically
- Detection is difficult - prevention is critical
- Trust but verify: even popular packages can be compromised
- Transitive dependencies are a massive attack surface
- Dependency confusion affects 50%+ of Fortune 500 companies
- Package managers often default to public repositories (dangerous)
- Post-install scripts run with full permissions (major risk)
- Regular dependency audits are essential
- SBOM tracking enables rapid incident response
- Private package managers provide control and visibility
