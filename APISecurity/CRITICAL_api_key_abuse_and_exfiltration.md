# API Security - API Key Abuse and Exfiltration

## Severity
**CRITICAL**

## Description
Detects unauthorized use, abuse, or exfiltration of API keys including excessive API calls, geographic anomalies, usage from unexpected IP addresses, privilege escalation via API, and potential API key theft through logs, error messages, or source code repositories.

## MITRE ATT&CK
- **Tactic**: Credential Access (TA0006), Collection (TA0009), Exfiltration (TA0010)
- **Technique**: Unsecured Credentials (T1552), Steal Application Access Token (T1528), Exfiltration Over Web Service (T1567)
- **Sub-technique**: Credentials in Files (T1552.001), Cloud Instance Metadata API (T1552.005)

## DEVO Query

```sql
from api.gateway
select eventdate
select api_key_id
select api_key_name
select user_id
select src_ip
select endpoint
select http_method
select response_code
select response_time_ms
select bytes_transferred
select user_agent
select count() as request_count
select countdistinct(endpoint) as unique_endpoints
select countdistinct(src_ip) as unique_ips
select sum(bytes_transferred) as total_bytes
select mm2country(src_ip) as source_country
select mm2city(src_ip) as source_city
where (
    -- High request volume (API abuse/scraping)
    request_count > 1000 in 5m

    -- Geographic anomaly
    or not `in`(expected_countries_for_key, mm2country(src_ip))

    -- Multiple IPs using same API key (potential key theft)
    or unique_ips > 5 in 1h

    -- Excessive data transfer (data exfiltration)
    or total_bytes > 1073741824  -- 1 GB in 5 minutes

    -- Access to privileged endpoints
    or (weakhas(endpoint, "/admin")
        or weakhas(endpoint, "/internal")
        or weakhas(endpoint, "/debug")
        or weakhas(endpoint, "/users")
        or weakhas(endpoint, "/keys")
        or weakhas(endpoint, "/secrets"))

    -- Elevated error rates (reconnaissance/fuzzing)
    or (response_code >= 400 and request_count > 50 in 5m)

    -- After-hours API usage (for business hour restricted keys)
    or (hour(eventdate) < 6 or hour(eventdate) > 22)
       and api_key_type = "business_hours_only"

    -- Suspicious user agents
    or weakhas(user_agent, "curl")
       and weakhas(user_agent, "python")
       and weakhas(user_agent, "scanner")
       and weakhas(user_agent, "bot")
  )
group by api_key_id, src_ip, user_id
every 5m
having request_count > 100 or unique_endpoints > 20
```

## API Key in Logs Detection

```sql
from logs.application
select eventdate
select hostname
select application
select log_level
select log_message
select user
where (
    -- API key patterns
    weakhas(log_message, "api_key=")
    or weakhas(log_message, "apikey=")
    or weakhas(log_message, "api-key=")
    or weakhas(log_message, "Authorization: Bearer")
    or weakhas(log_message, "X-API-Key:")

    -- AWS keys
    or log_message like "%AKIA%"  -- AWS Access Key

    -- Generic secret patterns
    or weakhas(log_message, "password=")
    or weakhas(log_message, "token=")
    or weakhas(log_message, "secret=")
  )
  and `in`("INFO", "DEBUG", "WARN", log_level)
group by application, log_message
every 10m
```

## Source Code Repository Scanning

```sql
from git.commits
select eventdate
select repository_name
select branch
select commit_hash
select author
select commit_message
select added_files
select modified_files
select diff_content
where (
    -- API keys in commits
    weakhas(diff_content, "AKIA")  -- AWS
    or weakhas(diff_content, "AIza")  -- Google API
    or weakhas(diff_content, "sk_live_")  -- Stripe
    or weakhas(diff_content, "ghp_")  -- GitHub Personal Access Token
    or weakhas(diff_content, "glpat-")  -- GitLab PAT
    or weakhas(diff_content, "xoxb-")  -- Slack Bot Token

    -- Generic patterns
    or (weakhas(diff_content, "api_key") and diff_content like "%=%")
    or (weakhas(diff_content, "apiKey") and diff_content like "%:%")
  )
  and repository_visibility = "public"
group by repository_name, commit_hash
every 30m
```

## Alert Configuration
- **Trigger**:
  - Excessive API usage (>1000 req/5min)
  - Geographic anomaly (unexpected country)
  - Multiple IPs using same key (>5 in 1 hour)
  - API key exposed in logs or source code
  - Large data transfer (>1GB in 5 minutes)
- **Throttling**: 5 minute window, group by API key and source IP
- **Severity**: Critical
- **Priority**: P1
- **Auto-Response**: Rate limit or temporary key suspension on excessive usage

## Recommended Actions
1. **IMMEDIATE**: Suspend or rotate the compromised API key
2. Identify the scope of unauthorized access:
   ```bash
   # Query API logs for all usage of the key
   grep "api_key=<key-id>" /var/log/api/*.log
   ```
3. Review all API calls made with the compromised key
4. Check for data exfiltration or unauthorized data access
5. Identify the source of the compromise:
   - Exposed in logs?
   - Committed to public repository?
   - Stolen from developer workstation?
   - Phished from user?
6. Block the source IP addresses if malicious
7. Notify affected users if their data was accessed
8. Generate new API key for legitimate users
9. Implement stricter API key management policies
10. Enable API request logging and monitoring
11. Review application code for insecure key handling
12. Scan all repositories for exposed secrets

## False Positive Considerations
- Legitimate high-volume API consumers (batch jobs, integrations)
- VPN or proxy IP changes for legitimate users
- Distributed architectures using shared API keys
- Load testing or performance benchmarking
- CI/CD pipelines with fluctuating IP addresses

**Tuning Recommendations**:
- Whitelist approved high-volume API consumers
- Allow expected IP ranges for legitimate services
- Baseline normal API usage patterns per key
- Exclude development/staging environment keys
- Implement separate keys for batch vs. interactive usage
- Use IP allowlisting for production keys where possible

## Enrichment Opportunities
- API key creation date and creator
- Historical usage patterns for the key
- Geolocation history for the key
- User behavior analytics (is this normal for this user?)
- Threat intelligence on source IPs
- Application logs correlation
- Related API keys by same user
- Data accessed via API calls
- Rate limit history

## Response Playbook

### Phase 1: Immediate Containment (0-5 minutes)
1. **Suspend Compromised API Key**:
   ```bash
   # AWS
   aws iam delete-access-key --access-key-id <AKIA...> --user-name <username>

   # Custom API
   curl -X DELETE https://api.company.com/admin/keys/<key-id> \
     -H "Authorization: Bearer <admin-token>"
   ```

2. **Block Malicious IP Addresses**:
   ```bash
   # Add to firewall/WAF
   aws waf update-ip-set --ip-set-id <id> --updates Action=INSERT,IPSetDescriptor={Type=IPV4,Value=<ip>/32
   ```

3. **Enable Enhanced Monitoring**:
   ```bash
   # Increase API logging verbosity
   # Enable real-time alerting for related keys
   ```

### Phase 2: Investigation (5-60 minutes)
1. **Analyze API Usage**:
   ```bash
   # Extract all API calls by the compromised key
   cat /var/log/api/access.log | grep "<api-key-id>" | jq '{time:.timestamp, ip:.src_ip, endpoint:.endpoint, response:.response_code}'
   ```

2. **Determine Compromise Vector**:
   - **Check logs for exposure**:
     ```bash
     grep -r "api_key=" /var/log/application/
     grep -r "Authorization: Bearer" /var/log/nginx/
     ```

   - **Scan repositories**:
     ```bash
     # Use GitLeaks, TruffleHog, or git-secrets
     trufflehog git https://github.com/company/repo --only-verified
     ```

   - **Check S3/storage for exposed configs**:
     ```bash
     aws s3 ls s3://bucket/config/ | grep -E "\.env|config\.json|secrets"
     ```

3. **Assess Data Access**:
   - What data was queried via API?
   - Were any modifications made (POST/PUT/DELETE)?
   - Was PII or sensitive data accessed?

### Phase 3: Scope Assessment (1-4 hours)
1. **Identify Affected Resources**:
   ```sql
   SELECT endpoint, COUNT(*) as access_count
   FROM api_logs
   WHERE api_key_id = '<compromised-key>'
     AND timestamp > '<compromise-time>'
   GROUP BY endpoint
   ORDER BY access_count DESC;
   ```

2. **Check for Lateral Movement**:
   - Did the attacker create new API keys?
   - Were additional credentials accessed?
   - Was cloud metadata service queried (AWS IMDS)?

3. **Data Exfiltration Analysis**:
   ```sql
   SELECT SUM(response_size_bytes) as total_exfiltrated
   FROM api_logs
   WHERE api_key_id = '<compromised-key>'
     AND response_code = 200
     AND timestamp > '<compromise-time>';
   ```

### Phase 4: Eradication (2-8 hours)
1. **Rotate All Related Credentials**:
   ```bash
   # Rotate API keys for affected services
   # Rotate database passwords if accessed
   # Rotate cloud provider credentials
   ```

2. **Remove Exposed Secrets from Code**:
   ```bash
   # Use BFG Repo-Cleaner to remove secrets from Git history
   bfg --replace-text secrets.txt repo.git
   cd repo.git
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive

   # Force push cleaned history
   git push --force
   ```

3. **Patch Vulnerable Applications**:
   - Fix logging of sensitive data
   - Implement secure credential storage
   - Add secrets scanning to CI/CD

### Phase 5: Recovery & Prevention (4-24 hours)
1. **Issue New API Keys**:
   ```bash
   # Generate new keys for legitimate users
   # Communicate new keys securely (not via email)
   ```

2. **Implement API Key Best Practices**:
   ```yaml
   # Rotate keys regularly
   rotation_policy:
     frequency: 90_days
     auto_rotate: true

   # Scope keys to minimum necessary permissions
   permissions:
     - read:users
     # NOT: *:*

   # IP allowlisting
   allowed_ips:
     - 203.0.113.0/24

   # Rate limiting
   rate_limit:
     requests_per_minute: 100
     burst: 50
   ```

3. **Secrets Management**:
   ```bash
   # Use secrets manager (AWS Secrets Manager, HashiCorp Vault)
   aws secretsmanager create-secret \
     --name prod/api/key \
     --secret-string "<api-key>"

   # Application retrieves at runtime
   ```

4. **Automated Secrets Scanning**:
   ```yaml
   # GitHub Actions example
   name: Secret Scan
   on: [push, pull_request]
   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
           with:
             fetch-depth: 0
         - name: GitLeaks
           uses: gitleaks/gitleaks-action@v2
         - name: TruffleHog
           uses: trufflesecurity/trufflehog@main
   ```

## Investigation Steps

1. **Timeline Reconstruction**:
   - When was the API key first compromised?
   - When did abnormal usage begin?
   - What was the peak usage?

2. **Impact Assessment**:
   - How much data was accessed?
   - What type of data (PII, financial, health)?
   - Were any write operations performed?

3. **Attribution**:
   - Source IP addresses (who/where?)
   - User-Agent analysis
   - Behavioral patterns
   - Threat intelligence correlation

4. **Root Cause**:
   - How was the key exposed?
   - Was it preventable?
   - Which security control failed?

## Common API Key Exposure Vectors

### 1. Source Code Repositories
```python
# BAD - hardcoded API key
api_key = "AKIA1234567890ABCDEF"
response = requests.get(url, headers={"X-API-Key": api_key})
```

### 2. Application Logs
```
[INFO] API request: GET /api/users?api_key=secret_key_12345
[ERROR] Authentication failed for key: AKIA1234567890ABCDEF
```

### 3. Client-Side Code
```javascript
// BAD - exposed in browser
const API_KEY = "AIzaSyD1234567890abcdefg";
fetch(`https://api.example.com/data?key=${API_KEY}`);
```

### 4. Configuration Files
```yaml
# config.yml committed to public repo
database:
  host: db.example.com
  password: super_secret_password
api:
  key: AKIA1234567890ABCDEF
```

### 5. Cloud Metadata Service (IMDS)
```bash
# From compromised EC2 instance
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```

### 6. Environment Variables (Exposed)
```dockerfile
# BAD - in Dockerfile
ENV API_KEY=secret_key_12345
```

### 7. Error Messages
```
API Error: Invalid API key 'AKIA1234567890ABCDEF' for endpoint /admin
```

## API Abuse Patterns

### Excessive API Calls (Scraping/DoS)
```
Normal: 10 req/min
Attack: 10,000 req/min
```

### Credential Stuffing
```
POST /api/login
{"username": "user1", "password": "password123"}
... 1000s of attempts with different credentials
```

### Enumeration
```
GET /api/users/1
GET /api/users/2
GET /api/users/3
... sequential ID enumeration
```

### Data Exfiltration
```
GET /api/customers?limit=10000&offset=0
GET /api/customers?limit=10000&offset=10000
... downloading entire database
```

### Privilege Escalation
```
GET /api/user/profile  -- Normal
GET /api/admin/users  -- Privilege escalation attempt
```

## Prevention Measures

### 1. Never Hardcode API Keys
```python
# GOOD - use environment variables
import os
api_key = os.environ.get("API_KEY")
```

### 2. Use Secrets Managers
```python
# AWS Secrets Manager
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/api/key')
api_key = json.loads(secret['SecretString'])['api_key']
```

### 3. Implement Rate Limiting
```python
# Flask-Limiter example
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_api_key)

@app.route("/api/data")
@limiter.limit("100 per minute")
def api_endpoint():
    return data
```

### 4. IP Allowlisting
```python
ALLOWED_IPS = ['203.0.113.0/24', '198.51.100.0/24']

def check_ip(request_ip):
    return any(ipaddress.ip_address(request_ip) in ipaddress.ip_network(cidr)
               for cidr in ALLOWED_IPS)
```

### 5. API Key Scoping
```json
{
  "api_key": "key_12345",
  "permissions": [
    "read:users",
    "write:logs"
  ],
  "resources": [
    "/api/v1/users",
    "/api/v1/logs"
  ],
  "rate_limit": 1000
}
```

### 6. Short-Lived Tokens
```python
# JWT with 1-hour expiration
token = jwt.encode({
    'user_id': user_id,
    'exp': datetime.utcnow() + timedelta(hours=1)
}, SECRET_KEY)
```

### 7. Secrets Scanning in CI/CD
```yaml
# .github/workflows/secret-scan.yml
- name: Gitleaks
  run: |
    docker run -v ${PWD}:/path zricethezav/gitleaks:latest \
      detect --source="/path" --no-git
```

### 8. Monitoring & Alerting
```python
# Monitor for anomalies
if request_count > baseline * 3:
    alert("API abuse detected", api_key=key)

if source_country not in allowed_countries:
    alert("Geographic anomaly", api_key=key, country=source_country)
```

## Forensic Artifacts
- API access logs (timestamp, endpoint, response code, IP, key ID)
- Application logs (may contain key exposure)
- WAF/Load balancer logs
- Git commit history
- CI/CD pipeline logs
- Cloud provider audit logs (CloudTrail, Azure Activity Log)
- Network packet captures
- SIEM correlation data

## Compliance Impact
- **PCI-DSS**: Requirement 3.4 (Render PAN unreadable), 8.2 (Authentication)
- **GDPR**: Article 32 (Security of processing), Data breach notification
- **HIPAA**: Access controls for PHI, audit logging
- **SOC 2**: Access control, monitoring, incident response
- **ISO 27001**: A.9.4 (Access control), A.14.2 (Security in development)

## Business Impact
- **Data Breach**: Unauthorized access to customer/business data
- **Financial Loss**: API abuse costs (compute, bandwidth)
- **Service Degradation**: DoS from excessive API calls
- **Reputation Damage**: Customer trust erosion
- **Regulatory Fines**: GDPR, HIPAA, PCI-DSS violations
- **Competitive Disadvantage**: Intellectual property theft
- **Legal Liability**: Customer lawsuits, regulatory action

## Related Use Cases
- SupplyChain - Malicious Dependency Injection (keys in dependencies)
- InsiderThreat - Credential Theft
- Cloud/AWS - IAM Access Key Exposure
- DLP - Sensitive Data Upload (keys uploaded to external sites)

## Tools & Resources

**Secrets Detection**:
- GitLeaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- git-secrets: https://github.com/awslabs/git-secrets
- detect-secrets: https://github.com/Yelp/detect-secrets

**API Security**:
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- Burp Suite: API testing
- Postman: API monitoring

**Secrets Management**:
- HashiCorp Vault: https://www.vaultproject.io/
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

## References
- OWASP API Security Top 10 - API2:2023 Broken Authentication
- MITRE ATT&CK T1552: Unsecured Credentials
- NIST SP 800-63B: Digital Identity Guidelines
- CIS AWS Foundations Benchmark: IAM key rotation

## Notes
- API keys in logs/code is one of the most common security mistakes
- Public GitHub repos are continuously scraped for exposed secrets
- Automated bots exploit exposed keys within minutes
- Rate limiting is essential defense against API abuse
- Never trust client-side API key protection (always leaks)
- Use OAuth 2.0 or similar for production applications
- Implement monitoring for anomalous API usage patterns
- Regular API key rotation reduces compromise window
- Secrets managers are not optional for production systems
