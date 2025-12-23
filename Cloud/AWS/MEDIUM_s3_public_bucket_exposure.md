# AWS - S3 Bucket Public Exposure

## Severity
**MEDIUM**

## Description
Detects when S3 buckets are made publicly accessible, potentially exposing sensitive data to unauthorized access.

## MITRE ATT&CK
- **Tactic**: Initial Access (TA0001), Collection (TA0009)
- **Technique**: Data from Cloud Storage Object (T1530)

## DEVO Query

```sql
from cloud.aws.cloudtrail
where eventSource = "s3.amazonaws.com"
  and eventName in ("PutBucketAcl", "PutBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock")
  and (requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI = "http://acs.amazonaws.com/groups/global/AllUsers"
    or requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    or requestParameters like "%AllUsers%"
    or requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls = "false")
select
  eventdate,
  userIdentity.principalId,
  userIdentity.arn,
  eventName,
  requestParameters.bucketName as bucket_name,
  requestParameters,
  sourceIPAddress,
  userAgent,
  awsRegion
group by bucket_name, userIdentity.arn, eventName
```

## Alert Configuration
- **Trigger**: Any public exposure configuration
- **Throttling**: 1 alert per bucket per 2 hours
- **Severity**: Medium
- **Priority**: P3

## Recommended Actions
1. Identify the S3 bucket made public
2. Verify if public access is required
3. Review bucket contents for sensitive data
4. Check S3 access logs for unauthorized access
5. Remove public access if not required
6. Implement bucket policies with least privilege
7. Enable S3 Block Public Access
8. Review who made the change
9. Scan bucket for sensitive data exposure
10. Document legitimate business need if required

## False Positive Considerations
- Public website hosting buckets
- CDN origin buckets
- Public dataset distribution
- Static asset hosting

**Tuning Recommendations**:
- Whitelist approved public buckets
- Exclude buckets with "public" or "website" in name
- Tag public buckets appropriately
- Implement approval workflow for public access

## Enrichment Opportunities
- Scan bucket contents with Macie
- Check S3 access logs
- Review bucket tagging
- Correlate with data classification
- Check CloudTrail for who made change
- Review IAM permissions of user

## S3 Public Access Scenarios
1. **Bucket ACL**: Grants to AllUsers/AuthenticatedUsers
2. **Bucket Policy**: Principal set to "*"
3. **Block Public Access Disabled**: Allows public configurations
4. **Object ACL**: Individual objects made public

## Response Playbook
1. Assess bucket's data classification
2. Review current bucket ACL and policy
3. Check S3 access logs for external access
4. If sensitive data exposed:
   - Immediately revoke public access
   - Notify security/compliance team
   - Scan logs for data exfiltration
   - Consider data breach procedures
5. If legitimate public access:
   - Verify minimum necessary access
   - Document business justification
   - Implement additional monitoring
   - Apply appropriate tags
6. Review user's permissions and recent activities

## Data Classification Check
- **Critical/Confidential**: Immediate remediation required
- **Internal**: Remove public access unless justified
- **Public**: Verify intentional and document

## Investigation Steps
- Review bucket creation date
- Check bucket versioning status
- Analyze bucket encryption settings
- Review lifecycle policies
- Check for requester pays configuration
- Review CORS configuration
- Examine bucket tags

## Preventive Controls
- Enable S3 Block Public Access (account/org level)
- Implement S3 bucket policies requiring encryption
- Use AWS Config rules for compliance
- Regular Macie scans
- IAM policies restricting PutBucketAcl
- Service Control Policies (SCPs)
- Automated remediation with Lambda

## Compliance Considerations
- GDPR: Data exposure notification may be required
- PCI-DSS: Cardholder data must not be public
- HIPAA: PHI exposure is reportable
- SOX: Financial data exposure implications

## AWS Macie Integration
- Enable Macie to scan bucket
- Check for PII/PHI exposure
- Review sensitivity scoring
- Set up automated alerts

## Automated Remediation
```python
# Lambda function to auto-remediate
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket = event['detail']['requestParameters']['bucketName']

    # Block public access
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
```

## Notes
- Not all public buckets are security issues
- Context and data classification matter
- Implement defense in depth
- Regular compliance scanning essential
