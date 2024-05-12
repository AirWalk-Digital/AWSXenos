# AWS External Account Scanner

> Xenos, is Greek for stranger.

AWSXenos will list all the trust relationships in all the IAM roles, and S3 buckets, in an AWS account and give you a breakdown of all the accounts that have trust relationships to your account. It will also highlight whether the trusts have an [external ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html) or not.

https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html

This tool reports against the [Trusted Relationship Technique](https://attack.mitre.org/techniques/T1199/) of the ATT&CK Framework. 

* For the "known" accounts list AWSXenos uses a modified version of [known AWS Accounts](https://github.com/fwdcloudsec/known_aws_accounts).
* For the Org accounts list, AWSXenos will query AWS Organizations.
* AWS Services are classified separately.
* Everything else falls under unknown account
* For regional services, e.g. KMS, you'll need to run AWSXenos per region.

## Example
![HTML Report Screenshot](screenshots/report.png)

## Why

Access Analyzer falls short because:

1. You need to enable it in every region. 

2. Identified external entities might be known entities. E.g. a trusted third party vendor or a vendor you no longer trust. An Account number is seldom useful. 

3. Zone of trust is a fixed set of the AWS organisation. You won’t know if a trust between sandbox->prod has been established. 

4. Does not identify AWS Service principals. This is mainly important because of [Wiz's AWSConfig, et al vulnverabilities](http://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Breaking-The-Isolation-Cross-Account-AWS-Vulnerabilities.pdf)

## Resource Support comparison to AWS IAM Access Analyzer for cross account access

Comparison based on AWS Documentation [1](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html) and [2](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html#what-is-access-analyzer-resource-identification)

| Service | AWSXenos | Access Analyzer |
| :--: | :--: | :--: |
| S3 | :white_check_mark: |  :white_check_mark: |
| S3 ACLs | :white_check_mark: |
| S3 Glacier | :x: | :x: |
| IAM |  :white_check_mark: |  :white_check_mark: |
| KMS |  :white_check_mark: |  :white_check_mark: |
| Secrets Manager |  :white_check_mark: |  :white_check_mark: |
| Lambda | :x: |  :white_check_mark: |
| SNS | :x: |  :white_check_mark: |
| SQS | :x: |  :white_check_mark: |
| RDS Snapshots | :x: |  :white_check_mark: |
| RDS Cluster Snapshots | :x: |  :white_check_mark: |
| ECR | :x: |  :white_check_mark: |
| EFS | :x: |  :white_check_mark: |
| DynamoDB streams | :x: |  :white_check_mark: |
| DynamoDB tables | :x: |  :white_check_mark: |
| EBS Snapshots | :x: |  :white_check_mark: |
| EventBridge | :x: | :x: |
| EventBridge Schema | :x: | :x: |
| Mediastore | :x: | :x: |
| Glue | :x: | :x: |
| Kinesis Data Streams | :x: | :x: |
| Lex v2 | :x: | :x: |
| Migration Hub Orchestrator | :x: | :x: |
| OpenSearch | :x: | :x: |
| AWS PCA | :x: | :x: |
| Redshift Serverless | :x: | :x: |
| Serverless Application Repository | :x: | :x: |
| SES v2 | :x: | :x: |
| Incident Manager | :x: | :x: |
| Incident Manager Contacts | :x: | :x: |


## How to run

### Cli
```sh
pip install AWSXenos
awsxenos --reporttype HTML -w report.html
awsxenos --reporttype JSON -w report.json
```
You will get an HTML and JSON report.

See [example report](example/example.html)

You can configure the services you care about by using [your own config](awsxenos/config.yaml).

### Library

```python
from awsxenos.scan import PreScan
from awsxenos.report import Report
from awsxenos.s3 import S3
#from awsxenos.iam import IAM

prescan = PreScan()
aws_service = S3()
findings = aws_service.fetch(prescan.known)
r = Report(s.findings, s.known_accounts_data)
json_summary = r.JSON_report()
html_summary = r.HTML_report()
```

### IAM Permissions

Permissions required.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "iam:ListRoles"
        "organizations:ListAccounts",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "iam:ListRoles",
        "kms:ListKeys",
        "kms:GetKeyPolicy",
        "secretsmanager:ListSecrets",
        "secretsmanager:GetResourcePolicy",
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

## Development

```sh
python3 -m env venv
source /env/bin/activate
pip install -r requirements.txt
```

1. Create a file with the name of the service.
2. Create a class with the name of the resource that you want from that service
3. Your class must inherit from `Service` and return `Findings`

Example: 

```python
class S3(Service):

    def fetch(self, accounts: DefaultDict[str, Set] ) -> Findings:
        self._buckets = self.list_account_buckets()
        self.policies = self.get_bucket_policies()
        return super().collate(accounts, self.policies)
```
4. Add your filename and class to the config



## I want to add more known accounts
Create a PR or raise an issue. Contributions are welcome.

## Features
- [x] IAM Roles
- [x] S3 Bucket Policies and ACLs
- [x] Use as library
- [x] HTML and JSON output 
- [x] Supports AWS Services
