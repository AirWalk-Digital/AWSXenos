# AWS External Account Scanner

> Xenos, is Greek for stranger.

AWSXenos will list all the trust relationships in all the IAM roles, and S3 buckets, in an AWS account and give you a breakdown of all the accounts that have trust relationships to your account.

This tool reports against the [Trusted Relationship Technique](https://attack.mitre.org/techniques/T1199/) of the ATT&CK Framework. 

* For the "known" accounts list AWSXenos uses https://github.com/rupertbg/aws-public-account-ids.
* For the Org accounts list AWSXenos query AWS Organizations.
* AWS Services are classified separately.
* Everything else falls under unknown account

## Example
![HTML Report Screenshot](screenshots/report.png)

## Why

Access Analyzer falls short because:

1. You need to enable it in every region. 

2. Identified external entities might be known entities. E.g. a trusted third party vendor or a vendor you no longer trust. An Account number is seldom useful. 

3. Zone of trust is a fixed set of the AWS organisation. You won’t know if a trust between sandbox->prod has been established. 

4. Does not identify AWS Service principals. This is mainly important because of [Wiz's AWSConfig, et al vulnverabilities](http://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Breaking-The-Isolation-Cross-Account-AWS-Vulnerabilities.pdf)


## How to run

### Cli
```sh
pip install AWSXenos
awsxenos --reporttype HTML -w report.html
awsxenos --reporttype JSON -w report.json
```
You will get an HTML and JSON report.

See (example report)[example/example.html]

### Library

```python
from awsxenos.scan import Scan
from awsxenos.report import Report

s = Scan()
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
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl"
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
## I want to add more known accounts
Create a PR or raise an issue. Contributions are welcome.

## Features
- [x] IAM Roles
- [x] S3 Bucket Policies and ACLs
- [x] Use as library
- [x] HTML and JSON output 
- [x] Supports AWS Services

## TODO
- [ ] Add support for more resource policies services, e.g. SecretsManager, KSM, SNS, SQS, Lambda
- [ ] Add support for Cognito, RAM
- [ ] Add support for VPCE