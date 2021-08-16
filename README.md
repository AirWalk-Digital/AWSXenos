# AWS External Account Scanner

> Xenos, is Greek for stranger.

AWSXenos will list all the trust relationships in all the roles in an AWS account and give you a breakdown of all the accounts that have trust relationships to your account.

This tool reports against the [Trusted Relationship Technique](https://attack.mitre.org/techniques/T1199/) of the ATT&CK Framework. 

* For the "known" accounts list AWSXenos uses https://github.com/rupertbg/aws-public-account-ids.
* For the Org accounts list AWSXenos query AWS Organizations.
* AWS Services are classified separately.
* Everything else falls under unknown account

## Why

Access Analyzer falls short because
A. You need to enable it in every region
B. Identified external entities might be known entities. E.g. a trusted third party vendor. 

Tools like [ScoutSuite](https://github.com/nccgroup/ScoutSuite/blob/db827e3d8e36e3bc7adcb8c62f2453960353c2ef/ScoutSuite/providers/aws/rules/findings/iam-assume-role-lacks-external-id-and-mfa.json) can uncover the external trusts that don't have MFA.
[Dome9](https://gsl.dome9.com/D9.AWS.IAM.61.html) can discover if there are conditions, associated.

The list goes on, however:
1. A malicious external trust can have MFA or a condition attached.
2. The accounts could be from within the AWS Organization, from a known provider (see [accounts.json](AWSXenos/accounts.json)), or unknown
3. The checks helps you organise and verify if you still have a need for these trusts and if new trusts are introduced.


## How to run

```sh
pip install AWSXenos
AWSXenos --reporttype HTML -w report.html
```
You will get a JSON output and an HTML report.
See example report here

Policy should like this.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "iam:ListRoles"
        "organizations:ListAccounts"
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
./scan.py
```
## I want to add more known accounts
Create a PR

## Features
- [ ] Import as library/package
- [x] HTML and JSON Report 
- [x] Support AWS Services. [See Wiz's AWSConfig, et al vulnverabilities](http://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Breaking-The-Isolation-Cross-Account-AWS-Vulnerabilities.pdf)

## TODO
- [ ] Add support for resource policies services, e.g. SNS, SQS, S3, Lambda
- [ ] Add support for Cognito, RAM
- [ ] Add support for VPCE