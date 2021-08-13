# AWS External Account Scanner

Discover all the external trusts in your AWS and categorise them based on known and unknown entities.
AWSXenos will list all the roles in an AWS accounts and give you a list of all the unknown accounts that have trust relationships to your account.

For the "known" accounts list AWSXenos uses https://github.com/rupertbg/aws-public-account-ids and will try to get a list of all the AWS accounts in your AWS organization.
For the Org accounts list

## Why

This tool reports against the [Trusted Relationship Technique](https://attack.mitre.org/techniques/T1199/) of the ATT&CK Framework. 

Tools like [ScoutSuite](https://github.com/nccgroup/ScoutSuite/blob/db827e3d8e36e3bc7adcb8c62f2453960353c2ef/ScoutSuite/providers/aws/rules/findings/iam-assume-role-lacks-external-id-and-mfa.json) can uncover the external trusts that don't have MFA.
[Dome9](https://gsl.dome9.com/D9.AWS.IAM.61.html) can discover if there are conditions, associated.

The list goes on, however:
1. A malicious external trust can have MFA or a condition attached.
2. The accounts could be from within the AWS Organization, from a known provider (see [accounts.json](AWSXenos/accounts.json)), or unknown
3. The checks helps you organise and verify if you still have a need for these trusts and if new trusts are introduced.


## How to run

```sh
pip install AWSXenos
AWSXenos --json --html
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

## TODO
- [ ] Run as lambda
- [ ] HTML Report
- [ ] Return JSON