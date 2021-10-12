#!/usr/bin/env python3

import argparse
from collections import defaultdict
from re import I
from typing import Any, Optional, Dict, List, DefaultDict, Set
import json
import sys

import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore
from policyuniverse.arn import ARN  # type: ignore
from policyuniverse.policy import Policy  # type: ignore
from policyuniverse.statement import Statement, ConditionTuple  # type: ignore

from awsxenos.finding import AccountType, Finding
from awsxenos.report import Report
from awsxenos import package_path


class Scan:
    def __init__(self, exclude_service: Optional[bool] = True, exclude_aws: Optional[bool] = True) -> None:
        self.known_accounts_data = defaultdict(dict)  # type: DefaultDict[str, Dict[Any, Any]]
        self.findings = defaultdict(AccountType)  # type: DefaultDict[str, AccountType]
        self._buckets = self.list_account_buckets()
        self.roles = self.get_roles(exclude_service, exclude_aws)
        self.accounts = self.get_all_accounts()
        self.bucket_policies = self.get_bucket_policies()
        self.bucket_acls = self.get_bucket_acls()
        for resource in ["roles", "bucket_policies", "bucket_acls"]:
            if resource != "bucket_acls":
                self.findings.update(self.collate_findings(self.accounts, getattr(self, resource)))
            else:
                self.findings.update(self.collate_acl_findings(self.accounts, getattr(self, resource)))

    def get_org_accounts(self) -> DefaultDict[str, Dict]:
        """Get Account Ids from the AWS Organization

        Returns:
            DefaultDict: Key of Account Ids. Value of other Information
        """
        accounts = defaultdict(dict)  # type: DefaultDict[str, Dict]
        orgs = boto3.client("organizations")
        paginator = orgs.get_paginator("list_accounts")
        try:
            account_iterator = paginator.paginate()
            for account_resp in account_iterator:
                for account in account_resp["Accounts"]:
                    accounts[account["Id"]] = account
            return accounts
        except Exception as e:
            print("[!] - Failed to get organization accounts")
            print(e)
        return accounts

    def get_bucket_acls(self) -> DefaultDict[str, List[Dict[Any, Any]]]:
        bucket_acls = defaultdict(str)
        buckets = self._buckets
        s3 = boto3.client("s3")
        for bucket in buckets["Buckets"]:
            bucket_arn = f'arn:aws:s3:::{bucket["Name"]}'
            try:
                bucket_acls[bucket_arn] = s3.get_bucket_acl(Bucket=bucket["Name"])["Grants"]
            except ClientError as e:
                if e.response["Error"]["Code"] == "AccessDenied":
                    bucket_acls[bucket_arn] = [
                        {
                            "Grantee": {"DisplayName": "AccessDenied", "ID": "AccessDenied", "Type": "CanonicalUser"},
                            "Permission": "FULL_CONTROL",
                        }
                    ]
                else:
                    print(e)
                    continue
        return bucket_acls

    def get_bucket_policies(self) -> DefaultDict[str, Dict[Any, Any]]:
        """Get a dictionary of buckets and their policies from the AWS Account

        Returns:
            DefaultDict[str, str]: Key of BucketARN, Value of PolicyDocument
        """
        bucket_policies = defaultdict(str)
        buckets = self._buckets
        s3 = boto3.client("s3")
        for bucket in buckets["Buckets"]:
            bucket_arn = f'arn:aws:s3:::{bucket["Name"]}'
            try:
                bucket_policies[bucket_arn] = json.loads(s3.get_bucket_policy(Bucket=bucket["Name"])["Policy"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "AccessDenied":
                    bucket_policies[bucket_arn] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AccessDeniedOnResource",
                                "Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
                                "Action": ["s3:*"],
                                "Resource": f"{bucket_arn}",
                            }
                        ],
                    }
                    continue
                elif e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
                else:
                    print(e)
                    continue
        return bucket_policies

    def get_roles(
        self, exclude_service: Optional[bool] = True, exclude_aws: Optional[bool] = True
    ) -> DefaultDict[str, Dict[Any, Any]]:
        """Get a dictionary of roles and their policies from the AWS Account

        Args:
            exclude_service (Optional[bool], optional): exclude roles starting with /service-role/. Defaults to True.
            exclude_aws (Optional[bool], optional): exclude roles starting with /aws-service-role/. Defaults to True.

        Returns:
            DefaultDict[str, str]: Key of RoleNames, Value of AssumeRolePolicyDocument
        """
        roles = defaultdict(str)
        iam = boto3.client("iam")
        paginator = iam.get_paginator("list_roles")
        role_iterator = paginator.paginate()
        for role_resp in role_iterator:
            for role in role_resp["Roles"]:
                if role["Path"] == "/service-role/" and exclude_service:
                    continue
                elif role["Path"].startswith("/aws-service-role/") and exclude_aws:
                    continue
                else:
                    roles[role["Arn"]] = role["AssumeRolePolicyDocument"]

        return roles

    def list_account_buckets(self) -> Dict[str, Dict[Any, Any]]:
        s3 = boto3.client("s3")
        return s3.list_buckets()

    def get_all_accounts(self) -> DefaultDict[str, Set]:
        """Get all known accounts and from the AWS Organization

        Returns:
            DefaultDict[str, Set]: Key of account type. Value account ids
        """
        accounts = defaultdict(set)  # type: DefaultDict[str, Set]

        with open(f"{package_path.resolve().parent}/accounts.json", "r") as f:
            accounts_file = json.load(f)
            for account in accounts_file:
                self.known_accounts_data[account["id"]] = account

        accounts["known_accounts"] = set(self.known_accounts_data.keys())

        # Populate Org accounts
        org_accounts = self.get_org_accounts()
        aws_canonical_user = self._buckets["Owner"]

        # Add to the set of org_accounts
        accounts["org_accounts"] = set(org_accounts.keys())
        accounts["org_accounts"].add(aws_canonical_user["ID"])

        # Combine the metadata
        self.known_accounts_data[aws_canonical_user["ID"]] = {"owner": aws_canonical_user["DisplayName"]}
        self.known_accounts_data = self.known_accounts_data | org_accounts  # type: ignore

        return accounts

    def collate_acl_findings(
        self, accounts: DefaultDict[str, Set], resources: DefaultDict[str, List[Dict[Any, Any]]]
    ) -> DefaultDict[str, AccountType]:
        """Combine all accounts with all the acls to classify findings

        Args:
            accounts (DefaultDict[str, Set]): [description]
            resources (DefaultDict[str, List[Dict[Any, Any]]]): [description]

        Returns:
            DefaultDict[str, AccountType]: [description]
        """
        findings = defaultdict(AccountType)  # type: DefaultDict[str, AccountType]

        for resource, grants in resources.items():
            for grant in grants:
                if grant["Grantee"]["ID"] == self._buckets["Owner"]["ID"]:
                    continue  # Don't add if the ACL is of the same account
                elif grant["Grantee"]["ID"] in accounts["known_accounts"]:
                    findings[resource].known_accounts.append(Finding(principal=grant["Grantee"]["ID"], external_id=True))
                elif grant["Grantee"]["ID"] in accounts["org_accounts"]:
                    findings[resource].org_accounts.append(Finding(principal=grant["Grantee"]["ID"], external_id=True))
                else:
                    findings[resource].unknown_accounts.append(
                        Finding(principal=grant["Grantee"]["ID"], external_id=True)
                    )
        return findings

    def collate_findings(
        self, accounts: DefaultDict[str, Set], resources: DefaultDict[str, Dict[Any, Any]]
    ) -> DefaultDict[str, AccountType]:
        """Combine all accounts with all the resources to classify findings

        Args:
            accounts (DefaultDict[str, Set]): Key of account type. Value account ids
            resources (DefaultDict[str, Dict[Any, Any]]): Key ResourceIdentifier. Value Dict PolicyDocument

        Returns:
            DefaultDict[str, AccountType]: Key of ARN, Value of AccountType
        """
        findings = defaultdict(AccountType)  # type: DefaultDict[str, AccountType]
        for resource, policy_document in resources.items():
            try:
                policy = Policy(policy_document)
            except:
                print(policy_document)
                continue
            for unparsed_principal in policy.whos_allowed():
                try:
                    principal = ARN(unparsed_principal.value)  # type: Any
                except Exception as e:
                    print(e)
                    findings[resource].known_accounts.append(Finding(principal=unparsed_principal, external_id=True))
                    continue
                # Check if Principal is an AWS Service
                if principal.service:
                    findings[resource].aws_services.append(Finding(principal=principal.arn, external_id=True))
                # Check against org_accounts
                elif principal.account_number in accounts["org_accounts"]:
                    findings[resource].org_accounts.append(Finding(principal=principal.arn, external_id=True))
                # Check against known external accounts
                elif (
                    principal.account_number in accounts["known_accounts"]
                    or ConditionTuple(category="saml-endpoint", value="https://signin.aws.amazon.com/saml")
                    in policy.whos_allowed()
                ):
                    sts_set = False
                    for pstate in policy.statements:
                        if "sts" in pstate.action_summary():
                            try:
                                conditions = [
                                    k.lower() for k in list(pstate.statement["Condition"]["StringEquals"].keys())
                                ]
                                if "sts:externalid" in conditions:
                                    findings[resource].known_accounts.append(
                                        Finding(principal=principal.arn, external_id=True)
                                    )
                            except:
                                findings[resource].known_accounts.append(
                                    Finding(principal=principal.arn, external_id=False)
                                )
                            finally:
                                sts_set = True
                                break
                    if not sts_set:
                        findings[resource].known_accounts.append(Finding(principal=principal.arn, external_id=False))

                # Unknown Account
                else:
                    sts_set = False
                    for pstate in policy.statements:
                        if "sts" in pstate.action_summary():
                            try:
                                conditions = [
                                    k.lower() for k in list(pstate.statement["Condition"]["StringEquals"].keys())
                                ]
                                if "sts:externalid" in conditions:
                                    findings[resource].unknown_accounts.append(
                                        Finding(principal=principal.arn, external_id=True)
                                    )
                            except:
                                findings[resource].unknown_accounts.append(
                                    Finding(principal=principal.arn, external_id=False)
                                )
                            finally:
                                break
                    if not sts_set:
                        findings[resource].unknown_accounts.append(Finding(principal=principal.arn, external_id=False))
        return findings


def cli():
    parser = argparse.ArgumentParser(description="Scan an AWS Account for external trusts")

    parser.add_argument(
        "--reporttype",
        dest="reporttype",
        action="store",
        default="all",
        help="Type of report to generate. JSON or HTML",
    )
    parser.add_argument(
        "--include_service_roles",
        dest="service_roles",
        action="store_false",
        default=False,
        help="Include service roles in the report",
    )
    parser.add_argument(
        "--include_aws_service_roles",
        dest="aws_service_roles",
        action="store_false",
        default=False,
        help="Include AWS roles in the report",
    )
    parser.add_argument(
        "-w",
        "--write-output",
        dest="write_output",
        action="store",
        default=False,
        help="Path to write output",
    )
    args = parser.parse_args()
    reporttype = args.reporttype
    service_roles = args.service_roles
    aws_service_roles = args.aws_service_roles
    write_output = args.write_output

    s = Scan(service_roles, aws_service_roles)
    r = Report(s.findings, s.known_accounts_data)
    if reporttype.lower() == "json":
        summary = r.JSON_report()
    elif reporttype.lower() == "html":
        summary = r.HTML_report()
    else:
        summary = r.JSON_report()

    if write_output:
        with open(f"{write_output}", "w") as f:
            f.write(summary)

    sys.stdout.write(summary)


if __name__ == "__main__":
    cli()
