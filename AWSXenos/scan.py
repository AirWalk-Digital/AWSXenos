#!/usr/bin/env python3

import argparse
from collections import defaultdict
from os import write
from typing import Any, Optional, Dict, List, DefaultDict, Set
import json
import sys

from finding import Finding
from report import Report

import boto3  # type: ignore
from policyuniverse.arn import ARN  # type: ignore
from policyuniverse.policy import Policy  # type: ignore


class Scan:
    def __init__(self, exclude_service: Optional[bool] = True, exclude_aws: Optional[bool] = True) -> None:
        self.roles = self._get_roles(exclude_service, exclude_aws)
        self.accounts = self.get_all_accounts()
        self.findings = self.populate_findings(self.accounts, self.roles)

    def get_org_accountids(self) -> Set:
        """Get Account Ids from the AWS Organization

        Returns:
            Set: A Set of Account Ids
        """
        accounts = set()
        orgs = boto3.client("organizations")
        paginator = orgs.get_paginator("list_accounts")
        try:
            account_iterator = paginator.paginate()
            for account_resp in account_iterator:
                for account in account_resp["Accounts"]:
                    accounts.add(account["Id"])
            return accounts
        except Exception as e:
            print("[!] - Failed to get organization accounts")
            print(e)
        return accounts

    def _get_roles(
        self, exclude_service: Optional[bool] = True, exclude_aws: Optional[bool] = True
    ) -> DefaultDict[str, str]:
        """Get a list of roles from the AWS Account

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
                    roles[role["RoleName"]] = role["AssumeRolePolicyDocument"]

        return roles

    def get_all_accounts(self) -> DefaultDict[str, Set]:
        """Get all known accounts and from the AWS Organization

        Returns:
            DefaultDict[str, Set]: Key of account type. Value account ids
        """
        accounts = defaultdict(set)
        with open("accounts.json", "r") as f:
            known_accounts = json.load(f)
            for known_account in known_accounts:
                accounts["known_accounts"].add(known_account["id"])
        accounts["org_accounts"] = self.get_org_accountids()

        return accounts

    def populate_findings(
        self, accounts: DefaultDict[str, Set], roles: DefaultDict[str, str]
    ) -> DefaultDict[str, Finding]:
        """Combine all accounts with all the roles to get findings

        Args:
            accounts (DefaultDict[str, Set]): Key of account type. Value account ids
            roles (DefaultDict[str, str]): Key RoleName. Value AssumeRolePolicyDocument

        Returns:
            DefaultDict[str, Finding]: [description]
        """
        findings = defaultdict(Finding)  # type: DefaultDict[str, Finding]
        for role, assume_policy in roles.items():
            trust_policy = Policy(assume_policy)
            for unparsed_principal in trust_policy.principals:
                principal = ARN(unparsed_principal)  # type: Any
                if principal.service:
                    continue
                # Check against org_accounts
                if principal.account_number in accounts["org_accounts"]:
                    if role in findings:
                        findings[role].org_accounts.append(principal.arn)
                    else:
                        findings[role] = Finding(org_accounts=[principal.arn])
                # Check against known external accounts
                elif principal.account_number in accounts["known_accounts"]:
                    if role in findings:
                        findings[role].external_accounts.append(principal.arn)
                    else:
                        findings[role] = Finding(external_accounts=[principal.arn])
                # Unknown Account
                else:
                    if role in findings:
                        findings[role].unknown_accounts.append(principal.arn)
                    else:
                        findings[role] = Finding(unknown_accounts=[principal.arn])
        return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan an AWS Account for external trusts")

    parser.add_argument(
        "--reporttype", dest="reporttype", action="store", default="all", help="Type of report to generate. JSON or HTML"
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
        "-w", "--write-output", dest="write_output", action="store", default=False, help="Path to write output"
    )
    args = parser.parse_args()
    reporttype = args.reporttype
    service_roles = args.service_roles
    aws_service_roles = args.aws_service_roles
    write_output = args.write_output

    s = Scan(service_roles, aws_service_roles)
    r = Report(s.findings)
    if reporttype.lower() == "json":
        summary = r.JSONReport()
    elif reporttype.lower() == "html":
        summary = r.HTMLReport()
    else:
        summary = r.JSONReport()

    if write_output:
        with open(f"{write_output}", "w") as f:
            f.write(summary)

    sys.stdout.write(summary)
