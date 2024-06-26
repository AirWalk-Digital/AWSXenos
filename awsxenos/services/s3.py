import json
from typing import Any, Dict

import boto3  # type: ignore
from botocore.client import ClientError  # type: ignore

from awsxenos.finding import Accounts, Finding, Findings, Resources, Service

"""S3 Buckets Resource Policy """


class S3(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        self._buckets = self.list_account_buckets()
        self.policies = self.get_bucket_policies()
        return super().collate(accounts, self.policies)

    def list_account_buckets(self) -> Dict[str, Dict[Any, Any]]:
        s3 = boto3.client("s3")
        return s3.list_buckets()

    def get_bucket_policies(self) -> Resources:
        """Get a dictionary of buckets and their policies from the AWS Account

        Returns:
            DefaultDict[str, str]: Key of BucketARN, Value of PolicyDocument
        """
        bucket_policies = Resources()
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
                                "Principal": {"AWS": "*"},
                                "Action": ["s3:*"],
                                "Resource": f"{bucket_arn}",
                            }
                        ],
                    }
                    continue
                elif e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
                else:
                    bucket_policies[bucket_arn] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "Exception",
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": ["s3:*"],
                                "Resource": f"{bucket_arn}",
                            }
                        ],
                    }
        return bucket_policies


"""S3 Buckets ACLs"""


class S3ACL(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        self._buckets = self.list_account_buckets()
        self.policies = self.get_acls()
        return self.custom_collate(accounts, self.policies)

    def list_account_buckets(self) -> Dict[str, Dict[Any, Any]]:
        s3 = boto3.client("s3")
        return s3.list_buckets()

    def custom_collate(self, accounts: Accounts, resources: Resources) -> Findings:
        """Combine all accounts with all the acls to classify findings

        Args:
            accounts (DefaultDict[str, Set]): [description]
            resources (DefaultDict[str, List[Dict[Any, Any]]]): [description]

        Returns:
            DefaultDict[str, Accounts]: [description]
        """
        findings = Findings()
        for resource, grants in resources.items():
            for grant in grants:
                if grant["Grantee"]["ID"] == self._buckets["Owner"]["ID"]:
                    continue
                elif grant["Grantee"]["ID"] in accounts["known_accounts"]:
                    findings[resource].known_accounts.append(
                        Finding(principal=grant["Grantee"]["ID"], external_id=True)
                    )
                elif grant["Grantee"]["ID"] in accounts["org_accounts"]:
                    findings[resource].org_accounts.append(Finding(principal=grant["Grantee"]["ID"], external_id=True))
                else:
                    findings[resource].unknown_accounts.append(
                        Finding(principal=grant["Grantee"]["ID"], external_id=True)
                    )
        return findings

    def get_acls(self) -> Resources:
        bucket_acls = Resources()
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
                    bucket_acls[bucket_arn] = [
                        {
                            "Grantee": {"DisplayName": "Exception", "ID": "Exception", "Type": "CanonicalUser"},
                            "Permission": "FULL_CONTROL",
                        }
                    ]
        return bucket_acls


"""S3 Glacier Vault Policies"""


class S3Glacier(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_vault_policies())

    def get_vault_policies(self) -> Resources:
        vaults = Resources()
        glacier = boto3.client("glacier")
        paginator = glacier.get_paginator("list_vaults")
        glacier_iterator = paginator.paginate()
        for glacier_resp in glacier_iterator:
            if "VaultList" not in glacier_resp:
                continue
            for vault in glacier_resp["VaultList"]:
                try:
                    vaults[vault["VaultARN"]] = json.loads(
                        glacier.get_vault_access_policy(vaultName=vault["VaultName"])["policy"]["Policy"]
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "AccessDenied":
                        vaults[vault["VaultARN"]] = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AccessDeniedOnResource",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": ["glacier:*"],
                                    "Resource": f'{vault["VaultARN"]}',
                                }
                            ],
                        }
                        continue
                    elif e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                        continue
                    else:
                        vaults[vault["VaultARN"]] = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "Exception",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": ["glacier:*"],
                                    "Resource": f'{vault["VaultARN"]}',
                                }
                            ],
                        }
        return vaults
