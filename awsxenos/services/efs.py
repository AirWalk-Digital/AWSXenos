import json

import boto3  # type: ignore
from botocore.client import ClientError  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""EFS Resource Policies"""


class EFSResource(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_efs_policies())

    def get_efs_policies(self) -> Resources:
        filesystems = Resources()
        efs = boto3.client("efs")
        paginator = efs.get_paginator("describe_file_systems")
        for page in paginator.paginate():
            if "FileSystems" not in page:
                continue
            for fs in page["FileSystems"]:
                try:
                    filesystems[fs["FileSystemArn"]] = json.loads(
                        efs.describe_file_system_policy(FileSystemId=fs["FileSystemId"])["Policy"]
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "PolicyNotFound":
                        continue
                    else:
                        filesystems[fs["FileSystemArn"]] = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "Exception",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": ["efs:*"],
                                    "Resource": "*",
                                }
                            ],
                        }

        return filesystems
