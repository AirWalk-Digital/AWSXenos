import json
from typing import DefaultDict, Set

import boto3  # type: ignore

from awsxenos.finding import Findings, Resources, Service

"""EFS Resource Policies"""


class EFSResource(Service):

    def fetch(self, accounts: DefaultDict[str, Set]) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_efs_policies())

    def get_efs_policies(self) -> Resources:
        filesystems = Resources()
        efs = boto3.client("efs")
        paginator = efs.get_paginator("describe_file_systems")
        for page in paginator.paginate():
            for fs in page["FileSystems"]:
                filesystems[fs["FileSystemArn"]] = json.loads(
                    efs.describe_file_system_policy(FileSystemId=fs["FileSystemId"])["Policy"]
                )
        return filesystems
