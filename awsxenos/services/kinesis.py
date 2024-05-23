import json
from typing import DefaultDict, Optional, Set

import boto3  # type: ignore
from botocore.client import ClientError  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""Kinesis Stream resource policy"""


class Kinesis(Service):

    def fetch(  # type: ignore
        self,
        accounts: Accounts,
        exclude_service: Optional[bool] = True,
        exclude_aws: Optional[bool] = True,
    ) -> Findings:
        return super().collate(accounts, self.get_kinesis_policies())

    def get_kinesis_policies(
        self,
    ) -> Resources:

        kins = Resources()
        kin = boto3.client("kinesis")
        paginator = kin.get_paginator("list_streams")
        for kin_resp in paginator.paginate():
            for stream in kin_resp["StreamSummaries"]:
                try:
                    kins[stream["StreamARN"]] = json.loads(
                        kin.get_resource_policy(ResourceARN=stream["StreamARN"])["Policy"]
                    )
                except ClientError as err:
                    kins[kins["StreamARN"]] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": f"{err}",
                                "Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
                                "Action": ["kinesis:*"],
                                "Resource": f'{kins["StreamARN"]}',
                            }
                        ],
                    }
        return kins
