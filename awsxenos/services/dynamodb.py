import json

import boto3  # type: ignore
from botocore.client import ClientError  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""DynamoDB resource policies"""


class DynamoDBTable(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_dynamodb_policies())

    def get_dynamodb_policies(self) -> Resources:
        """
        Returns:
            Resources: UserDict[arn] = DynamoDBPolicy
        """
        dydbs = Resources()
        dydb = boto3.client("dynamodb")
        paginator = dydb.get_paginator("list_tables")

        build_arn = ""
        for dydb_resp in paginator.paginate():
            for table in dydb_resp["TableNames"]:
                if not build_arn:
                    table_arn = dydb.describe_table(TableName=table)["Table"]["TableArn"]
                    build_arn = table_arn.split("/")[0]
                else:
                    table_arn = f"{build_arn}/{table}"
                try:
                    dydbs[table_arn] = json.loads(dydb.get_resource_policy(ResourceArn=table_arn)["Policy"])
                except ClientError as e:
                    if e.response["Error"]["Code"] == "PolicyNotFoundException":
                        continue
                    else:
                        dydbs[table_arn] = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "Exception",
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": ["s3:*"],
                                    "Resource": f"{table_arn}",
                                }
                            ],
                        }

        return dydbs


class DynamoDBStreams(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_dynamodbstreams_policies())

    def get_dynamodbstreams_policies(self) -> Resources:
        """
        Returns:
            Resources: UserDict[arn] = DynamoDBStreamPolicy
        """
        dydbs = Resources()
        dydbstream = boto3.client("dynamodbstreams")
        dydb = boto3.client("dynamodb")
        for stream in dydbstream.list_streams()["Streams"]:
            dydbs[stream["StreamArn"]] = json.loads(dydb.get_resource_policy(ResourceArn=stream["StreamArn"])["Policy"])
        return dydbs
