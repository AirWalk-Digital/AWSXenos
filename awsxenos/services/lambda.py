import json

import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""Lambda Resource Policies"""


class LambdaResource(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_lambda_policies())

    def get_lambda_policies(self) -> Resources:
        lambdas = Resources()
        lam = boto3.client("lambda")
        paginator = lam.get_paginator("list_functions")
        for lam_resp in paginator.paginate():
            if "Functions" not in lam_resp:
                continue
            for func in lam_resp["Functions"]:
                try:
                    lambdas[func["FunctionArn"]] = json.loads(
                        lam.get_policy(FunctionName=func["FunctionName"])["Policy"]
                    )
                except ClientError as err:
                    lambdas[func["FunctionArn"]] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": f"{err}",
                                "Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
                                "Action": ["lambda:*"],
                                "Resource": f'{func["FunctionArn"]}',
                            }
                        ],
                    }
        return lambdas
