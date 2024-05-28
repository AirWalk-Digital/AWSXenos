import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""Secrets Manager Secrets Resource Policies"""


class SecretsManager(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_secret_policies())

    def get_secret_policies(self) -> Resources:
        """Get a dictionary of secrets and their policies from the AWS Account

        Args:

        Returns:
            DefaultDict[str, str]: Key of ARN, Value of ResourcePolicy
        """
        secrets = Resources()
        sm = boto3.client("secretsmanager")
        paginator = sm.get_paginator("list_secrets")
        sm_iterator = paginator.paginate()
        for sm_resp in sm_iterator:
            if "SecretList" not in sm_resp:
                continue
            for secret in sm_resp["SecretList"]:
                try:
                    secrets[secret["ARN"]] = json.loads(
                        sm.get_resource_policy(SecretId=secret["ARN"])["ResourcePolicy"]
                    )
                except Exception as err:
                    secrets[secret["ARN"]] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "Exception",
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": ["secretsmanager:*"],
                                "Resource": "*",
                            }
                        ],
                    }
        return secrets
