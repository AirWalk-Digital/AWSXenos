import json
from typing import DefaultDict, Set

import boto3  # type: ignore

from awsxenos.finding import Findings, Resources, Service

"""Secrets Manager Secrets Resource Policies"""


class SecretsManager(Service):

    def fetch(self, accounts: DefaultDict[str, Set]) -> Findings:  # type: ignore
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
            for secret in sm_resp["SecretList"]:
                secrets[secret["ARN"]] = json.loads(sm.get_resource_policy(SecretId=secret["ARN"])["ResourcePolicy"])

        return secrets