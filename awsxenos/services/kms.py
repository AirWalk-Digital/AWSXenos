import json
from typing import DefaultDict, Set

import boto3  # type: ignore

from awsxenos.finding import Findings, Resources, Service

"""KMS Customer Managed Keys resource policies"""


class KMS(Service):

    def fetch(self, accounts: DefaultDict[str, Set]) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_kms_keys())

    def get_kms_keys(self) -> Resources:
        """
        Returns:
            Resources: UserDict[arn] = KMSPolicy
        """
        keys = Resources()
        kms = boto3.client("kms")
        paginator = kms.get_paginator("list_keys")
        kms_paginator = paginator.paginate()
        for kms_resp in kms_paginator:
            for key in kms_resp["Keys"]:
                keys[key["KeyArn"]] = json.loads(kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")["Policy"])
        return keys
