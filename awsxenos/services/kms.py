import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""KMS Customer Managed Keys resource policies"""


class KMS(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
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
            if "Keys" not in kms_resp:
                continue
            for key in kms_resp["Keys"]:
                try:
                    keys[key["KeyArn"]] = json.loads(
                        kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")["Policy"]
                    )
                except Exception as err:
                    keys[key["KeyArn"]] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": f"{err}",
                                "Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
                                "Action": ["kms:*"],
                                "Resource": "*",
                            }
                        ],
                    }

        return keys
