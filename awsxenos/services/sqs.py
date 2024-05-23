import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""SQS Access/Resource Policy"""


class SQS(Service):

    def fetch(  # type: ignore
        self,
        accounts: Accounts,
    ) -> Findings:
        return super().collate(accounts, self.get_sqs_policies())

    def get_sqs_policies(self) -> Resources:
        queues = Resources()
        sqs = boto3.client("sqs")
        paginator = sqs.get_paginator("list_queues")
        for sqs_resp in paginator.paginate():
            if "QueueUrls" not in sqs_resp:
                continue
            for queue in sqs_resp["QueueUrls"]:
                try:
                    queues[queue] = json.loads(
                        sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["Policy"])["Attributes"]["Policy"]
                    )
                except Exception as err:
                    queues[queue] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": f"{err}",
                                "Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
                                "Action": ["sqs:*"],
                                "Resource": "*",
                            }
                        ],
                    }

        return queues
