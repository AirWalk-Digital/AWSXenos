import json
from typing import DefaultDict, Optional, Set

import boto3  # type: ignore

from awsxenos.finding import Findings, Resources, Service

"""SQS Access/Resource Policy"""


class SQS(Service):

    def fetch(  # type: ignore
        self,
        accounts: DefaultDict[str, Set],
        exclude_service: Optional[bool] = True,
        exclude_aws: Optional[bool] = True,
    ) -> Findings:
        return super().collate(accounts, self.get_sqs_policies(exclude_service, exclude_aws))

    def get_sqs_policies(self, exclude_service: Optional[bool] = True, exclude_aws: Optional[bool] = True) -> Resources:
        queues = Resources()
        sqs = boto3.client("sqs")
        paginator = sqs.get_paginator("list_queues")
        for sqs_resp in paginator.paginate():
            for queue in sqs_resp["QueueUrls"]:
                queues[queue["QueueUrl"]] = json.loads(
                    sqs.get_queue_attributes(QueueUrl=queue["QueueUrl"], AttributeNames=["Policy"])["Attributes"][
                        "Policy"
                    ]
                )

        return queues
