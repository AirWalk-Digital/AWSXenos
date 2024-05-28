import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""SNS Access/Resource Policy"""


class SNS(Service):

    def fetch(  # type: ignore
        self,
        accounts: Accounts,
    ) -> Findings:
        return super().collate(accounts, self.get_sns_policies())

    def get_sns_policies(self) -> Resources:
        topics = Resources()
        sns = boto3.client("sns")
        paginator = sns.get_paginator("list_topics")
        for sns_resp in paginator.paginate():
            if "Topics" not in sns_resp:
                continue
            for topic in sns_resp["Topics"]:
                try:
                    topics[topic["TopicArn"]] = json.loads(
                        sns.get_topic_attributes(TopicArn=topic["TopicArn"])["Attributes"]["Policy"]
                    )
                except Exception as err:
                    topics[topic] = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": f"{err}",
                                "Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
                                "Action": ["sns:*"],
                                "Resource": "*",
                            }
                        ],
                    }

        return topics
