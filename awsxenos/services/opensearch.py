import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""OpenSearch Domain Access Policies"""


class OpenSearch(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_domain_policies())

    def get_domain_policies(self) -> Resources:
        """
        Returns:
            Resources: UserDict[arn] = OpenSearch Access Policy
        """
        domains = Resources()
        opens = boto3.client("opensearch")
        for domain_name in opens.list_domain_names()["DomainNames"]:
            try:
                domain_details = opens.describe_domain(DomainName=domain_name["DomainName"])["DomainStatus"]
                domains[domain_details["ARN"]] = json.loads(domain_details["AccessPolicies"])
            except Exception as err:
                domains[domain_name["DomainName"]] = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "Exception",
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": ["es:*"],
                            "Resource": "*",
                        }
                    ],
                }
        return domains
