import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""VPC Endpoint Policies"""


class VPCEndpoint(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_vpc_policies())

    def get_vpc_policies(self) -> Resources:
        """
        Returns:
            Resources: UserDict[arn] = KMSPolicy
        """
        vpcs = Resources()
        ec2 = boto3.client("ec2")
        paginator = ec2.get_paginator("describe_vpc_endpoints")
        for ec2_resp in paginator.paginate():
            for endpoint in ec2_resp["VpcEndpoints"]:
                vpcs[f'{endpoint["VpcId"]}-{endpoint.get("ServiceName","")}'] = json.loads(endpoint["PolicyDocument"])
        return vpcs
