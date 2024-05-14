from typing import DefaultDict, Optional, Set

import boto3  # type: ignore

from awsxenos.finding import Findings, Resources, Service

"""IAM Roles trust policies"""


class IAM(Service):

    def fetch(  # type: ignore
        self,
        accounts: DefaultDict[str, Set],
        exclude_service: Optional[bool] = True,
        exclude_aws: Optional[bool] = True,
    ) -> Findings:
        return super().collate(accounts, self.get_role_policies(exclude_service, exclude_aws))

    def get_role_policies(
        self, exclude_service: Optional[bool] = True, exclude_aws: Optional[bool] = True
    ) -> Resources:
        """Get a dictionary of roles and their policies from the AWS Account

        Args:
            exclude_service (Optional[bool], optional): exclude roles starting with /service-role/. Defaults to True.
            exclude_aws (Optional[bool], optional): exclude roles starting with /aws-service-role/. Defaults to True.

        Returns:
            DefaultDict[str, str]: Key of RoleNames, Value of AssumeRolePolicyDocument
        """
        roles = Resources()
        iam = boto3.client("iam")
        paginator = iam.get_paginator("list_roles")
        role_iterator = paginator.paginate()
        for role_resp in role_iterator:
            for role in role_resp["Roles"]:
                if role["Path"] == "/service-role/" and exclude_service:
                    continue
                elif role["Path"].startswith("/aws-service-role/") and exclude_aws:
                    continue
                else:
                    roles[role["Arn"]] = role["AssumeRolePolicyDocument"]

        return roles
