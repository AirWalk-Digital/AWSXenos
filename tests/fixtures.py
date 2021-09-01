from collections import defaultdict
import datetime


class Fixtures:
    @staticmethod
    def mock_get_roles():
        roles = defaultdict(str)
        boto_list_roles = {
            "Roles": [
                {
                    "Path": "/service-role/",
                    "RoleName": "AccessAnalyzerMonitor",
                    "RoleId": "AROA09I634LQK4QC3ISLR",
                    "Arn": "arn:aws:iam::000000000000:role/service-role/AccessAnalyzerMonitor",
                    "CreateDate": datetime.datetime(2021, 5, 27, 14, 7, 36),
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "access-analyzer.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "MaxSessionDuration": 3600,
                },
                {
                    "Path": "/",
                    "RoleName": "ExternalRole",
                    "RoleId": "AROA02I634LQK4QC3ISLR",
                    "Arn": "arn:aws:iam::000000000000:role/ExternalRole",
                    "CreateDate": datetime.datetime(2021, 4, 8, 14, 1, 33),
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::000000000001:root"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "MaxSessionDuration": 3600,
                },
                {
                    "Path": "/",
                    "RoleName": "test-sdlc-notifier-dev-eu-west-1-lambdaRole",
                    "RoleId": "AROA49I634LQK4QC3ISLR",
                    "Arn": "arn:aws:iam::000000000000:role/test-sdlc-notifier-dev-eu-west-1-lambdaRole",
                    "CreateDate": datetime.datetime(2021, 5, 11, 8, 59, 9),
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Description": "",
                    "MaxSessionDuration": 3600,
                },
            ]
        }
        roles = {role["Arn"]: role["AssumeRolePolicyDocument"] for role in boto_list_roles["Roles"]}
        return roles

    @staticmethod
    def mock_get_accounts():
        accounts = defaultdict(set)
        boto_list_orgs = {
            "Accounts": [
                {
                    "Id": "000000000000",
                    "Arn": "arn:aws:organizations::000000000000:account/o-7s9fjxxxxn/000000000000",
                    "Email": "info@airwalkconsulting.com",
                    "Name": "AirWalk Sandbox",
                    "Status": "ACTIVE",
                    "JoinedMethod": "CREATED",
                    "JoinedTimestamp": datetime.datetime(2018, 9, 18, 12, 47, 22, 179000),
                },
                {
                    "Id": "000000000002",
                    "Arn": "arn:aws:organizations::000000000002:account/o-7s9fjxxxxn/000000000002",
                    "Email": "info@airwalkconsulting.com",
                    "Name": "AirWalk Sandbox1",
                    "Status": "ACTIVE",
                    "JoinedMethod": "CREATED",
                    "JoinedTimestamp": datetime.datetime(2019, 4, 29, 16, 7, 32, 155000),
                },
            ]
        }
        accounts["org_accounts"] = set([account["Id"] for account in boto_list_orgs["Accounts"]])
        accounts["org_accounts"].add("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        accounts["known_accounts"] = set(["000000000001"])
        return accounts

    @staticmethod
    def mock_list_s3_buckets():
        return {
            "Buckets": [
                {"Name": "examplebucket", "CreationDate": datetime.datetime(2021, 3, 29, 20, 17, 11)},
                {"Name": "anotherexample", "CreationDate": datetime.datetime(2021, 5, 11, 8, 58, 53)},
                {
                    "Name": "aws-athena-query-results-examplebucket",
                    "CreationDate": datetime.datetime(2021, 8, 10, 10, 12, 28),
                },
            ],
            "Owner": {"DisplayName": "exampleaccount", "ID": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        }

    @staticmethod
    def mock_get_bucket_policies():
        return {
            "arn:aws:s3:::examplebucketwithpolicy": {
                "Version": "2008-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::examplebucketwithpolicy",
                    }
                ],
            }
        }

    @staticmethod
    def mock_get_bucket_acl():
        return {
            "arn:aws:s3:::examplebucket": [
                {
                    "Grantee": {
                        "DisplayName": "exampleexternalaccount",
                        "ID": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
                        "Type": "CanonicalUser",
                    },
                    "Permission": "FULL_CONTROL",
                }
            ]
        }

    @staticmethod
    def mock_known_accounts():
        known_accounts = defaultdict(dict)
        accounts = Fixtures.mock_get_accounts()
        for account in accounts:
            known_accounts[account] = {"owner": "test", "description": "test"}
        return known_accounts
