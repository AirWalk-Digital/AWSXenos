import unittest

from tests.fixtures import Fixtures
from awsxenos.finding import Service
from awsxenos.services.s3 import S3ACL

class MockService(Service):
    def fetch(self, accounts, **kwargs):
        pass  # Implementation not required for testing collate

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.service = MockService()
        self.s3acl =  S3ACL()
        self.s3acl._buckets = Fixtures.mock_list_s3_buckets()
        self.accounts = Fixtures.mock_get_accounts()
        self.resources = Fixtures.mock_get_roles()
        self.buckets_acl = Fixtures.mock_get_bucket_acl()
        self.buckets = Fixtures.mock_get_bucket_policies()

    def test_collate_known(self):
        
        findings = self.service.collate(self.accounts, self.resources) # type: ignore
        self.assertTrue(findings["arn:aws:iam::000000000000:role/service-role/AccessAnalyzerMonitor"].aws_services)
        self.assertTrue(findings["arn:aws:iam::000000000000:role/ExternalRoleNoExternalID"].known_accounts)
        self.assertTrue(findings["arn:aws:iam::000000000000:role/ExternalRole"].known_accounts)

    def test_collate_org(self):
        
        findings = self.service.collate(self.accounts, self.resources) # type: ignore
        self.assertTrue(findings["arn:aws:iam::000000000000:user/ExternalUserWithinOrg"].org_accounts)
        self.assertTrue(findings["arn:aws:iam::000000000000:role/ExternalRoleFromSaml"].org_accounts)


    def test_collate_unknown(self):
        
        findings = self.service.collate(self.accounts, self.resources) # type: ignore
        self.assertTrue(findings["arn:aws:iam::000000000000:user/ExternalUserWithinOrgButOrgIdCondition"].unknown_accounts)
    
    def test_collate_buckets(self):
        findings = self.service.collate(self.accounts, self.buckets) # type: ignore
        self.assertTrue(findings["arn:aws:s3:::examplebucketwithpolicy"].unknown_accounts)
    
    def test_collate_buckets_acl(self):
        findings =  self.s3acl.custom_collate(self.accounts, self.buckets_acl) # type: ignore
        print(findings)
        self.assertTrue(findings["arn:aws:s3:::examplebucketexternalaccount"].unknown_accounts)