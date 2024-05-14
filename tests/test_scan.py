from collections import defaultdict
import collections
import datetime
import unittest
from unittest import mock

from tests.fixtures import Fixtures
from awsxenos.scan import PreScan
from awsxenos.finding import Finding, Findings, Service

class MockService(Service):
    def fetch(self, accounts, **kwargs):
        pass  # Implementation not required for testing collate

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.service = MockService()
        self.accounts = Fixtures.mock_get_accounts()
       
        self.resources = Fixtures.mock_get_roles() 

    def test_collate(self):
        
        findings = self.service.collate(self.accounts, self.resources) # type: ignore

        self.assertTrue(findings["arn:aws:iam::000000000000:role/service-role/AccessAnalyzerMonitor"].aws_services)
        self.assertTrue(findings["arn:aws:iam::000000000000:role/ExternalRoleNoExternalID"].known_accounts)
        self.assertTrue(findings["arn:aws:iam::000000000000:user/ExternalUserWithinOrg"].org_accounts)
