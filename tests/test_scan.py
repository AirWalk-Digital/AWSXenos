from collections import defaultdict
import collections
import datetime
import unittest
from unittest import mock

from tests.fixtures import Fixtures
from awsxenos.scan import Scan


class ScanTests(unittest.TestCase):
    @mock.patch("awsxenos.scan.Scan.get_bucket_acls", return_value=Fixtures.mock_get_bucket_acl())
    @mock.patch("awsxenos.scan.Scan.get_bucket_policies", return_value=Fixtures.mock_get_bucket_policies())
    @mock.patch("awsxenos.scan.Scan.list_account_buckets", return_value=Fixtures.mock_list_s3_buckets())
    @mock.patch("awsxenos.scan.Scan.get_roles", return_value=Fixtures.mock_get_roles())
    @mock.patch("awsxenos.scan.Scan.get_all_accounts", return_value=Fixtures.mock_get_accounts())
    def test_collate_findings(self, *args):
        s = Scan()
        s.known_accounts_data = mock.MagicMock(return_value=Fixtures.mock_known_accounts())
        self.assertEqual(type(s.findings), collections.defaultdict)
        for role in s.findings.keys():
            self.assertIn("arn:aws:", role)
        self.assertGreaterEqual(
            len(s.findings["arn:aws:iam::000000000000:role/service-role/AccessAnalyzerMonitor"].aws_services),
            1,
        )

        self.assertListEqual(
            s.findings["arn:aws:iam::000000000000:role/ExternalRole"].known_accounts, ["arn:aws:iam::000000000001:root"]
        )
        self.assertListEqual(
            s.findings["arn:aws:s3:::examplebucket"].unknown_accounts, ["yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"]
        )
        self.assertListEqual(s.findings["arn:aws:s3:::examplebucketwithpolicy"].unknown_accounts, ["*"])
