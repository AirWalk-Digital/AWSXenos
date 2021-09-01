import json
import unittest
from unittest import mock


from tests.fixtures import Fixtures
from awsxenos.scan import Scan
from awsxenos.report import Report


class ReportTests(unittest.TestCase):
    @mock.patch("awsxenos.scan.Scan.get_bucket_acls", return_value=Fixtures.mock_get_bucket_acl())
    @mock.patch("awsxenos.scan.Scan.get_bucket_policies", return_value=Fixtures.mock_get_bucket_policies())
    @mock.patch("awsxenos.scan.Scan.list_account_buckets", return_value=Fixtures.mock_list_s3_buckets())
    @mock.patch("awsxenos.scan.Scan.get_roles", return_value=Fixtures.mock_get_roles())
    @mock.patch("awsxenos.scan.Scan.get_all_accounts", return_value=Fixtures.mock_get_accounts())
    def test_report_summary(self, *args):

        s = Scan()
        r = Report(s.findings, s.known_accounts_data)
        self.assertIn("known_accounts", r.summary)
        self.assertIn("org_accounts", r.summary)
        self.assertIn("aws_services", r.summary)
        # self.assertIn(r.summary, "unknown_accounts")

    @mock.patch("awsxenos.scan.Scan.get_bucket_acls", return_value=Fixtures.mock_get_bucket_acl())
    @mock.patch("awsxenos.scan.Scan.get_bucket_policies", return_value=Fixtures.mock_get_bucket_policies())
    @mock.patch("awsxenos.scan.Scan.list_account_buckets", return_value=Fixtures.mock_list_s3_buckets())
    @mock.patch("awsxenos.scan.Scan.get_roles", return_value=Fixtures.mock_get_roles())
    @mock.patch("awsxenos.scan.Scan.get_all_accounts", return_value=Fixtures.mock_get_accounts())
    def test_json_report(self, *args):
        s = Scan()
        r = Report(s.findings, s.known_accounts_data)
        result = json.loads(r.JSON_report())
        self.assertEqual(dict, type(result))
        self.assertGreater(len(result), 1)
