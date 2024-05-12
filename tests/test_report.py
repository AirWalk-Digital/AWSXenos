import json
import unittest
from unittest import mock


from tests.fixtures import Fixtures
from awsxenos.scan import PreScan
from awsxenos.report import Report


class ReportTests(unittest.TestCase):
    @mock.patch("awsxenos.scan.PreScan.list_account_buckets", return_value=Fixtures.mock_list_s3_buckets())
    @mock.patch("awsxenos.scan.PreScan.get_all_accounts", return_value=Fixtures.mock_get_accounts())
    def test_report_summary(self, *args):

        prescan = PreScan()
        result = Fixtures.mock_findings()
        r = Report(result, prescan.known_accounts)
        
        self.assertIn("known_accounts", r.summary)
        self.assertIn("org_accounts", r.summary)
        self.assertIn("aws_services", r.summary)
        self.assertIn("unknown_accounts", r.summary)

    @mock.patch("awsxenos.scan.PreScan.list_account_buckets", return_value=Fixtures.mock_list_s3_buckets())
    @mock.patch("awsxenos.scan.PreScan.get_all_accounts", return_value=Fixtures.mock_get_accounts())
    def test_json_report(self, *args):
        prescan = PreScan()
        result = Fixtures.mock_findings()
        r = Report(result, prescan.known_accounts)
        result = json.loads(r.JSON_report())
        self.assertEqual(dict, type(result))
        self.assertGreater(len(result), 1)
