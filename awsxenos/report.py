import json
from collections import defaultdict
from typing import DefaultDict, Dict, List

from jinja2 import Environment, FileSystemLoader  # type: ignore
from policyuniverse.arn import ARN  # type: ignore

from awsxenos import package_path

from awsxenos.finding import Findings, Resources


class Report:
    def __init__(self, findings: Findings, account_info: Resources) -> None:
        self.summary = self._summarise(findings, account_info)

    def _summarise(self, findings: Findings, account_info: Resources) -> DefaultDict[str, List]:
        summary = defaultdict(list)
        # print('Report - Findings')
        # print(findings)
        # print('Report - Account Info')
        # print(account_info)

        for resource, account_type in findings.items():
            # Refactor
            # for account_type, principal in finding
            if account_type.known_accounts:
                for finding in account_type.known_accounts:
                    role_arn = ARN(finding.principal)
                    summary["known_accounts"].append(
                        {
                            "ARN": resource,
                            "principal": account_type.known_accounts,
                            "external_info": account_info[role_arn.account_number],
                            "external_id": finding.external_id,
                        }
                    )
            if account_type.org_accounts:
                for finding in account_type.org_accounts:
                    role_arn = ARN(finding.principal)
                    summary["org_accounts"].append(
                        {
                            "ARN": resource,
                            "principal": account_type.org_accounts,
                            "external_info": account_info[role_arn.account_number],
                        }
                    )
            if account_type.aws_services:
                for finding in account_type.aws_services:
                    role_arn = ARN(finding.principal)
                    summary["aws_services"].append(
                        {
                            "ARN": resource,
                            "principal": account_type.aws_services,
                            "external_info": account_info[role_arn.tech],
                        }
                    )
            if account_type.unknown_accounts:
                for finding in account_type.unknown_accounts:
                    role_arn = ARN(finding.principal)
                    summary["unknown_accounts"].append(
                        {
                            "ARN": resource,
                            "principal": account_type.unknown_accounts,
                            "external_info": account_info[role_arn.account_number],
                            "external_id": finding.external_id,
                        }
                    )
        return summary

    def JSON_report(self) -> str:
        """Return the Findings in JSON format

        Returns:
            str: Return the Findings in JSON format
        """
        return json.dumps(self.summary, indent=4, default=str)

    def HTML_report(self) -> str:
        """Generate an HTML report based on the template.html

        Returns:
            str: return HTML
        """
        jinja_env = Environment(loader=FileSystemLoader(package_path.resolve().parent))
        template = jinja_env.get_template("template.html")
        return template.render(summary=self.summary)
