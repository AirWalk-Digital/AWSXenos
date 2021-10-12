from collections import defaultdict
from typing import List, Dict, DefaultDict
import json

from jinja2 import Environment, FileSystemLoader  # type: ignore
from policyuniverse.arn import ARN  # type: ignore

from awsxenos.finding import AccountType, Finding
from awsxenos import package_path


class Report:
    def __init__(self, findings: DefaultDict[str, AccountType], account_info: DefaultDict[str, Dict]) -> None:
        self.summary = self._summarise(findings, account_info)

    def _summarise(
        self, findings: DefaultDict[str, AccountType], account_info: DefaultDict[str, Dict]
    ) -> DefaultDict[str, List]:
        summary = defaultdict(list)
        for resource, accounttype in findings.items():
            # Refactor
            # for account_type, principal in finding
            if accounttype.known_accounts:
                for finding in accounttype.known_accounts:
                    role_arn = ARN(finding.principal)
                    summary["known_accounts"].append(
                        {
                            "ARN": resource,
                            "principal": accounttype.known_accounts,
                            "external_info": account_info[role_arn.account_number],
                            "external_id": finding.external_id,
                        }
                    )
            if accounttype.org_accounts:
                for finding in accounttype.org_accounts:
                    role_arn = ARN(finding.principal)
                    summary["org_accounts"].append(
                        {
                            "ARN": resource,
                            "principal": accounttype.org_accounts,
                            "external_info": account_info[role_arn.account_number],
                        }
                    )
            if accounttype.aws_services:
                for finding in accounttype.aws_services:
                    role_arn = ARN(finding.principal)
                    summary["aws_services"].append(
                        {
                            "ARN": resource,
                            "principal": accounttype.aws_services,
                            "external_info": account_info[role_arn.tech],
                        }
                    )
            if accounttype.unknown_accounts:
                for finding in accounttype.unknown_accounts:
                    role_arn = ARN(finding.principal)
                    summary["unknown_accounts"].append(
                        {
                            "ARN": resource,
                            "principal": accounttype.unknown_accounts,
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
