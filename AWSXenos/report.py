from collections import defaultdict
from typing import List, Dict, DefaultDict
import json

from jinja2 import Environment, FileSystemLoader  # type: ignore
from policyuniverse.arn import ARN  # type: ignore

from awsxenos.finding import Finding
from awsxenos import package_path


class Report:
    def __init__(self, findings: defaultdict[str, Finding], account_info: DefaultDict[str, Dict]) -> None:
        self.summary = self._summarise(findings, account_info)

    def _summarise(
        self, findings: defaultdict[str, Finding], account_info: DefaultDict[str, Dict]
    ) -> DefaultDict[str, List]:
        summary = defaultdict(list)
        for role, finding in findings.items():
            # Refactor
            # for account_type, principal in finding
            if finding.known_accounts:
                for principal in finding.known_accounts:
                    role_arn = ARN(principal)
                    summary["known_accounts"].append(
                        {
                            "role": role,
                            "principal": principal,
                            "external_info": account_info[role_arn.account_number],
                        }
                    )
            if finding.org_accounts:
                for principal in finding.org_accounts:
                    role_arn = ARN(principal)
                    summary["org_accounts"].append(
                        {
                            "role": role,
                            "principal": finding.org_accounts,
                            "external_info": account_info[role_arn.account_number],
                        }
                    )
            if finding.aws_services:
                for principal in finding.aws_services:
                    role_arn = ARN(principal)
                    summary["aws_services"].append(
                        {
                            "role": role,
                            "principal": finding.aws_services,
                            "external_info": account_info[role_arn.tech],
                        }
                    )
            if finding.unknown_accounts:
                for principal in finding.unknown_accounts:
                    role_arn = ARN(principal)
                    summary["unknown_accounts"].append(
                        {
                            "role": role,
                            "principal": finding.unknown_accounts,
                            "external_info": account_info[role_arn.account_number],
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
