from collections import defaultdict
from typing import List, Dict, DefaultDict
import json

from finding import Finding

from policyuniverse.arn import ARN
from jinja2 import Environment, FileSystemLoader


class Report(object):
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
                        {"role": role, "principal": principal, "external_info": account_info[role_arn.account_number]}
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
                        {"role": role, "principal": finding.aws_services, "external_info": account_info[role_arn.tech]}
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

    def JSONReport(self) -> str:
        return json.dumps(self.summary, indent=4, default=str)

    def HTMLReport(self) -> str:
        jinja_env = Environment(loader=FileSystemLoader("."))
        template = jinja_env.get_template("template.html")
        return template.render(summary=self.summary)
