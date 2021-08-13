from collections import defaultdict
import json
from typing import List, Dict, DefaultDict

from finding import Finding

from jinja2 import Environment, FileSystemLoader


class Report(object):
    def __init__(self, findings: defaultdict[str, Finding]) -> None:
        self.summary = self._summarise(findings)

    def _summarise(self, findings: defaultdict[str, Finding]) -> DefaultDict[str, List]:
        summary = defaultdict(list)
        for role, finding in findings.items():
            if finding.external_accounts:
                summary["external_accounts"].append(f"{role} - {finding.external_accounts}")
            elif finding.org_accounts:
                summary["org_accounts"].append(f"{role} - {finding.org_accounts}")
            else:
                summary["unknown_accounts"].append(f"{role} - {finding.unknown_accounts}")
        return summary

    def JSONReport(self) -> str:
        return json.dumps(self.summary, indent=4)

    def HTMLReport(self) -> str:
        jinja_env = Environment(loader=FileSystemLoader("."))  # nosec
        template = jinja_env.get_template("template.html")
        return template.render(summary=self.summary)
