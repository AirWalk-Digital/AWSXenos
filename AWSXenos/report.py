from collections import defaultdict
from typing import List, Dict, DefaultDict

from finding import Finding

from jinja2 import Environment, FileSystemLoader

class Report(object):
    def __init__(self):
        pass

    def JSONReport(self, findings: defaultdict[str, Finding]) -> defaultdict[str, list]:
        summary = defaultdict(list)
        for role, finding in findings.items():
            if finding.external_accounts:
                summary["external_accounts"].append(f"{role} - {finding.external_accounts}")
            elif finding.org_accounts:
                summary["org_accounts"].append(f"{role} - {finding.org_accounts}")
            else:
                summary["unknown_accounts"].append(f"{role} - {finding.unknown_accounts}")
        return summary
    
    def HTMLReport(self, findings: defaultdict[str, Finding]) -> defaultdict[str, list]:
        summary = defaultdict(list)
        for role, finding in findings.items():
            if finding.external_accounts:
                summary["external_accounts"].append(f"{role} - {finding.external_accounts}")
            elif finding.org_accounts:
                summary["org_accounts"].append(f"{role} - {finding.org_accounts}")
            else:
                summary["unknown_accounts"].append(f"{role} - {finding.unknown_accounts}")
        return summary