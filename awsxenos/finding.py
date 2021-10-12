from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    principal: str
    external_id: bool

    def __repr__(self) -> str:
        return str(self.principal)

    def __str__(self) -> str:
        return self.principal


@dataclass
class AccountType:
    org_accounts: List[Finding] = field(default_factory=list)
    known_accounts: List[Finding] = field(default_factory=list)
    unknown_accounts: List[Finding] = field(default_factory=list)
    aws_services: List[Finding] = field(default_factory=list)
