from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    org_accounts: List[str] = field(default_factory=list)
    external_accounts: List[str] = field(default_factory=list)
    unknown_accounts: List[str] = field(default_factory=list)
