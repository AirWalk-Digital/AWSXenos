import abc
from collections import defaultdict, UserDict
from dataclasses import dataclass, field
from typing import Any, DefaultDict, List

from policyuniverse.arn import ARN  # type: ignore
from policyuniverse.policy import Policy  # type: ignore
from policyuniverse.statement import ConditionTuple, Statement  # type: ignore


@dataclass
class Finding:
    principal: str
    external_id: bool

    def __repr__(self) -> str:
        return str(self.principal)

    def __str__(self) -> str:
        return self.principal


@dataclass
class Accounts:
    org_accounts: List[Finding] = field(default_factory=list)
    known_accounts: List[Finding] = field(default_factory=list)
    unknown_accounts: List[Finding] = field(default_factory=list)
    aws_services: List[Finding] = field(default_factory=list)
    org_id: str = ""

    def __getitem__(self, key):
        return super().__getattribute__(key)

    def __contains__(self, key):
        return getattr(self, key)


"""Container for Finding"""


class Findings(UserDict):
    def __missing__(self, key):
        self[key] = Accounts()
        return self[key]


""" Container for any resource, e.g. IAM roles returned by a service
    Expects a key of arn and a value of the policy
"""


class Resources(UserDict):
    def __missing__(self, key):
        self[key] = defaultdict()
        return self[key]


"""Main class to derive from when implementing other services"""


class Service(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def fetch(self, accounts: Accounts, **kwargs) -> Findings:
        raise NotImplementedError

    def _get_account_type(self, account: str, accounts: Accounts) -> str:
        account_types = ["org_accounts", "known_accounts"]
        for account_type in account_types:
            if account in accounts[account_type]:
                return account_type
        return "unknown_accounts"

    def collate(self, accounts: Accounts, resources: Resources) -> Findings:
        """Combine all accounts with all the resources to classify findings.
            This is the default collation function called by Service

        Args:
            accounts (Accounts): Key of account type. Value account ids
            resources (Resources): Key ResourceIdentifier. Value Dict PolicyDocument

        Returns:
            DefaultDict[str, AccountType]: Key of ARN, Value of AccountType
        """

        findings = Findings()

        for resource, policy_document in resources.items():  # TODO: extract the IAM trust policy logic
            try:
                policy = Policy(policy_document)
            except:
                continue  # TODO: Don't fail silently
            for st in policy.statements:
                if st.effect != "Allow":
                    continue
                for unparsed_principal in st.principals:  # There is always a principal - including "*"
                    principal = ARN(unparsed_principal)
                    if st.condition_accounts:  # If condition exists on account, it's an account
                        for account in st.condition_accounts:
                            findings[resource][self._get_account_type(account, accounts)].append(
                                Finding(principal=account, external_id=True)
                            )
                    elif st.condition_orgids:  # If condition exists on orgid, it's the orgid
                        for org_id in st.condition_orgids:
                            if accounts.org_id == org_id:
                                findings[resource]["org_accounts"].append(
                                    Finding(principal=principal.arn, external_id=True)  # type: ignore
                                )
                            else:
                                findings[resource]["unknown_accounts"].append(
                                    Finding(principal=principal.arn, external_id=True)  # type: ignore
                                )
                    elif principal.account_number:  # if there are no conditions
                        if "sts" in st.action_summary():  # IAM Assume Role
                            try:
                                conditions = [k.lower() for k in list(st.statement["Condition"]["StringEquals"].keys())]
                                if "sts:externalid" in conditions:
                                    findings[resource][
                                        self._get_account_type(principal.account_number, accounts)
                                    ].append(
                                        Finding(principal=principal.arn, external_id=True)  # type: ignore
                                    )
                                else:
                                    findings[resource][
                                        self._get_account_type(principal.account_number, accounts)
                                    ].append(
                                        Finding(principal=principal.arn, external_id=False)  # type: ignore
                                    )
                            except:
                                findings[resource][self._get_account_type(principal.account_number, accounts)].append(
                                    Finding(principal=principal.arn, external_id=False)  # type: ignore
                                )
                        else:
                            findings[resource][self._get_account_type(principal.account_number, accounts)].append(
                                Finding(principal=principal.arn, external_id=True)  # type: ignore
                            )
                    elif not principal.account_number and principal.service:  # It's an aws service
                        findings[resource].aws_services.append(
                            Finding(principal=principal.arn, external_id=True)  # type: ignore
                        )
                    elif not principal.account_number and not principal.service:  # It's anonymous
                        findings[resource].unknown_accounts.append(
                            Finding(principal=principal.arn, external_id=True)  # type: ignore
                        )
                    else:  # Catch-all
                        findings[resource].unknown_accounts.append(
                            Finding(principal=principal, external_id=True)  # type: ignore
                        )
        return findings
