import abc
from collections import defaultdict, UserDict
from dataclasses import dataclass, field
from typing import Any, DefaultDict, List, Set

from policyuniverse.arn import ARN  # type: ignore
from policyuniverse.policy import Policy  # type: ignore
from policyuniverse.statement import ConditionTuple  # type: ignore


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

    def __getitem__(self, key):
        return super().__getattribute__(key)


class Findings(UserDict):
    def __missing__(self, key):
        self[key] = Accounts()
        return self[key]


class Resources(UserDict):
    def __missing__(self, key):
        self[key] = defaultdict()
        return self[key]


class Service(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def fetch(self, accounts: DefaultDict[str, Set], **kwargs) -> Findings:
        raise NotImplementedError

    def collate(self, accounts: DefaultDict[str, Set], resources: Resources) -> Findings:
        """Combine all accounts with all the resources to classify findings. Try custom_collate first and fallback to this.

        Args:
            accounts (DefaultDict[str, Set]): Key of account type. Value account ids
            resources (DefaultDict[str, Dict[Any, Any]]): Key ResourceIdentifier. Value Dict PolicyDocument

        Returns:
            DefaultDict[str, AccountType]: Key of ARN, Value of AccountType
        """

        findings = Findings()
        for resource, policy_document in resources.items():
            try:
                policy = Policy(policy_document)
            except:
                continue
            for unparsed_principal in policy.whos_allowed():
                try:
                    principal = ARN(unparsed_principal.value)  # type: Any
                except Exception as e:
                    print(e)
                    findings[resource].known_accounts.append(Finding(principal=unparsed_principal, external_id=True))
                    continue
                # Check if Principal is an AWS Service
                if principal.service:
                    findings[resource].aws_services.append(Finding(principal=principal.arn, external_id=True))
                # Check against org_accounts
                elif principal.account_number in accounts["org_accounts"]:
                    findings[resource].org_accounts.append(Finding(principal=principal.arn, external_id=True))
                # Check against known external accounts
                elif (
                    principal.account_number in accounts["known_accounts"]
                    or ConditionTuple(category="saml-endpoint", value="https://signin.aws.amazon.com/saml")
                    in policy.whos_allowed()
                ):
                    sts_set = False
                    for pstate in policy.statements:
                        if "sts" in pstate.action_summary():
                            try:
                                conditions = [
                                    k.lower() for k in list(pstate.statement["Condition"]["StringEquals"].keys())
                                ]
                                if "sts:externalid" in conditions:
                                    findings[resource].known_accounts.append(
                                        Finding(principal=principal.arn, external_id=True)
                                    )
                            except:
                                findings[resource].known_accounts.append(
                                    Finding(principal=principal.arn, external_id=False)
                                )
                            finally:
                                sts_set = True
                                break
                    if not sts_set:
                        findings[resource].known_accounts.append(Finding(principal=principal.arn, external_id=False))

                # Unknown Account
                else:
                    sts_set = False
                    for pstate in policy.statements:
                        if "sts" in pstate.action_summary():
                            try:
                                conditions = [
                                    k.lower() for k in list(pstate.statement["Condition"]["StringEquals"].keys())
                                ]
                                if "sts:externalid" in conditions:
                                    findings[resource].unknown_accounts.append(
                                        Finding(principal=principal.arn, external_id=True)
                                    )
                            except:
                                findings[resource].unknown_accounts.append(
                                    Finding(principal=principal.arn, external_id=False)
                                )
                            finally:
                                break
                    if not sts_set:
                        findings[resource].unknown_accounts.append(Finding(principal=principal.arn, external_id=False))
        return findings
