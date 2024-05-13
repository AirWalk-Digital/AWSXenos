import json
from typing import DefaultDict, Set

import boto3  # type: ignore

from awsxenos.finding import Findings, Resources, Service

"""EventBridge Bus Resource Policies"""


class EventBus(Service):

    def fetch(self, accounts: DefaultDict[str, Set]) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_eb_policies())

    def get_eb_policies(self) -> Resources:
        buses = Resources()
        eb = boto3.client("events")
        for bus in eb.list_event_buses():
            if "Policy" in bus:
                buses[bus["Arn"]] = json.loads(bus["Policy"])
        return buses
