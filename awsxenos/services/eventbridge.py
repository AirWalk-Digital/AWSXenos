import json

import boto3  # type: ignore

from awsxenos.finding import Accounts, Findings, Resources, Service

"""EventBridge Bus Resource Policies"""


class EventBus(Service):

    def fetch(self, accounts: Accounts) -> Findings:  # type: ignore
        return super().collate(accounts, self.get_eb_policies())

    def get_eb_policies(self) -> Resources:
        buses = Resources()
        eb = boto3.client("events")
        for bus in eb.list_event_buses():
            if "Policy" in bus:
                buses[bus["Arn"]] = json.loads(bus["Policy"])
        return buses
