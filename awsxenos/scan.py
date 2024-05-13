#!/usr/bin/env python3
import argparse
import concurrent.futures
import importlib
import json
import sys

from typing import Any, Callable, Dict

import boto3  # type: ignore
import yaml  # type: ignore

from awsxenos import package_path

from awsxenos.finding import Accounts, Findings, Resources
from awsxenos.report import Report

"""
High level architecture

1. Run prescan to collect org_accounts and buckets. 
2. Load config, instantiate classes, submit to ThreadPoolExecutor to run "fetch"
3. Each fetch will return `Findings` by running `collate` or `custom_collate`
4. Pass the findings to `Report`
"""


class PreScan:
    def __init__(self):
        self.known_accounts = Resources()
        self._buckets = self.list_account_buckets()
        self.accounts = self.get_all_accounts()

    def get_org_accounts(self) -> Resources:
        """Get Account Ids from the AWS Organization

        Returns:
            DefaultDict: Key of Account Ids. Value of other Information
        """
        accounts = Resources()
        orgs = boto3.client("organizations")
        paginator = orgs.get_paginator("list_accounts")
        try:
            account_iterator = paginator.paginate()
            for account_resp in account_iterator:
                for account in account_resp["Accounts"]:
                    accounts[account["Id"]] = account
            return accounts
        except Exception as e:
            print("[!] - Failed to get organization accounts")
            print(e)
        return accounts

    def list_account_buckets(self) -> Dict[str, Dict[Any, Any]]:
        s3 = boto3.client("s3")
        return s3.list_buckets()

    def get_all_accounts(self) -> Accounts:
        """Get all known accounts and from the AWS Organization

        Returns:
            DefaultDict[str, Set]: Key of account type. Value account ids
        """
        accounts = Accounts()

        with open(f"{package_path.resolve().parent}/accounts.json", "r") as f:
            accounts_file = json.load(f)
            for account in accounts_file:
                self.known_accounts[account["id"]] = account

        accounts.known_accounts = set(self.known_accounts.keys())  # type: ignore

        # Populate Org accounts
        org_accounts = self.get_org_accounts()
        aws_canonical_user = self._buckets["Owner"]

        # Add to the set of org_accounts
        accounts.org_accounts = set(org_accounts.keys())  # type: ignore
        accounts.org_accounts.add(aws_canonical_user["ID"])  # type: ignore

        # Combine the metadata
        self.known_accounts[aws_canonical_user["ID"]] = {"owner": aws_canonical_user["DisplayName"]}
        self.known_accounts = self.known_accounts | org_accounts  # type: ignore

        return accounts


def load_fetch(module_path: str, class_name: str) -> Callable:
    """Dynamically load "fetch"" from a given file/module and class"""
    path = f".services.{module_path}"
    module = importlib.import_module(path, package="awsxenos")
    cls = getattr(module, class_name)
    instance = cls()
    fn = getattr(instance, "fetch")
    return fn


def load_and_run(config_file, accounts) -> Findings:
    """Load classes from a YAML configuration file and run their 'fetch' method"""
    results = Findings()

    with open(config_file, "r") as file:
        config = yaml.safe_load(file)
        plugins = config["plugins"]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_name = {}
        for plugin in plugins:
            fn = load_fetch(plugin["module"], plugin["class"])
            args = [accounts]
            ext_args = plugin.get("args", [])
            args = args + ext_args  # type: ignore
            future = executor.submit(fn, *args)
            future_to_name[future] = plugin["module"] + "." + plugin["class"]

        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results.update(future.result())
            except Exception as e:
                # TODO: Better handling, add logger
                print(e)
                results[name] = str(e)  # Store the exception if the function call fails
    return results


def cli():
    parser = argparse.ArgumentParser(description="Scan an AWS Account for external trusts")

    parser.add_argument(
        "--reporttype",
        dest="reporttype",
        action="store",
        default="all",
        help="Type of report to generate. JSON or HTML",
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config",
        action="store",
        help="Config location",
    )
    parser.add_argument(
        "-w",
        "--write-output",
        dest="write_output",
        action="store",
        default=False,
        help="Path to write output",
    )
    args = parser.parse_args()
    reporttype = args.reporttype
    write_output = args.write_output

    if not args.config:
        config_path = f"{package_path.resolve().parent}/config.yaml"
    else:
        config_path = args.config

    prescan = PreScan()
    results = load_and_run(config_path, prescan.accounts)
    r = Report(results, prescan.known_accounts)

    if reporttype.lower() == "json":
        summary = r.JSON_report()
    elif reporttype.lower() == "html":
        summary = r.HTML_report()
    else:
        summary = r.JSON_report()

    if write_output:
        with open(f"{write_output}", "w") as f:
            f.write(summary)

    sys.stdout.write(summary)


if __name__ == "__main__":
    cli()
