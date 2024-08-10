from __future__ import annotations

import asyncio
import csv
import logging
import logging.config
import os
import time
from typing import Dict, List

import aiofiles
from azure.identity.aio import DefaultAzureCredential
from azure.mgmt.resource.subscriptions.aio import SubscriptionClient
from azure.mgmt.resourcegraph.aio import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

from core.utils import setup_logging, load_config, setup_basic_argparser


class NSGScanner:
    IP_ANY_RULES = ["any", "0.0.0.0/0", "*"]
    PORT_ANY_RULES = ["any", "0-65535", "*"]
    PROTOCOL_ANY_RULES = ["any", "*"]

    # BASIC_QUERY = "Resources | where type =~ 'microsoft.network/networksecuritygroups'"

    # BASIC_QUERY = """
    #             Resources
    #             | where type =~ 'microsoft.network/networksecuritygroups'
    #             | extend rules=properties.securityRules
    #             | mv-expand rules
    #             | where rules.properties.direction == 'Inbound'
    #             | project name, subscriptionId, ruleName=rules.name, ruleProperties=rules.properties
    #             """

    BASIC_QUERY = """  
                    Resources  
                    | where type =~ 'microsoft.network/networksecuritygroups'  
                    | extend rules=properties.securityRules  
                    | mv-expand rules   
                    | extend subnetId = tostring(properties.subnets[0].id), 
                            ruleName = tostring(rules.name),  
                            sourceAddressPrefix = tostring(rules.properties.sourceAddressPrefix),  
                            destinationAddressPrefix = tostring(rules.properties.destinationAddressPrefix),  
                            sourcePortRange = tostring(rules.properties.sourcePortRange),  
                            destinationPortRange = tostring(rules.properties.destinationPortRange),  
                            protocol = tostring(rules.properties.protocol), 
                            direction = tostring(rules.properties.direction), 
                            access = tostring(rules.properties.access) 
                    | project name, subscriptionId, ruleName, subnetId, sourceAddressPrefix, 
                            destinationAddressPrefix, sourcePortRange, destinationPortRange, 
                            protocol, direction, access  
                    | join kind=leftouter (  
                        Resources  
                        | where type =~ 'microsoft.network/publicipaddresses'  
                        | project publicIpId=id, associatedSubnet=tostring(id), ipAddress=properties.ipAddress  
                    ) on $left.subnetId == $right.associatedSubnet  
                    | summarize PublicIPCount=sum(iif(isnotempty(ipAddress), 1, 0)) by name, subscriptionId, ruleName, subnetId, 
                            sourceAddressPrefix, destinationAddressPrefix, 
                            sourcePortRange, destinationPortRange, protocol,
                            direction, access, publicIpId, ipAddress=tostring(ipAddress)
                """

    FILTERED_QUERY = """  
                    Resources  
                    | where type =~ 'microsoft.network/networksecuritygroups'  
                    | extend rules=properties.securityRules  
                    | mv-expand rules  
                    | where rules.properties.direction == 'Inbound'  
                        and rules.properties.access == 'Allow'  
                        and (rules.properties.sourceAddressPrefix == '*' or rules.properties.sourceAddressPrefix == '0.0.0.0/0' or tolower(rules.properties.sourceAddressPrefix) == "any")  
                        and (rules.properties.destinationAddressPrefix == '*' or rules.properties.destinationAddressPrefix == '0.0.0.0/0' or tolower(rules.properties.destinationAddressPrefix) == "any")  
                        and (rules.properties.sourcePortRange == '*' or rules.properties.sourcePortRange == '0-65535' or tolower(rules.properties.sourcePortRange) == "any")  
                        and (rules.properties.destinationPortRange == '*' or rules.properties.destinationPortRange == '0-65535' or tolower(rules.properties.destinationPortRange) == "any")  
                        and (rules.properties.protocol == '*' or rules.properties.protocol == 'Any') 
                    | extend subnetId = tostring(properties.subnets[0].id), 
                            ruleName = tostring(rules.name),  
                            sourceAddressPrefix = tostring(rules.properties.sourceAddressPrefix),  
                            destinationAddressPrefix = tostring(rules.properties.destinationAddressPrefix),  
                            sourcePortRange = tostring(rules.properties.sourcePortRange),  
                            destinationPortRange = tostring(rules.properties.destinationPortRange),  
                            protocol = tostring(rules.properties.protocol), 
                            direction = tostring(rules.properties.direction), 
                            access = tostring(rules.properties.access) 
                    | project name, subscriptionId, ruleName, subnetId, sourceAddressPrefix, 
                            destinationAddressPrefix, sourcePortRange, destinationPortRange, 
                            protocol, direction, access  
                    | join kind=leftouter (  
                        Resources  
                        | where type =~ 'microsoft.network/publicipaddresses'  
                        | project publicIpId=id, associatedSubnet=tostring(id), ipAddress=properties.ipAddress  
                    ) on $left.subnetId == $right.associatedSubnet 
                    | summarize PublicIPCount=sum(iif(isnotempty(ipAddress), 1, 0)) by name, subscriptionId, ruleName, subnetId, 
                            sourceAddressPrefix, destinationAddressPrefix, 
                            sourcePortRange, destinationPortRange, protocol,
                            direction, access, publicIpId, ipAddress=tostring(ipAddress)
                """

    def __init__(self, csv_file: str):
        self.credential = DefaultAzureCredential()

        self.logger = logging.getLogger(self.__class__.__name__)

        self.csv_file_path = os.path.join(csv_file)
        self.csv_writer = None

    @staticmethod
    async def is_any(setting: list | str, any_rules: list | str) -> bool:
        """
        Check if a setting is any of the specified rules
        :param setting:
        :param any_rules:
        :return:
        """
        if isinstance(setting, str) and isinstance(any_rules, str):
            return setting.lower() == any_rules.lower()

        if isinstance(setting, list) and isinstance(any_rules, str):
            return any_rules in setting

        if isinstance(setting, str) and isinstance(any_rules, list):
            return setting in any_rules

        if isinstance(setting, list) and isinstance(any_rules, list):
            return all(item in any_rules for item in setting)

    async def is_rule_allow_all(self, rule: Dict) -> bool:
        """
        Check if a rule allows all connectivity
        :param rule: Dict with the rule properties
        :return: True if the rule allows all connectivity, False otherwise
        """
        return all([
            await self.is_any(rule.get("direction", ""), 'Inbound'),
            await self.is_any(rule.get("access", ""), 'Allow'),
            await self.is_any(rule.get("sourceAddressPrefix", "").lower(), self.IP_ANY_RULES),
            await self.is_any(rule.get("destinationAddressPrefix", "").lower(), self.IP_ANY_RULES),
            await self.is_any(rule.get("sourcePortRange", "").lower(), self.PORT_ANY_RULES),
            await self.is_any(rule.get("destinationPortRange", "").lower(), self.PORT_ANY_RULES),
            await self.is_any(rule.get("protocol", "").lower(), self.PROTOCOL_ANY_RULES)
        ])

    async def process_allow_all_rules(self, rules: List[Dict]) -> List[Dict]:
        """
        Process all rules and return only the ones that allow all connectivity
        :param rules:
        :return:
        """
        total_rules = len(rules)

        allow_all_rules = []
        for index, nsg_rule in enumerate(rules, 1):
            rule_name = nsg_rule.get("ruleName")
            nsg_name = nsg_rule.get("name")
            subscription_id = nsg_rule.get("subscriptionId")
            self.logger.info(
                f"Processing Rule {index}/{total_rules}: {rule_name} for NSG {nsg_name} "
                f"in Subscription {subscription_id}")

            if await self.is_rule_allow_all(nsg_rule):
                self.logger.info(f"Rule '{rule_name}' in NSG '{nsg_name}' allows all connectivity.")
                allow_all_rules.append(nsg_rule)

        # self.logger.info("Scan complete.")

        return allow_all_rules

    async def query_nsgs_and_rules(self) -> List[Dict]:
        """
        Query all NSGs and their rules across all subscriptions
        :return:
        """
        self.logger.info("Querying all NSGs across subscriptions using Azure Resource Graph...")
        async with self.credential:
            subscription_client = SubscriptionClient(self.credential)

            resource_graph_client = ResourceGraphClient(credential=self.credential)

            query = self.BASIC_QUERY
            subscriptions = [sub.subscription_id async for sub in subscription_client.subscriptions.list()]

            options = QueryRequestOptions(result_format="objectArray")
            request = QueryRequest(subscriptions=subscriptions, query=query, options=options)

            response = await resource_graph_client.resources(request)
            all_results = list(response.data)

            # Handle pagination with continuation token
            while response.skip_token:
                request.options.skip_token = response.skip_token
                response = await resource_graph_client.resources(request)
                all_results.extend(response.data)
            # tasks = [asyncio.create_task(self.process_rules(response.data))]
            # while response.skip_token:
            #     request.options.skip_token = response.skip_token
            #     response = await resource_graph_client.resources(request)
            #     tasks.append(asyncio.create_task(self.process_rules(response.data)))
            # all_results = list(itertools.chain(*await asyncio.gather(*tasks)))

            return all_results

    async def get_allow_all_rules(self) -> List[Dict]:
        """
        Get all Inbound Rules that allow all connectivity
        :return:
        """
        self.logger.info("Reading all Inbound Rules from all NSGs across all Subscriptions...")
        all_rules = await self.query_nsgs_and_rules()
        total_rules = len(all_rules)
        self.logger.info(f"Done. Total Rules to process: {total_rules}")

        allow_all_rules = await self.process_allow_all_rules(all_rules)

        self.logger.info("Scan complete.")

        return allow_all_rules

    async def export_rules_to_csv(self, csv_file: str, rules: Dict) -> None:
        """
        Export the rules to a CSV file
        :param csv_file:
        :param rules:
        """
        # This will store all unique keys across all rules
        all_keys = set()

        # A list to hold flattened rule dictionaries
        flattened_rules = []

        # Flatten each rule dictionary, including nested properties
        for rule in rules:
            flat_rule_dict = {
                **{key: value for key, value in rule.items() if key != 'ruleProperties'},
                **{f'ruleProperties_{key}': value for key, value in rule.get('ruleProperties', {}).items()}
            }
            flattened_rules.append(flat_rule_dict)
            all_keys.update(flat_rule_dict.keys())

            # Convert set to list to maintain order and use as fieldnames in CSV
        all_keys = sorted(list(all_keys))

        # Initialize the CSV writer
        self.csv_writer = csv.DictWriter(csv_file, fieldnames=all_keys)
        await self.csv_writer.writeheader()

        # Write each flattened rule to the CSV file
        for flat_rule in flattened_rules:
            # Fill missing keys with None or an empty string
            filled_rule = {key: flat_rule.get(key, None) for key in all_keys}
            await self.csv_writer.writerow(filled_rule)


async def main(output_dir: str) -> None:
    """
    Main function to scan all NSGs and export rules to a CSV file
    """
    # Start time measurement
    start_time = time.time()

    logger = logging.getLogger(__name__)

    csv_file_path = os.path.join(output_dir, "allow_all_rules.csv")
    # Create the output directory if it does not exist
    os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)

    # Initialize the scanner
    scanner = NSGScanner(csv_file_path)
    # Query all NSGs and their rules
    rules = await scanner.get_allow_all_rules()
    logger.info(f"Found {len(rules)} rules that allow all connectivity.")
    # Export the rules to a CSV file
    async with aiofiles.open(csv_file_path, mode='w', newline='') as csv_file:
        await scanner.export_rules_to_csv(csv_file, rules)
    # End time measurement
    end_time = time.time()
    logger.info(f"Execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    parser = setup_basic_argparser()
    args = parser.parse_args()

    setup_logging(os.path.join(str(args.logging_config_file)))

    _logger = logging.getLogger(__name__)

    config = load_config(os.path.join(str(args.config_file)))

    asyncio.run(main(output_dir=config.get("output_dir")))
