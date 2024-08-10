# Azure Tools

## Overview
This project includes multiple Python-based tools for managing Azure resources.

## Tools
- **[NSG Scanner](scan_nsgs/README.md)**: Queries all Network Security Groups (NSGs) across Azure subscriptions, identifies inbound rules that allow all connectivity, and exports these rules to a CSV file.
- **[Key Vault Access Policies Migrator](migrate_kv_access_policies/README.md)**: Migrates access policies on Azure Key Vault to appropriate roles based access control assignments.

## Requirements
- Python 3.11+
- Azure CLI

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.