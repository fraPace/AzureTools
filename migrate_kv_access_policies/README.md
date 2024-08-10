# Key Vault Access Policies Migrator

## Overview
The Key Vault Access Policies Migrator is a Python-based tool designed to migrate access policies on Azure Key Vault to appropriate roles based access control assignments.

## Features
- List all access policies for a given Key Vault.
- Map access policies to Azure RBAC roles.
- Assign roles based on their policy permissions.

## Requirements
- Python 3.11+
- Azure CLI

### Azure RBAC Assignments
The script requires the following Azure RBAC assignments to migrate Key Vault access policies (from most to least privileged):
- Owner or User Access Administrator or Key Vault Data Access Administrator role (either at subscription, resource group, or resource level).

## Installation
1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

## Configuration
1. Ensure you have the necessary Azure credentials set up. You can use the Azure CLI to log in:
    ```sh
    az login
    ```

2. Create a configuration file (e.g., `config.yaml`) with the necessary settings. Ensure it includes the `subscription_id`, `vault_name`, and `resource_group_name` keys. You have an example in the `config.yaml.example` file.

## Usage
1. Run the script:
    ```sh
    python main.py
    ```
2. The script will migrate Key Vault access policies to appropriate roles based access control assignments.

## Logging
The script uses Python's built-in logging module to log information. You can customize the logging configuration by modifying the `logging_config.yaml` file.


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.