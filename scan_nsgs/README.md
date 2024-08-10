# NSG Scanner

## Overview
The NSG Scanner is a Python-based tool designed to query all Network Security Groups (NSGs) across Azure subscriptions, identify inbound rules that allow all connectivity, and export these rules to a CSV file.

## Features
- Query NSGs across multiple Azure subscriptions using Azure Resource Graph.
- Identify inbound rules that allow all connectivity.
- Export the identified rules to a CSV file.

## Requirements
- Python 3.11+
- Azure CLI

### Azure RBAC Assignments
The script requires the following Azure RBAC assignments to query NSGs across subscriptions (from most to least privileged):
- Reader role (either at subscription, resource group, or resource level)


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

2. Create a configuration file (e.g., `config.yaml`) with the necessary settings. Ensure it includes the `output_dir` key for the output directory. You have an example in the `config.yaml.example` file.

## Usage
1. Run the script:
    ```sh
    python scan_nsgs.py
    ```

2. The script will query all NSGs, identify the rules that allow all connectivity, and export these rules to a CSV file in the specified output directory.

## Logging
The script uses Python's built-in logging module to log information. You can customize the logging configuration by modifying the `logging_config.yaml` file.


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.