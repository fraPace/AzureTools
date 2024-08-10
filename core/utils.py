from __future__ import annotations

import argparse
import logging
import logging.config
import os
from typing import Dict, Any

import yaml

# Constants for file paths
CONFIG_FILE_NAME = 'config.yaml'
LOGGING_CONFIG_FILE_NAME = 'logging_config.yaml'

CONFIG_PATH = os.path.join(os.path.dirname(__file__), CONFIG_FILE_NAME)
LOGGING_CONFIG_PATH = os.path.join(os.path.dirname(__file__), LOGGING_CONFIG_FILE_NAME)


# Load logging configuration
def setup_logging(config_path: str = LOGGING_CONFIG_PATH):
    """
    Load logging configuration from a YAML file if it exists, otherwise set up a basic configuration
    """
    if os.path.exists(config_path):
        with open(config_path) as config_file:
            logging.config.dictConfig(yaml.safe_load(config_file))
    else:
        logging.basicConfig(level=logging.INFO)


def load_config(path: str = CONFIG_PATH) -> Dict[str, Any]:
    """Load configuration from a YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def get_config(key: str, config: Dict[str, Any] = None) -> Dict[str, Any] | None:
    """
    Get configuration for the current script from a configuration dictionary.

    :param key:
    :param config:
    :return:
    """
    if key not in config:
        return None
    return config[key]


def setup_basic_argparser():
    """
    Set up a basic argument parser for the script.
    :return:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--config_file", type=str,
                        default="config.yaml", help="Path to the configuration file",
                        dest="config_file")
    parser.add_argument("--logging_config_file", type=str,
                        default="logging_config.yaml", help="Path to the logging configuration file",
                        dest="logging_config_file")
    return parser
