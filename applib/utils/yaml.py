import sys

import yaml
from yaml.scanner import ScannerError

from loguru import logger as _logger


def read_yaml_config_file(config_file: str) -> list[dict]:
    try:
        with open(config_file, "r") as yml_file:
            integrations = yaml.safe_load(yml_file)
            if integrations is None:
                _logger.critical("Failure - integrations.yml file seems to be empty.")
                sys.exit(1)
            return integrations
    except ScannerError as e:
        _logger.critical(f"Failure in YML validation: {e.__class__}, {repr(e)} - {e}")
        sys.exit(1)
    except Exception as e:
        _logger.critical(
            f"Failure in configuration validation: {e.__class__}, {repr(e)} - {e}"
        )
        sys.exit(1)
