import os
import sys
from enum import Enum
from pathlib import Path
from sqlite3 import OperationalError
from threading import RLock

import typer
from loguru import logger as _logger

from applib.schemas.app import ControllerInput
from applib.schemas.config import config_validation, CompanyModel
from applib.utils.logging import init_logging
from applib.utils.utils import CustomCacheFile
from applib.utils.yaml import read_yaml_config_file
from applib.work import Worker
from lumudblib.utils import check_process


class LoggingTypeEnum(str, Enum):
    screen = "screen"
    file = "file"


def main(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose mode."),
    clean: bool = typer.Option(
        False,
        "--clean",
        help="Clean all integrations and override the yml clean field.",
    ),
    logging_type: LoggingTypeEnum = typer.Option(
        LoggingTypeEnum.screen,
        "--logging-type",
        "-l",
        help="Logging output type: 'screen' or 'file'",
        case_sensitive=False,
    ),
    config: str = typer.Option(
        "integrations.yml", "--config", help="Path to the configuration file."
    ),
    ioc_manager_db_path: str = typer.Option(
        "./ioc.db",
        "--ioc-manager-db-path",
        help="Path to the IOC manager database file.",
    ),
):
    init_logging(logging_type, verbose=verbose)
    check_process(__file__)

    ioc_db_path = Path(ioc_manager_db_path)
    try:
        if (
            not ioc_db_path.exists()
            or not ioc_db_path.is_file()
            or not ioc_db_path.stat().st_size
        ):
            _logger.critical(f"ioc_manager_db_path not found or empty: {ioc_db_path}")
            sys.exit(1)
        os.environ["IOC_DB_PATH"] = ioc_db_path.name

    except OperationalError as e:
        _logger.critical(f"{e.__class__} - {repr(e)} on {ioc_db_path} \n {e}")
        sys.exit(1)

    integrations = read_yaml_config_file(config)

    outbound_rule_file = CustomCacheFile(".rule_id_file.json", rlock=RLock())
    last_register_file = CustomCacheFile(".last_register_file.json", rlock=RLock())

    worker = Worker(outbound_rule_file, last_register_file)

    app_names = set()
    for integration in integrations:
        config: CompanyModel = config_validation(integration)
        if not config:
            _logger.error("Invalid configuration file.")
            raise sys.exit(1)

        integration_uuid = config.app.name + "-" + str(config.lumu.uuid)
        app_name = config.app.name.lower()
        app_names.add(app_name)

        controller_input = ControllerInput(
            integration_uuid=integration_uuid,
            config=config,
            clean=clean,
            ioc_db_path=ioc_db_path,
        )

        worker.init_integration(controller_input)

    if len(app_names) != len(integrations):
        _logger.critical(
            f"There is a duplicate Company Name. Review your input in your configuration file: {app_names}"
        )
        sys.exit(1)

    worker.run_threads()

    _logger.info("Integration has finished")


if __name__ == "__main__":
    typer.run(main)
