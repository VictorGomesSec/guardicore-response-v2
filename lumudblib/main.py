import argparse
import gc
import json
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, time, date
from time import sleep

import psutil
import schedule
import yaml
from pydantic import ValidationError
from yaml.scanner import ScannerError

from lumudblib.db_client import create_companies, clean_expired_records
from lumudblib.integration_db import CustomLumuDBIntegration
from lumudblib.models.db import Base, engine
from lumudblib.schema import CompanySchema
from lumulib.defender import Incident
from lumulib.integration import LumuResponseIntegration
from lumulib.web_socket_consumer import messages_throttled_consumer
from lumulib.websock import WebSocketLumu, MsgThrottling
from utils import init_logging


def run(
    companies: list[CompanySchema],
    _logger: logging.Logger,
    _verbose: bool,
    days_intervals,
    db_expires_days,
    _logging_type,
):
    run_path = os.path.dirname(os.path.realpath(__file__))

    def init_websock(
        company_key,
        companyId,
        pendings: MsgThrottling,
        lumu_db_integration: CustomLumuDBIntegration,
    ):
        ws_client = WebSocketLumu(
            company_key=company_key,
            ioc_inc_inc_integration=lumu_db_integration,
            companyId=companyId,
            msgs_throttle=pendings,
        )
        ws_client.run_ws()

    def job_all_ioc(
        argv,
        run_path,
        ioc_types,
        companyId,
        lumu_db_integration: CustomLumuDBIntegration,
    ):
        try:
            inc_integration = LumuResponseIntegration(
                argv, run_path=run_path, ioc_types=ioc_types
            )
            inc_integration.init_lumu()
            lumu_incidents = inc_integration.collect_incidents()
            _logger.info(
                f"job_all_ioc - companyId: {companyId} - Incidents length before filtering duplicates, adversaries and status: {len(lumu_incidents)}"
            )

            def remove_duplicates_inc_adversaries_status(
                lumu_incidents: list[Incident],
            ):
                items: dict[str, Incident | None] = {
                    f"{inc.adversaryId}-{inc.status}": None for inc in lumu_incidents
                }
                for incident in lumu_incidents:
                    if not items.get(f"{incident.adversaryId}-{incident.status}"):
                        items[f"{incident.adversaryId}-{incident.status}"] = incident
                    else:
                        if datetime.fromisoformat(
                            items[
                                f"{incident.adversaryId}-{incident.status}"
                            ].lastContact.strip("zZ")
                        ) < datetime.fromisoformat(incident.lastContact.strip("zZ")):
                            items[f"{incident.adversaryId}-{incident.status}"] = (
                                incident
                            )

                return list(items.values())

            lumu_incidents = remove_duplicates_inc_adversaries_status(lumu_incidents)
            _logger.info(
                f"job_all_ioc - companyId: {companyId} - Incidents length after filtering duplicates, adversaries and status: {len(lumu_incidents)}"
            )
            num_lumu_incidents = len(lumu_incidents)
            for i, incident in enumerate(lumu_incidents, 1):
                _logger.info(f"companyId: {companyId} - {i} of {num_lumu_incidents}")
                lumu_db_integration.save_incident(incident)
                if incident.status == "muted":
                    _logger.info(
                        f"companyId: {companyId} - Skipping IOC collection from incident '{incident.id}' due to '{incident.status}' status"
                    )
                    continue
                lumu_db_integration.save_inc_ioc(incident, incident.content)

            del lumu_incidents
            del inc_integration
        except Exception as e:
            _logger.error(e)
        finally:
            gc.collect()
            sys.exit()

    def thread_polling_ioc(
        company: CompanySchema,
        lumu_db_integration: CustomLumuDBIntegration,
        offset_day_of_year,
        interval_days=3,
    ):
        if (
            ((y_day := datetime.today().timetuple().tm_yday) - offset_day_of_year)
            % interval_days
        ) != 0:
            _logger.warning(
                f"thread_polling_ioc, the day number does not match the interval. It is not time to poll the IOCs. "
                f"{y_day=} & {offset_day_of_year} & {interval_days=}"
            )
            return
        companyId = company.lumu.uuid
        company_key = company.lumu.defender_key
        hash_type = company.lumu.hash_type
        ioc_types = company.lumu.ioc_types
        adversary = company.lumu.adversary
        days = company.lumu.days

        argv = []
        argv += ["--company_key", company_key]
        argv += ["--days", str(days)]
        argv += ["--logging", _logging_type]
        if _verbose:
            argv += ["--verbose"]
        for adversary_type in adversary:
            argv += ["--adversary-types", adversary_type]

        task_poll = threading.Thread(
            target=job_all_ioc,
            args=(argv, run_path, ioc_types, companyId, lumu_db_integration),
        )
        task_poll.name = f"thread-{companyId}"
        task_poll.start()

    def schedule_polling_ioc(
        companies: list[CompanySchema],
        lumu_db_integrations: dict[str, CustomLumuDBIntegration],
    ):
        day_of_year = datetime.today().timetuple().tm_yday
        start_polling_hour = (datetime.today() + timedelta(minutes=3)).time().strftime(
            "%H:%M:%S"
        ) or "02:02:15"
        start_hour = time.fromisoformat(start_polling_hour)
        timestamp = datetime.combine(date.today(), start_hour)
        time_step = timedelta(minutes=21)
        for i, company in enumerate(companies):
            lumu_db_integration = lumu_db_integrations.get(str(company.lumu.uuid))
            schedule_time = (timestamp + (time_step * i)).time().isoformat()
            schedule.every().days.at(schedule_time).do(
                thread_polling_ioc,
                company,
                lumu_db_integration,
                day_of_year,
                days_intervals,
            )
            _logger.info(
                f"schedule_polling_ioc - companyId: {company.lumu.uuid} - every {days_intervals} days at {schedule_time}"
            )

    def job_clean_db(worker: ThreadPoolExecutor, days):
        worker.submit(clean_expired_records, days=days)
        _logger.info(f"job_clean_db - Local DB cleaned")

    websock_pool = {}
    websock_consumer_pool = {}

    lumu_db_integrations = {}
    msgs_pendings = {}
    app_process = psutil.Process()
    with ThreadPoolExecutor(
        max_workers=2 * len(companies) + 3, thread_name_prefix="Pool"
    ) as executor:
        for company in companies:
            company_id = str(company.lumu.uuid)
            defender_key = company.lumu.defender_key
            hash_type = company.lumu.hash_type
            ioc_types = company.lumu.ioc_types

            lock = threading.RLock()
            msgs_pending = MsgThrottling(lock).begin()
            msgs_pendings[company_id] = msgs_pending

            lumu_db_integration = CustomLumuDBIntegration(
                company_key=defender_key,
                hash_type=hash_type,
                companyId=company_id,
                ioc_types=ioc_types,
            )
            lumu_db_integrations[company_id] = lumu_db_integration

            websock_pool.update(
                {
                    company_id: executor.submit(
                        init_websock,
                        defender_key,
                        company_id,
                        msgs_pending,
                        lumu_db_integration,
                    )
                }
            )

            websock_consumer_pool.update(
                {
                    company_id: executor.submit(
                        messages_throttled_consumer,
                        company_id,
                        msgs_pending,
                        lumu_db_integration,
                    )
                }
            )

        schedule_polling_ioc(companies, lumu_db_integrations)
        schedule.every(6).hours.at("05:05").do(job_clean_db, executor, db_expires_days)
        counter = 0
        while True:
            schedule.run_pending()

            for company_id, worker in websock_consumer_pool.items():
                if not worker.running():
                    worker_exception = worker.exception()
                    _logger.error(
                        f"websock_consumer_pool - companyId: {company_id} - {worker_exception.__class__}, {repr(worker_exception)}, {worker_exception}"
                    )
                    if companies_filtered := list(
                        filter(
                            lambda record: str(record.lumu.uuid) == company_id,
                            companies,
                        )
                    ):
                        company = next(iter(companies_filtered))

                        company_id = str(company.lumu.uuid)

                        websock_consumer_pool.update(
                            {
                                company_id: executor.submit(
                                    messages_throttled_consumer,
                                    company_id,
                                    msgs_pendings[company_id],
                                    lumu_db_integrations[company_id],
                                )
                            }
                        )
                        _logger.info(
                            f"companyId: {company_id} - restarting Websocket consumer thread"
                        )

            for company_id, worker in websock_pool.items():
                if not worker.running():
                    worker_exception = worker.exception()
                    _logger.error(
                        f"websock_pool- companyId: {company_id} - {worker_exception.__class__}, {repr(worker_exception)}, {worker_exception}"
                    )
                    if companies_filtered := list(
                        filter(
                            lambda record: str(record.lumu.uuid) == company_id,
                            companies,
                        )
                    ):
                        company = next(iter(companies_filtered))

                        company_id = str(company.lumu.uuid)
                        defender_key = company.lumu.defender_key

                        websock_pool.update(
                            {
                                company_id: executor.submit(
                                    init_websock,
                                    defender_key,
                                    company_id,
                                    msgs_pendings[company_id],
                                    lumu_db_integrations[company_id],
                                )
                            }
                        )
                        _logger.info(
                            f"companyId: {company_id} - restarting Websocket thread"
                        )

            if counter >= 20:
                _logger.info(f"About {threading.active_count()} active threads")
                msg_mem = f"Memory rss used: {app_process.memory_info().rss / (1024 * 1024)} Mb {app_process.memory_percent()} %"
                _logger.info(msg_mem)
                counter = 0
            counter += 1
            gc.collect()
            sleep(15)


def main():
    LOG_FILE = "lumu.log"
    LOG_MAX_BYTES = 10 * 1024 * 1024
    LOG_PATH = "."
    LOG_SHORTNAME = "lumu-ioc-management"
    LOG_HEADER = "Lumu Custom Response"

    DESCRIPTION = "Lumu Custom IOC management: Main Process"
    INTEGRATION_SHORT_NAME = "ioc_management_lumu"
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog="Please complete all parameter to run",
        prog=INTEGRATION_SHORT_NAME,
    )
    parser.add_argument(
        "--config",
        default="companies.yml",
        help="The configuration file path (default: companies.yml)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enables verbosity in log output",
    )
    parser.add_argument(
        "-l",
        "--logging",
        choices=["screen", "file"],
        default="screen",
        help="Writes command output to screen or to log file (default: screen)",
    )
    parser.add_argument(
        "--hours",
        default=720 * 3,
        type=int,
        help="Defines the time the script preserves its log record. USE WITH CAUTION",
    )
    parser.add_argument(
        "--days-intervals",
        dest="days_intervals",
        default=3,
        type=int,
        help="Time interval in days to run a full update of Lumu IOCs (default: 3)",
    )

    args = parser.parse_args()

    companies_config_path = args.config
    file = os.path.join(LOG_PATH, LOG_FILE)
    init_logging(args.logging, file, args.verbose, maxBytes=LOG_MAX_BYTES)

    db_expires_days = int(args.hours / 24)

    days_intervals = args.days_intervals
    _logging_type = args.logging
    _verbose = args.verbose
    _logger = logging.getLogger("ioc_manager")
    Base.metadata.create_all(engine)

    if not (
        os.path.exists(companies_config_path) and os.path.isfile(companies_config_path)
    ):
        print("#" * 150)
        print("Go check the companies_template.yml file")
        print("#" * 150)
        exit(f"Error: the yml config file not exist")

    try:
        with open(companies_config_path, "r") as yml_file:
            companies_config = yaml.safe_load(yml_file)
    except yaml.scanner.ScannerError as e:
        exit(f"Invalid configuration file: {e.__class__}, {repr(e)} - {e}")

    try:
        companies = [
            CompanySchema.model_validate(company) for company in companies_config
        ]
        create_companies(companies_config)
    except ValidationError as errors:
        for error in errors.errors():
            _logger.error(
                f"Parameter: {'.'.join((str(loc) for loc in error['loc']))} -> type:{error['type']} -> {error['msg']}"
            )
        sys.exit(1)
    except (ValueError, json.decoder.JSONDecodeError) as e:
        _logger.critical(f"Malformed configuration file - {repr(e)} - {e.__class__}")
        sys.exit(1)

    run(companies, _logger, _verbose, days_intervals, db_expires_days, _logging_type)
