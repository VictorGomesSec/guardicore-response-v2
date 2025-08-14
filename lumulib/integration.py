"""
Base integration class.

This class is used as the base of Custom (Ad-hoc) integration. The main goal of this class is to assist the development
of other integrations based on CLI.

All integrations classes should extend this one
"""

from __future__ import absolute_import

import logging
import os
from argparse import Action
from datetime import datetime, timedelta
from typing import Literal
from urllib.parse import urlparse

from requests import HTTPError

# Lumu lib
import lumulib.defender as defender

# Utils constants
from utils import FLAGS_LUMU

# Cmd utils
from utils import (
    parse,
    dslice,
    init_logging,
    check_pid_lock,
    create_pid_lock,
    release_pid_lock,
    error,
    clean_domain,
    get_ioc_type,
)

# Used for date format
from .constants.globals import DATE_FORMAT, INCIDENT_DETAILS

# Global logger to differentiate log entries between portions of codes
logger = None

LOCK_FILE = "pid.pid"
LOG_FILE = "lumu.log"
LOG_MAX_BYTES = 10 * 1024 * 1024

# Adversary types to be checked
ADVERSARY_TYPES = ["C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"]
# IOC types to be collected per incident
IOC_TYPES = ["ip", "domain", "url", "hash"]
HASH_TYPES = ["sha256", "sha1", "md5"]

# Max days allowed to fetch Lumu incidents
MAX_DAYS = 30

# Updated flags management

# Lumu specific flags for tool
FLAGS_LUMU_QUERY = {
    "adversary_types": {
        "flags": ["--adversary-types", "--adversary_types"],
        "action": "append",
        "choices": ADVERSARY_TYPES,
        "help": "Lumu adversary types to be filtered.",
    }
}

# Output flags
FLAGS_OUTPUT = {
    "logging": {
        "flags": ["--logging"],
        "default": "screen",
        "choices": ["screen", "file"],
        "help": "Logging option (default screen).",
    },
    "verbose": {
        "flags": ["--verbose", "-v"],
        "action": "store_true",
        "default": False,
        "help": "Verbosity level.",
    },
}


# CustomAction to handle days argument
class DaysAction(Action):
    """
    Custom action to handle days argument
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if values > MAX_DAYS:
            parser.error(f"Max number for {option_string} is {MAX_DAYS}.")

        setattr(namespace, self.dest, values)


# Specific flags for tool
FLAGS_TOOL = {
    "days": {
        "flags": ["--days"],
        "type": int,
        "action": DaysAction,
        "default": MAX_DAYS,
        "help": f"The number of days backward from now to query Lumu incidents (default {MAX_DAYS}).",
    },
    "test": {
        "flags": ["--test", "-t"],
        "action": "store_true",
        "default": False,
        "help": "Runs a test with one incident only.",
    },
    "clean": {
        "flags": ["--clean"],
        "action": "store_true",
        "default": False,
        "help": "Cleans all rules and objects created by the Lumu integration.",
    },
}


def cmdline(argv, flags, **kwargs):
    """A cmdopts wrapper that takes a list of flags and builds the
    corresponding cmdopts rules to match those flags."""
    # Enhance to handle list or dict with fully defined args
    if isinstance(flags, list):
        rules = dict([(flag, {"flags": ["--%s" % flag]}) for flag in flags])
    elif isinstance(flags, dict):
        rules = flags
    return parse(argv, rules, ".config", **kwargs)


class LumuResponseIntegrationException(Exception):
    """
    Base exception
    """


class LumuResponseIntegration(object):
    """
    Base class to encapsulate all actions required to process a custom response integration
    """

    def __init__(
        self,
        argv,
        short_name="",
        log_header="Lumu Response Integration",
        description="Lumu integration",
        ioc_types=IOC_TYPES,
        run_path=".",
    ):
        """
        The class constructor takes the command line arguments to take change of the parsing process.
        Create the required objects and continue all the processing.

        :param argv: `list` List with console arguments
        :param short_name: `str` Short name given to the integration (used for log header)
        :param log_header: `str` Log header. String used to identify the beginning of integration execution within log trace
        :param description: `str` Descriptions to be shown in the help menu
        :param ioc_types: `list` List of IOC types to be processed. Useful to collect specific IOC types according to the third-party tool to be integrated
        :param run_path: `str` Folder/directory where the integration wil save required files: log, intermediate files. Set this accordingly or you will have this files inside `lumulib` folder
        """
        # Runtime control
        self.start_time = datetime.now()
        self.start_time_utc = datetime.utcnow()
        # Integration short name
        self.short_name = short_name
        # Description of the integration
        self.description = description
        # Log header
        self.log_header = log_header
        # Lock file
        self.tool_path = run_path
        self.lock_file = os.path.join(self.tool_path, LOCK_FILE)
        # IOC types to be processed
        self.ioc_types_to_process(ioc_types)
        # Setting flags for the parser
        self.flags_processing()
        self.opts = cmdline(argv, self.flags, description=self.description)
        # Time To dslice arguments
        self.dslice_arguments()
        self.init_logging()
        self.argument_postprocessing()
        # Attribute to save running stats
        self.stats = {
            "ip": {"collected": 0},
            "host": {"collected": 0},
            "url": {"collected": 0},
            "hash": {"collected": 0},
        }
        # Dict to kee record of IOC
        self.ioc = {"ip": [], "host": [], "url": [], "hash": []}

    def ioc_types_to_process(self, ioc_types):
        """
        Check the IOC types to process
        """
        # If ioc_types is a single value, then convert to list
        if not isinstance(ioc_types, list):
            ioc_types = [ioc_types]

        # If the symmetric difference has results, then we raise an exception
        sym_diff = list(set(ioc_types) - set(IOC_TYPES))
        if len(sym_diff) > 0:
            raise LumuResponseIntegrationException(
                f"Not valid IOC types: {', '.join(sym_diff)}"
            )

        # Finally, set IOC types to process
        self.ioc_types = ioc_types

    def flags_processing(self):
        """
        Flags processing.
        This function builds the required flags to process user's input

        Overrides this method to add the required arguments for your integration
        """
        self.flags = {}
        # Flags related to verbosity and script output
        self.flags.update(FLAGS_OUTPUT)
        # Flags related to Lumu Defender queries
        self.flags.update(FLAGS_LUMU_QUERY)
        # Flags related to tool information
        self.flags.update(FLAGS_TOOL)

    def dslice_arguments(self):
        """
        Dslice arguments based on the flags give to the processing phase.

        Override to add third-party solution specific arguments
        """
        self.kwargs = {}
        # Lumu arguments
        self.kwargs["lumu"] = dslice(self.opts.kwargs, FLAGS_LUMU)
        self.kwargs["lumu_query"] = dslice(self.opts.kwargs, FLAGS_LUMU_QUERY)

        # Output and tool arguments
        self.kwargs["output"] = dslice(self.opts.kwargs, FLAGS_OUTPUT)
        self.kwargs["tool"] = dslice(self.opts.kwargs, FLAGS_TOOL)

    def argument_postprocessing(self):
        """
        Argument post-processing.

        Runs additional checks required on the arguments given by the user. Override it accordingly
        """

    def init_logging(self):
        """
        Method used to init logging capabilities based on user input
        """
        # Logging init
        logging_type = self.kwargs["output"]["logging"]
        file = os.path.join(self.tool_path, LOG_FILE)
        verbose = self.kwargs["output"]["verbose"]
        init_logging(logging_type, file, verbose, maxBytes=LOG_MAX_BYTES)
        # Setting specific logger
        self.logger = logging.getLogger(self.short_name)
        self.logger.info(f"----------------- {self.log_header} -----------------")

    def check_race_conditions(self):
        """
        Tests if there is another instance running. If so, quits.
        """
        # Check to avoid race conditions based on cron schedule
        if check_pid_lock(self.lock_file):
            self.logger.info("Another instance is already running. Quitting")
            error("Another instance is running. Quitting.", 2)

    def lock_process(self, action="create"):
        """
        Handles process lock fle based on action parameter
        :param action: `str` "create" or "destroy". Acts according the argument
        """
        if action == "create":
            self.logger.debug("Creating lock file.")
            create_pid_lock(self.lock_file)
        elif action == "destroy":
            self.logger.debug("Releasing lock file.")
            release_pid_lock(self.lock_file)

    def init_lumu(self):
        """
        Method to initialize Lumu Defender API instance
        """
        try:
            self.logger.info("Getting instance to operate with Lumu Defender.")
            self.lumu = defender.connect(**self.kwargs["lumu"])
        except Exception as e:
            self.logger.error(f"Cannot connect to Lumu API.")
            self.logger.debug(f"Details: {e}")
            # Release lock
            self.lock_process("destroy")
            error("Cannot connect to Lumu. Check log for details.", 2)

    def init_thirdparty(self):
        """
        Method to initialize Third-party API.

        Override it accordingly.

        Example:
            try:
                self.logger.info("Getting instance to operate with Meraki dashboard API")
                self.meraki = DashboardAPI(**self.kwargs["meraki"])
            except Exception as e:
                self.logger.error("Cannot connect to Meraki Dashboard API.")
                self.logger.debug(f"Details: { e }")
                self.lock_process("destroy")
                error("Cannot connect to Mekari Dashboard API. Check logs for details.", 2)
        """

    def collect_incidents(self):
        """
        Method to collect incidents based on arguments received from user: days, adversary_types
        """
        # First, identify which adversary types were selected, if none, the all will be queried
        adversary_types = self.kwargs["lumu_query"].get(
            "adversary_types", ADVERSARY_TYPES
        )

        # Check if days argument is set
        days = self.kwargs["tool"].get("days", None)

        # Check if it's a test run
        is_test = self.kwargs["tool"].get("test")

        # Params to collect incidents
        params = {
            "adversary-types": adversary_types,
            "status": ["open", "closed", "muted"],
        }

        # Collect all incidents
        if days:
            from_time = self.start_time_utc - timedelta(days=days)
            params["fromDate"] = from_time.strftime(DATE_FORMAT)

        # Based on the timestamp, build the log message
        msg_timespan = (
            "for the last 7 days" if not days else f"for the last {days} days"
        )
        adversary_types = self.kwargs["lumu_query"].get(
            "adversary_types", ADVERSARY_TYPES
        )
        self.logger.info(
            f"Collecting incidents {msg_timespan}. Adversary types: {', '.join(adversary_types)}. IOC types: {', '.join(self.ioc_types)}"
        )
        try:
            incidents = self.lumu.incidents.get_all(**params)
        except Exception as e:
            raise Exception("Cannot collect Lumu incidents.")

        # We will sort incidents in descending order based on lastContact value. This will be useful if we need to truncate the number of IOCs
        # later based on third-party solution restrictions.
        incidents = sorted(
            incidents,
            key=lambda incident: datetime.strptime(
                f"{incident.lastContact[:19]}Z", "%Y-%m-%dT%H:%M:%SZ"
            ),
            reverse=True,
        )

        # If it's a test, truncate to one incident
        if is_test:
            self.logger.info("This a test run.")
            incidents = incidents[:1]

        return incidents

    @staticmethod
    def process_ioc(ioc, incident, incident_details=INCIDENT_DETAILS):
        """
        Static method to process IOC.

        Add the information indicated by the `incident_details` argument.

        :param ioc: `str` IOC to be processed.
        :param incident: `Incident` Incident detail.
        :param incident_details: `list` List of parameters to be included in the IOC.
        :return: `dict` Dictionary with all the information requested by the IOC
        """
        # Process the IOC and return it as a dict
        # Check if incident_details are valid
        # If the symmetric difference has results, then we raise an exception
        sym_diff = list(set(incident_details) - set(INCIDENT_DETAILS))
        if len(sym_diff) > 0:
            raise LumuResponseIntegrationException(
                f"Incident details not valid: {', '.join(sym_diff)}"
            )

        # Time to process the ioc
        ioc_detail = {"ioc": ioc}

        # Check all details requested and add them in the ioc_details dictionary
        for detail in incident_details:
            ioc_detail[detail] = incident[detail]

        return ioc_detail

    def process_incidents(
        self,
        ioc_types=IOC_TYPES,
        hash_type="sha256",
        consolidate_https=False,
        remove_duplicates=True,
        incident_details=INCIDENT_DETAILS,
    ):
        """
        Process each incident IOCs based on the input given by the user.

        This method queries and process IOCs based on type: IP, domain, URL, HASH

        Override this method accordingly. The flow here could differ based on the third-party product features.

        :param ioc_types: `list` List of IOC types to collect from Lumu incidents (ip, domain, url, hash)
        :param hash_type: `str` Hash type to query from Lumu if 'hash' is included in the ioc_types argument (sha256, sha1, md5) Default sha256
        :param consolidate_https: `bool` If set to True, the https URLs will be consolidated into one, just schema and domain.
        :param remove_duplicates: `bool` If set to True, removes all duplicated IOCs
        :param incident_details: `list` Incident details to be collected and added to the IOC information (default all).
        """
        # The method has been updated to collect as muchs details as required per IOC
        incidents_count = len(self.incidents)
        processed_incidents_count = 0
        if incidents_count > 0:
            self.logger.info(
                f"Starting to process incidents. Incidents found: {incidents_count}."
            )
            # Based on the indicated feature, process different type of indicators per incident
            # Collected IOCs will be stored at self.ioc dict
            for incident in self.incidents:
                incident_ips, incident_hosts, incident_urls, incident_hashes = (
                    [] for i in range(4)
                )
                processed_incidents_count += 1
                self.logger.info(
                    f"Processing incident {processed_incidents_count} of {incidents_count}. ID: {incident['id']}. Please wait."
                )

                # We need to collect the incident context to validate if the related IOCs are no longer valid
                try:
                    # Request specific hash type indistinctly
                    context = incident.context(hash_type=hash_type)
                except (HTTPError, ConnectionError) as e:
                    # This error is not considered a critical one. Just display a warning and skip to the next incident
                    self.logger.warning(
                        f"Cannot collect context for incident {incident.id}. Skipping."
                    )
                    continue

                # Fixed missing IOCs
                currently_active = context.get("currently_active", False)
                rank = context.get("rank", 900000)
                if currently_active is False or rank < 900000:
                    self.logger.debug(
                        f"Skipping incident {incident.id}. Adversary: {incident.adversaryId}. Active: {currently_active}. Rank: {rank}"
                    )
                    continue

                # Modifying how to collect and classify IOCs per incident
                # File hashes first
                related_files = context.get("related_files", [])
                for ioc in related_files:
                    incident_hashes.append(
                        self.process_ioc(ioc, incident, incident_details)
                    )
                # Now, let's check threat_triggers
                threat_triggers = context.get("threat_triggers", [])
                for ioc in threat_triggers:
                    # Potential formats
                    # [[scheme]://][adversary]:[port][/[path]/[query]]
                    # Scheme: tcp, udp, http, https
                    if "://" not in ioc:
                        # Lets add a dummy scheme to parse it
                        parsed_ioc = urlparse(f"dummy://{ioc}")
                    else:
                        parsed_ioc = urlparse(ioc)
                    # Now, it's time to classify the ioc
                    if parsed_ioc.scheme in ["http", "https"]:
                        # This is an URL
                        for ioc_ in self.depurate_urls(
                            [ioc], consolidate_https, remove_duplicates
                        ):
                            incident_urls.append(
                                self.process_ioc(ioc_, incident, incident_details)
                            )
                    elif parsed_ioc.scheme in ["tcp", "udp", "dummy"]:
                        # First, check if we have port
                        if ":" in parsed_ioc.netloc:
                            ioc_str = parsed_ioc.netloc.split(":")[0]
                        else:
                            ioc_str = parsed_ioc.netloc
                        # Let's check if we have domain or IP
                        if (ioc_type := get_ioc_type(ioc_str)) == "ip":
                            incident_ips.append(
                                self.process_ioc(ioc_str, incident, incident_details)
                            )
                        elif ioc_type == "domain":
                            incident_hosts.append(
                                self.process_ioc(
                                    clean_domain(ioc_str), incident, incident_details
                                )
                            )

                # Finally, check if we need to append adversaries
                for adversary in incident.adversaries:
                    if incident_ips or incident_hosts:
                        # If we have already stored information of IPs or hosts, break
                        break
                    if (ioc_type := get_ioc_type(adversary)) == "ip":
                        incident_ips.append(
                            self.process_ioc(adversary, incident, incident_details)
                        )
                    elif ioc_type == "domain":
                        incident_hosts.append(
                            self.process_ioc(
                                clean_domain(adversary), incident, incident_details
                            )
                        )

                self.logger.debug(
                    f"Details for incident {incident.id}: IPs: {len(incident_ips)}. Hosts: {len(incident_hosts)}. URLs: {len(incident_urls)}. Hashes: {len(incident_hashes)}."
                )
                self.ioc["ip"] += incident_ips
                self.ioc["host"] += incident_hosts
                self.ioc["url"] += incident_urls
                self.ioc["hash"] += incident_hashes

            # Remove duplicates
            if remove_duplicates:
                for ioc_type in self.ioc.keys():
                    # Removing duplicates using dict comprehension
                    self.ioc[ioc_type] = list(
                        {v["ioc"]: v for v in self.ioc[ioc_type]}.values()
                    )

            # Update stats
            self.stats.update(
                {
                    "ip": {"collected": len(self.ioc["ip"])},
                    "host": {"collected": len(self.ioc["host"])},
                    "url": {"collected": len(self.ioc["url"])},
                    "hash": {"collected": len(self.ioc["hash"])},
                }
            )

        else:
            self.logger.info("No incidents found!")

    def depurate_urls(
        self,
        url_list: list,
        consolidate_https=False,
        remove_duplicates=True,
        forbidden_chars=[],
    ):
        """
        Helper method to depurate urls returned by Lumu API context endpoint. It depurates the list of urls provided and returns the depurated list.

        Some cybersecurity technologies are not capable of full decrypt traffic. In these cases, the technology will only be capable of
        block the domain, not url with paths

        :param url_list: `list` list of URLs
        :param consolidate_https: `bool` If set to True, the https URLs will be consolidated into one, just schema and domain.
        :param remove_duplicates: `bool` If set to True, removes all duplicated URLs
        :param forbidden_chars: `list` List with forbidden characters. If one of this characters is found in the url, the URL is removed
        """
        # To remove duplicates, we will use a set
        new_url_list = list(set(url_list)) if remove_duplicates else url_list.copy()

        # If we need to consolidate https, let's iterate and select only the required values
        if consolidate_https:
            consolidated_url_list = []
            for url in new_url_list:
                if url.startswith("https://") or url.startswith("http://"):
                    # Get only URL with domain
                    parsed_url = urlparse(url)
                    # Append new url. Schema and domain
                    consolidated_url_list.append(
                        f"{parsed_url.scheme}://{parsed_url.netloc}"
                    )
                else:
                    consolidated_url_list.append(url)

            # Update the new url list
            new_url_list = consolidated_url_list

            # The domain is included inside the url_list. If there are more than 1 url, then, we are going remove the domain
        new_url_list = (
            [url for url in new_url_list if urlparse(url).scheme != ""]
            if len(new_url_list) > 1
            else new_url_list
        )

        # Return new list
        return new_url_list

    def postprocessing(self):
        """
        Method to run postprocessing tasks: persist control variables and other information used for next runs.

        Override this method accordingly
        """

    def clean(self, *args, **kwargs):
        """
        Method to clean all rules and objects created in the third-party tool.

        Override this accordingly
        """
        self.logger.info("Method not implemented")

    def show_stats(self):
        """
        Method to show stats
        """
        for k, v in self.stats.items():
            self.logger.info(
                f"Stats for {k}: Collected: {v.get('collected', 'NA')}. Processed: {v.get('processed', 'NA')}."
            )

        # Shows note or disclaimer related to collected and processed IOC
        self.logger.info(
            "NOTE: Differences between collected and processed IOCs depend on multiple factors, most of them are associated to duplicates and how the third-party solution deals with some cases. "
            "These statistics must be interpreted with care."
        )

    def get_ioc_only(self, hash_type: Literal["sha256", "sha1", "md5"]):
        try:
            self.init_lumu()
            self.incidents = self.collect_incidents()
            self.process_incidents(ioc_types=self.ioc_types, hash_type=hash_type)

            ips = [ioc["ioc"] for ioc in self.ioc["ip"]]
            domains = [ioc["ioc"] for ioc in self.ioc["host"]]
            urls = [ioc["ioc"] for ioc in self.ioc["url"]]
            hashes = [ioc["ioc"] for ioc in self.ioc["hash"]]

            return ips, domains, urls, hashes
        except Exception as e:
            self.logger.error(
                f"{self.get_ioc_only.__qualname__} - Error running integration. {e}"
            )
            raise

    def run(self):
        """
        Method to run the integration.


        """
        # Main logic to run the integration goes here
        self.lock_process(action="create")

        self.logger.info(f"Starting time: {self.start_time}.")

        # Init Third party client
        self.init_thirdparty()

        # If we are cleaning, then just clean
        if self.kwargs["tool"]["clean"]:
            self.logger.info("Running in cleaning mode!")
            self.clean()
        else:
            try:
                # Init Lumu Defender API instace
                self.init_lumu()
                # Collect incidents from Lumu Defender API
                self.incidents = self.collect_incidents()
                # Process incidents based on user input
                self.process_incidents(ioc_types=self.ioc_types)

                # Final processing
                self.postprocessing()

                # Print stats
                self.show_stats()
            except Exception as e:
                self.logger.error(f"Error running integration. {e}")

        self.logger.debug("Releasing lock.")
        self.lock_process(action="destroy")
        self.logger.info(
            f"Process has finished. Elapsed time: {datetime.now() - self.start_time}"
        )
