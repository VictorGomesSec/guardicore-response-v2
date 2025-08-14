# Copyright Lumu Technologies
"""Utility module shared by the SDK examples & unit tests."""

from __future__ import absolute_import

import logging
import os
from logging.handlers import RotatingFileHandler

import psutil

# Validators
from validators import ip_address as ip_validator, domain as domain_validator

try:
    from validators import ValidationFailure
except ImportError:
    from validators import ValidationError as ValidationFailure
from urllib.parse import urlparse
import re

from utils.cmdopts import *
from six import iteritems

# Default cmdline rules
# Common rules for both Defender and Custom Collector API
RULES_COMMON = {
    "config": {
        "flags": ["--config"],
        "action": ConfigAction,
        "nargs": 1,
        "help": "Load options from config file",
    },
    "proxy_host": {
        "flags": ["--proxy-host", "--proxy_host"],
        "required": False,
        "help": "Proxy host (if required)",
    },
    "proxy_port": {
        "flags": ["--proxy-port", "--proxy_port"],
        "required": False,
        "help": "Proxy port (if required)",
    },
    "proxy_user": {
        "flags": ["--proxy-user", "--proxy_user"],
        "required": False,
        "help": "Proxy user (if required)",
    },
    "proxy_password": {
        "flags": ["--proxy-password", "--proxy_password"],
        "required": False,
        "help": "Proxy password (if required)",
    },
}

# Specific rules for Defender API cmdline
RULES_DEFENDER = {
    "company_key": {
        "flags": ["--company-key", "--company_key"],
        "required": True,
        "help": "Lumu Company Key (Defender API).",
    }
}

# Specific rules for Defender API cmdline
RULES_COLLECTION = {
    "client_key": {
        "flags": ["--client-key", "--client_key"],
        "required": True,
        "help": "Lumu Client Key (Custom Collector API key).",
    },
    "collector_id": {
        "flags": ["--collector-id", "--collector_id"],
        "required": True,
        "help": "Lumu Custom Collector ID.",
    },
}

# Complete dictionary for "dslicing" keys
ALL_RULES = {**RULES_COMMON, **RULES_DEFENDER, **RULES_COLLECTION}

FLAGS_LUMU = list(ALL_RULES.keys())


# value: dict, args: [(dict | list | str)*]
def dslice(value, *args):
    """Returns a 'slice' of the given dictionary value containing only the
    requested keys. The keys can be requested in a variety of ways, as an
    arg list of keys, as a list of keys, or as a dict whose key(s) represent
    the source keys and whose corresponding values represent the resulting
    key(s) (enabling key rename), or any combination of the above."""
    result = {}
    for arg in args:
        if isinstance(arg, dict):
            for k, v in iteritems(arg):
                if k in value:
                    result[k] = value[k]
        elif isinstance(arg, list):
            for k in arg:
                if k in value:
                    result[k] = value[k]
        else:
            if arg in value:
                result[arg] = value[arg]
    return result


def parse(argv, rules=None, config=None, api="defender", **kwargs):
    """Parse the given arg vector with the default Lumu command rules."""
    parser_ = parser(rules, api, **kwargs)
    # Pass argv to loadrc to avoid parser errors for command line required arguments
    if config is not None:
        parser_.loadrc(config)
    # Adding loaded items from config to argv array. This is required to avoid error for loading config plus cmd args
    args = parser_.kwargs_as_list()
    args.extend(argv)
    return parser_.parse(args).result


def parser(rules=None, api="defender", **kwargs):
    """
    Instantiate a parser with the default Lumu command rules.
    It has into account the `api` parameter.
    """
    base_rules = RULES_COMMON.copy()
    base_rules = (
        dict(base_rules, **RULES_DEFENDER)
        if api == "defender"
        else dict(base_rules, **RULES_COLLECTION)
    )

    rules = base_rules if rules is None else dict(base_rules, **rules)
    return Parser(rules, **kwargs)


# Added function for support across Python versions
def merge_dicts(*dicts):
    """Merge multiple dicts into one"""
    result = {}
    for dictionary in dicts:
        result.update(dictionary)
    return result


def init_logging(logging_type="screen", file=None, verbose=0, maxBytes=1024 * 1024 * 5):
    """Initialize logging type"""
    level = logging.DEBUG if verbose else logging.INFO
    format = "%(asctime)s - %(name)s - [%(thread)d]:[%(levelname)s] - %(message)s"
    datefmt = "%d-%m-%Y %H:%M:%S"
    err_handler = RotatingFileHandler("errors.log", maxBytes=maxBytes, backupCount=5)
    err_handler.setLevel(logging.ERROR)
    err_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(filename)s->%(funcName)s->%(lineno)d - %(name)s - [%(thread)d]:[%(levelname)s] - %(message)s"
        )
    )

    if logging_type == "screen":
        logging.basicConfig(
            level=level,
            format=format,
            datefmt=datefmt,
            handlers=[logging.StreamHandler(), err_handler],
        )
    else:
        logging.basicConfig(
            level=level,
            format=format,
            datefmt=datefmt,
            handlers=[
                RotatingFileHandler(filename=file, maxBytes=maxBytes, backupCount=5),
                err_handler,
            ],
        )


def check_pid_lock(filename):
    """Check pid lock based on file existence"""
    if os.path.exists(filename):
        # If file exists, check if the process exists
        try:
            with open(filename, "r") as file:
                pid = int(file.read())
        except Exception as e:
            logging.error("Cannot read process file.")
            # If we cannot read file, return False (the process does not exist)
            return False

        # Check if the pid is found in the system
        try:
            proc = psutil.Process(pid)
            return True
        except Exception as e:
            # If there is an exception querying the process, then it does not exist
            return False

    return False


def create_pid_lock(filename):
    """Created pid lock file"""
    with open(filename, "w") as f:
        f.write(str(os.getpid()))


def release_pid_lock(filename):
    """Created pid lock file"""
    if os.path.exists(filename):
        # If file exists. Then return True
        os.remove(filename)
        return True

    return False


def get_ioc_type(value):
    """
    Returns IOC type based on the value. Useful for getting type based on Lumu adversary host.

    :param value: {str} Name of the host/adversary/ioc
    :return: ip or domain
    """
    # Check value with validators
    if not isinstance(ip_validator.ipv4(value), ValidationFailure) or not isinstance(
        ip_validator.ipv6(value), ValidationFailure
    ):
        return "ip"
    elif not isinstance(domain_validator(value), ValidationFailure):
        return "domain"
    else:
        # No match with known IOC type
        return False


def clean_domain(value):
    """
    Cleans domain ending points
    """
    return value if not value.endswith(".") else value[:-1]


def filter_urls(urls: list):
    """
    Method to filter URLs with bad character according to Forcepoint validations

    :param urls: `list` List of URLs to check
    """
    # Here, we validate if the URLs complies with the following rules:
    # - netloc with % and @ must have a valid "domain" before the character. If not, the URL is discarded.
    #   Have in mind that in this case, the URL will be uploaded but Forcepoint will truncate it one character before % or @
    # - Special caracters are valid in path and param in the URL
    DOMAIN_REX = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]+$"
    chars_to_validate = ["%", "@"]
    filtered_urls = []
    # Iterate over the list, parse the url and check the netloc construction
    for url in urls:
        url_tmp = urlparse(url)
        netloc = url_tmp.netloc
        if netloc:
            if "%" in netloc:
                domain = netloc.split("%")[0]
                if re.match(DOMAIN_REX, domain):
                    # Append URL to list
                    filtered_urls.append(url)
            elif "@" in netloc:
                domain = netloc.split("@")[0]
                if re.match(DOMAIN_REX, domain):
                    # Append URL to list
                    filtered_urls.append(url)
            else:
                # Not special characters detected. Append
                filtered_urls.append(url)

    return filtered_urls


def strip_scheme(url: str):
    """
    Strip scheme from url
    :param url: `str` URL to strip scheme from
    :returm: `str` URL without scheme
    """
    return "".join([*urlparse(url)[1:]])


def chunks(lst: list, n: int):
    """
    Generator of evenly-sized chunks

    :param lst: `list` List to be "chunked"
    :param n: `int` Chunk size
    :return: Yields of lists of size n
    """
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
