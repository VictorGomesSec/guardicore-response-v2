# Copyright Lumu Technologies
"""
Lumu Custom Collector logic
"""

from __future__ import absolute_import

import logging
import sys

# Import for date parsing
from datetime import datetime

import requests
from requests.exceptions import HTTPError
from six import iteritems
from six.moves import collections_abc as collections
from six.moves import urllib

from .constants.collector import (
    BASE_URL,
    PATH_DNS_PACKETS,
    PATH_DNS_QUERIES,
    PATH_PROXY_ENTRIES,
    PATH_FIREWALL_ENTRIES,
    ENTRY_TYPES,
    BODY_MAX_SIZE,
    BODY_MAX_ITEMS,
    PATH_POST_ENTRY_TYPES,
    ENTRY_TYPES_INPUT_SCHEMAS,
    FIELD_TYPES,
)
from .constants.globals import DATE_FORMAT, NULL_STRINGS
from .exceptions import NotSupportedEntryTypeException, DeserializationException

# Logger
logger = logging.getLogger("LumuCollectionSDK")


# Added function to update without replacing dicts
def _update_dict(d, u):
    """
    Helper to update, not replace, dict values
    :param d: Original dict
    :param u: Part to be updated
    :return: Updated dict
    """
    # Going through u
    for k, v in iteritems(u):
        if isinstance(v, collections.Mapping):
            d[k] = _update_dict(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def connect(**kwargs):
    """
    Helper to get a LumuCustomCollector instance

    :return: `LumuCustomCollector` Instance of LumuCustomCollector
    """
    s = LumuCustomCollector(**kwargs)
    return s


def transform(key, data):
    """
    Helper function to transform data based on datatype required for Lumu

    The supported datatypes for each entry key are the one documented on Custom Collector API Specifications
    [https://docs.lumu.io/portal/en/kb/articles/cc-api-specifications]

    :param key: `str` The key for parameter
    :param data: `object` The data to be transformed
    :return: Data transformed to the specific type in the FIELD_TYPES dict
    """
    target_type = FIELD_TYPES[key]
    if target_type == "integer":
        # Data conversion for integer type
        try:
            return int(data)
        except TypeError:
            # logging.debug('Error transforming data {} to type {}. Returning default for type'.format(data, target_type))
            return 0
    elif target_type == "boolean":
        # Data conversion for boolean type. TODO: Check if transformation done by request module handles False -> false conversion
        try:
            return True if data.lower() == "true" else False
        except TypeError:
            # logging.debug('Error transforming data {} to type {}. Returning default for type'.format(data, target_type))
            return False
    elif target_type == "date-time":
        # Data conversion for date-time. Supported format is %Y-%m-%dT%H:%M:%S.%fZ
        # Currently, support input from epoch
        # First, try transform to float
        try:
            dt_f = float(data)
        except TypeError:
            # logging.debug('Error transforming data {} to type {}. Returning default for type'.format(data, target_type))
            dt_f = 0
        # Transform timestamp to datetime
        dt = datetime.utcfromtimestamp(dt_f)
        # Return parsed date
        return dt.strftime(DATE_FORMAT)
    elif target_type == "string":
        # If the type if string, we also check if the value matches with the strings in NULL_STRINGS
        try:
            if data.lower() in NULL_STRINGS:
                return str("")
            return str(data)
        except Exception:
            return str("")
    else:
        return data


def rec_split(key, value, original_key):
    """
    Helper to split recurrently a particular entry

    Example:
        Turn this {'request.uri.host': 'test'.com'}
        into this:
            {'request': {'uri': {'host': 'test.com'}}}
    :param key:``string`` The key to be splitted. This is dynamically calculated based on the recurrence
    :param value:``string`` Value of the original entry
    :param original_key:``string`` Original key. Required for data transformation with tranform function
    :return:``dict`` Dictionary with the treated entry
    """
    aux = key.split(".")
    if len(aux) == 1:
        return {aux[0]: transform(original_key, value)}
    else:
        return {aux[0]: rec_split(".".join(aux[1:]), value, original_key)}


def parse_entries(
    entries,
    type="firewall",
):
    """
    Helper to "parse" entries according to the defined schema

    The supported input format is the one documented on Custom Collector API Specifications [https://docs.lumu.io/portal/en/kb/articles/cc-api-specifications]

    :param entries: `list` List of dics with the entry
    :param type: `str` The type of entry: firewall, dns-query, dns-packets, proxy
    :returns: `list` List of dict with entries parsed
    """
    # Check if the type on entry is supported by the method
    if type not in ENTRY_TYPES:
        # If the required type is not supported return False
        return False

    # Continue parsing based on ENTRY_TYPES_INPUT_SCHEMA
    _entries = []
    for entry in entries:
        # Temporal entry to build parsed one
        _entry = {}
        for key in ENTRY_TYPES_INPUT_SCHEMAS[type]:
            # Use recurrent splitting for handling situations with a composed key
            # i.e. request.uri.host, destinatio.ip
            _update_dict(
                _entry,
                (rec_split(key=key, value=entry.get(key, None), original_key=key)),
            )

        # Adding parsed entry to _entries
        _entries.append(_entry)

    return _entries


def _divide_chunks(lst, n):
    """
    Internal helper to split body for post requests larget than BODY_MAX_SIZE
    :param lst: List to be chunked
    :param n: Chunk size
    :return: List of chunks
    """
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


class LumuCustomCollector:
    def __init__(self, client_key, collector_id):
        self.client_key = client_key
        self.collector_id = collector_id
        self.http = requests.Session()

    def post(self, path, body):
        url = urllib.parse.urljoin(BASE_URL, path)

        try:
            # Implement body size validation
            body_size = sys.getsizeof(str(body))
            logger.debug("Body size = {}".format(body_size))
            if body_size > BODY_MAX_SIZE or len(body) > BODY_MAX_ITEMS:
                # Must divide the body and run multiple posts
                # Calculate estimated ratio
                logger.debug(
                    "Body size is greater than maximum allowed. Starting to chunk"
                )
                chunk_size = BODY_MAX_ITEMS
                logger.debug("Calculated chunk size: {}".format(chunk_size))
                chunked_body = list(_divide_chunks(body, chunk_size))
                # Time to send chunks
                for chunk in chunked_body:
                    logger.debug("Posting chunk")
                    self.post(path, chunk)
            else:
                r = self.http.post(url, json=body)
                r.raise_for_status()

            # If there is no errors return true
            return True
        except HTTPError as e:
            logger.error("Cannot post entries.")
            if e.response.status_code == 400:
                # Error in query
                raise DeserializationException(
                    f"{r.json()['name']} - {r.json()['detail']}"
                )
            raise

    def post_fw_entries(self, fw_entries):
        """
        Post Firewall Entries to Lumu Custom Collector
        :param fw_entries: List of dicts with firewall entries
        :return: Boolean indicating the result
        """
        return self.post(
            PATH_FIREWALL_ENTRIES.format(
                collector_id=self.collector_id, client_key=self.client_key
            ),
            fw_entries,
        )

    def post_proxy_entries(self, proxy_entries):
        """
        Post Proxy Entries to Lumu Custom Collector
        :param proxy_entries: List of dicts with proxy entries
        :return: Boolean indicating the result
        """
        return self.post(
            PATH_PROXY_ENTRIES.format(
                collector_id=self.collector_id, client_key=self.client_key
            ),
            proxy_entries,
        )

    def post_dns_packets(self, dns_packets):
        """
        Post DNS packets to lumu Custom Collector
        :param dns_packets: List of dicts with DNS packets
        :return: Boolean indicating the result
        """
        return self.post(
            PATH_DNS_PACKETS.format(
                collector_id=self.collector_id, client_key=self.client_key
            ),
            dns_packets,
        )

    def post_dns_queries(self, dns_queries):
        """
        Post DNS queries to lumu Custom Collector
        :param dns_queries: List of dicts with DNS packets
        :return: Boolean indicating the result
        """
        return self.post(
            PATH_DNS_QUERIES.format(
                collector_id=self.collector_id, client_key=self.client_key
            ),
            dns_queries,
        )

    def post_entries(self, entries, type="firewall"):
        """
        Post entries based on tyoe
        :param entries: List of dicts with entries to post
        :param type: string indicating type of entries. Supported types are firewall, proxy, dns-query, dns-entry
        :return: Boolean indicating the result
        """
        # Check type
        if type not in ENTRY_TYPES:
            raise NotSupportedEntryTypeException("Entry type not supported")

        return self.post(
            PATH_POST_ENTRY_TYPES[type].format(
                collector_id=self.collector_id, client_key=self.client_key
            ),
            entries,
        )
