# Constants used by the Lumu library

## Global constants
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
NULL_STRINGS = ["-", "null"]
DEFAULT_TIMEOUT = 30

## Integration constants
# Details to be included in the IOC loaded per incident
INCIDENT_DETAILS = [
    "id",
    "timestamp",
    "statusTimestamp",
    "status",
    "contacts",
    "adversaries",
    "adversaryId",
    "adversaryTypes",
    "description",
    "labelDistribution",
    "totalEndpoints",
    "lastContact",
    "unread",
    "hasPlaybackContacts",
    "firstContact",
]
