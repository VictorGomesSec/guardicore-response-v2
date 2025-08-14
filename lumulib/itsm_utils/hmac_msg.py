import hashlib
import hmac

import logging
from typing import Literal

_logger = logging.getLogger(__name__)

message_types = [
    "NewIncidentCreated",
    "IncidentUpdated",
    "IncidentMuted",
    "IncidentUnmuted",
    "IncidentClosed",
    "IncidentMarkedAsRead",
    "OpenIncidentsStatusUpdated",
    "IncidentCommentAdded",
]

drop_msg_types = [
    "IncidentMarkedAsRead",
    "OpenIncidentsStatusUpdated",
    "IncidentIntegrationsResponseUpdated",
]

create_msg_type = "NewIncidentCreated"
update_msg_type = "IncidentUpdated"

comment_sep = "msgId:"


def get_hmac_alg(key: str, comment: str, alg: Literal["sha256", "sha1", "md5"] = "md5"):
    return hmac.new(key.encode(), comment.encode(), getattr(hashlib, alg)).hexdigest()


def generate_hmac_alg_msg(key: str, comment: str):
    hmac_code = get_hmac_alg(key, comment)
    return f"{comment} {comment_sep}{hmac_code}"


def validate_hmac_alg(key: str, comment_w_hmac: str, separator=comment_sep):
    """

    :param key:
    :param comment_w_hmac: Resolved, from: ServiceNow Thu Nov 10 2022 07:56:13 GMT-0800 (PST),
    close_code: Solution provided, close_notes: ddddddddddddd hmacsha256:
    a9d7947047c371a10a44d07b381152951c46b0c954f8ddf1eeefc29fd120b8ae
    :param separator:
    :return:
    """
    result = [piece.strip() for piece in comment_w_hmac.split(separator)]
    if len(result) != 2:
        return False
    comment, hash_mac = result
    _logger.debug(f"validate_hmac_alg - comment: {comment}, {hash_mac}")
    if get_hmac_alg(key, comment) == hash_mac:
        _logger.info(
            f"validate_hmac_alg - validating hmac is True - comment: {comment}, {hash_mac}"
        )
        return True
    return False


def is_msg_from_third_party(key, comment):
    """
    validate if comment was signed with the same key and belong from the app
    :param key:
    :param comment:
    :return:
    """
    if comment and validate_hmac_alg(key=key, comment_w_hmac=comment):
        return True
    return False
