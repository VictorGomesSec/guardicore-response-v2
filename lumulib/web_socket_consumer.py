import logging
from copy import deepcopy
from time import sleep

from lumudblib.integration_db import CustomLumuDBIntegration
from lumulib.websock import MsgThrottling

_logger = logging.getLogger(__name__)


def process_msgs_throttled(
    company_id: str,
    msg_throttle: MsgThrottling,
    lumu_db_integrations: CustomLumuDBIntegration,
):
    if msg_throttle.is_interval_exceeded() and len(msg_throttle):
        for inc_id, value in deepcopy(msg_throttle.msgs).items():
            inc, incident = value
            lumu_db_integrations.save_inc_ioc(inc, incident)
            _logger.info(
                f"process_msgs_throttled - event save - companyId: {company_id} - Incident:{inc.id} - Adversary: {inc.adversaryId} - Status:{inc.status}"
            )
            msg_throttle.remove_msg(inc_id)
        len_pendings = len(msg_throttle.msgs)
        _logger.info(f"process_msgs_throttled - {len_pendings} messages still pending")
        if len_pendings == 0:
            msg_throttle.begin(force=True)

    return


def messages_throttled_consumer(
    company_id: str,
    pendings: MsgThrottling,
    lumu_db_integrations: CustomLumuDBIntegration,
    delay=60,
):
    while True:
        sleep(delay)

        process_msgs_throttled(company_id, pendings, lumu_db_integrations)
