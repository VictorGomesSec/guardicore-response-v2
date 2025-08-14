import datetime
import logging
from queue import Queue
from typing import Callable, AnyStr
from uuid import UUID

import websocket

from lumulib.itsm_utils.lumu_client import LumuClient, status_msg_update_type

_logger = logging.getLogger(__name__)

CompanyUUIDStr = IncidentIdStr = UUID | AnyStr
ThrottleInt = int
IncidentTypesLst = list[str] | None
CommentStr = MsgTypeType = AnyStr
MsgObjType = dict
ProducerType = Callable[
    [
        Queue,
        Queue,
        CompanyUUIDStr,
        ThrottleInt,
        IncidentTypesLst,
        IncidentIdStr,
        MsgTypeType,
        MsgObjType,
        CommentStr,
    ],
    None,
]


class WebSocketLumuBoosted:
    def __init__(
        self,
        company_key,
        q: Queue,
        q_updates: Queue,
        lumu_client: LumuClient,
        producer: ProducerType,
        companyId=None,
        include_muted_updates=False,
        throttle: ThrottleInt = 1,
        incident_types: IncidentTypesLst = None,
        ws_uri="wss://defender.lumu.io/api/incidents/subscribe",
    ):
        if not isinstance(companyId, UUID):
            try:
                companyId = UUID(companyId)
            except ValueError as e:
                raise ValueError(f"Invalid companyId UUID format - {repr(e)}")

        try:
            self.incident_types = (
                list(
                    {
                        "C2C",
                        "Malware",
                        "DGA",
                        "Mining",
                        "Spam",
                        "Phishing",
                        "Network Scan",
                        "Anonymizer",
                    }.intersection(incident_types)
                )
                if incident_types
                else []
            )

            self.include_muted_updates = include_muted_updates
            self.throttle = throttle
            self.companyId = companyId
            _logger.info(f"companyId: {self.companyId} - {__name__}")

            url = ws_uri + f"?key={company_key}"
            self.ws = websocket.WebSocketApp(
                url,
                on_open=self.on_open,
                on_message=self.on_message,
                on_ping=self.on_ping,
                on_pong=self.on_pong,
                on_error=self.on_error,
                on_close=self.on_close,
            )

            self._company_key = company_key
            self.lumu_client = lumu_client
            self.producer = producer
            self.error_str = ""

        except websocket.WebSocketException as e:
            _logger.error(
                f"companyId: {self.companyId} - WebSocketLumuBoosted - {repr(e)}"
            )
            self.ws.close()
            raise e
        self.q = q
        self.q_updates = q_updates

    def on_open(self, ws: websocket.WebSocketApp):
        try:
            ws.send("Hello")
            _logger.info(f"on_open - companyId: {self.companyId} - WebSocket Open")
        except Exception as e:
            _logger.error(
                f"on_open - companyId: {self.companyId} WebSocket Open Error {repr(e)}"
            )

    def on_message(self, ws, msg):
        _logger.debug(f"on_message - Raw Event: {msg}")
        if not (results := self.event_processor(msg)):
            return
        self.producer(
            self.q,
            self.q_updates,
            self.companyId,
            self.throttle,
            self.incident_types,
            *results,
        )

    def on_ping(self, ws, msg):
        _logger.debug(f"on_ping - companyId: {self.companyId}")

    def on_pong(self, ws, msg):
        _logger.debug(
            f"on_pong - companyId: {self.companyId} - WebSocket OnPong, {msg.decode()}"
        )

    def on_error(self, ws, err):
        _logger.error(
            f"on_error - company: {self.companyId} -  WebSocket Error, {repr(err)}"
        )
        self.error_str = f"{datetime.datetime.now(datetime.UTC)}-{repr(err)}."

    def on_close(self, ws, close_status_code, close_msg):
        _logger.error(
            f"on_close - company: {self.companyId} - WebSocket Close, {self.error_str}"
        )
        # sys.exit(repr(err))
        if self.error_str:
            raise ValueError(self.error_str)

    def run_ws(self, ping_interval=20, ping_timeout=10, ping_payload="heartbeat text"):
        try:
            result = self.ws.run_forever(
                ping_interval=ping_interval,
                ping_timeout=ping_timeout,
                ping_payload=ping_payload,
            )
            _logger.info(f"run_ws - companyId: {self.companyId=} - Result: {result}")
            return result
        except websocket.WebSocketException as e:
            _logger.error(f"run_ws - companyId: {self.companyId} - {repr(e)}")
            self.ws.close()
            raise e

    def event_processor(self, msg: str):
        msg_type, inc_msg = self.lumu_client.filter_msg_type(msg)
        if not inc_msg:
            return
        if self.filter_muted_updates(msg_type, inc_msg):
            return

        incident_id, msg_type, comment, inc_msg = self.lumu_client.format_input_msg(
            msg_type, inc_msg
        )

        # W recommend fill out the message in producer o consumer, depend your needs
        # if msg_type in status_msg_create_type:
        #     inc_msg: dict = self.lumu_client.msg_fill_in(inc_msg)

        return incident_id, msg_type, inc_msg, comment

    def filter_muted_updates(self, msg_type, inc_msg):
        if (
            not self.include_muted_updates
            and msg_type == status_msg_update_type
            and inc_msg.get("incident", {}).get("status", "") == "muted"
        ):
            _logger.debug(
                f"filter_muted_updates - Message will be discarded. It belongs to a muted incident. Ignore muted updates is {self.include_muted_updates}"
            )
            return True
        return False
