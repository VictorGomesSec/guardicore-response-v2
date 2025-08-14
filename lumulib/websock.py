from datetime import datetime
import json
import logging
import time
from threading import Thread, RLock

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc

import websocket
from benedict import benedict

from lumudblib.integration_db import CustomLumuDBIntegration

LOG_FILE = "lumu.log"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_PATH = "."

logger = logging.getLogger(__name__)

drop_msg_types = [
    "IncidentMarkedAsRead",
    "OpenIncidentsStatusUpdated",
    "IncidentIntegrationsResponseUpdated",
    "IncidentCommentAdded",
]

context_msg_type = ["NewIncidentCreated", "IncidentUpdated"]
new_created_msg_type = ["NewIncidentCreated"]
updated_msg_type = ["IncidentUpdated"]
status_msg_type = ["IncidentClosed", "IncidentMuted", "IncidentUnmuted"]


class MsgThrottling:
    def __init__(self, r_lock: RLock, interval=60):
        self.__begin: time = None
        self.__msgs = {}
        self.__interval = interval
        self._r_lock = r_lock

    def begin(self, force: bool = False):
        if force or not self.__begin:
            self.__begin = time.perf_counter()
        return self

    def is_interval_exceeded(self):
        if not self.__begin:
            return False
        return (
            True if ((time.perf_counter() - self.__begin) > self.__interval) else False
        )

    def add_msg(self, _id, msg: object, msg_dict: dict):
        with self._r_lock:
            self.__msgs[_id] = (msg, msg_dict)

    def remove_msg(self, _id):
        with self._r_lock:
            self.__msgs.pop(str(_id))

    @property
    def msgs(self):
        return self.__msgs

    def __len__(self):
        return len(self.__msgs.keys())

    def reset(self):
        with self._r_lock:
            self.__begin: time = None
            self.__msgs = {}


class WebSocketLumu:
    def __init__(
        self,
        company_key,
        ioc_inc_inc_integration: CustomLumuDBIntegration,
        msgs_throttle: MsgThrottling,
        ws_uri="wss://defender.lumu.io/api/incidents/subscribe",
        companyId=None,
    ):
        try:
            self.companyId = companyId
            logger.info(f"companyId: {self.companyId} - {__name__}")
            self.ioc_inc_inc_integration = ioc_inc_inc_integration
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
            self.error_str = ""
            self.msgs_throttle = msgs_throttle

        except websocket.WebSocketException as e:
            logger.error(
                f"companyId: {self.companyId} - {self.__init__.__qualname__} - {repr(e)}"
            )
            self.ws.close()
            raise e

    def on_open(self, ws: websocket.WebSocketApp):
        try:
            ws.send("Hello")
            logger.info(f"on_open - companyId: {self.companyId} - WebSocket Open")
        except Exception as e:
            logger.error(
                f"on_open - companyId: {self.companyId} - WebSocket Open Error {repr(e)}"
            )

    def on_message(self, ws, msg):
        self.event_processor(msg)

    def on_ping(self, ws, msg):
        logger.info(f"on_ping - companyId: {self.companyId} - WebSocket Ping")

    def on_pong(self, ws, msg):
        logger.debug(
            f"on_pong - companyId: {self.companyId} - WebSocket OnPong - {msg.decode()}"
        )

    def on_error(self, ws, err):
        logger.error(
            f"companyId:{self.companyId} - {self.on_error.__qualname__} - WebSocket Error - {repr(err)}"
        )
        self.error_str = f"{datetime.now(UTC)}-{repr(err)}."

    def on_close(self, ws, close_status_code, close_msg):
        logger.error(
            f"companyId: {self.companyId} - {self.on_close.__qualname__} - WebSocket Close, {self.error_str}"
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
            logger.info(
                f"companyId: {self.companyId} - {self.run_ws.__qualname__}, Result: {result}"
            )
            return result
        except websocket.WebSocketException as e:
            logger.error(
                f"companyId: {self.companyId} - {self.run_ws.__qualname__} - {repr(e)})"
            )
            self.ws.close()
            raise e

    def event_processor(self, msg: str):
        message_json = json.loads(msg)
        message_type = list(message_json.keys())[0]

        if message_type in drop_msg_types:
            logger.info(f"companyId: {self.companyId} - ignoring event: {message_type}")
            return

        if not (incident := message_json[message_type].get("incident", {})):
            logger.info(
                f"companyId: {self.companyId} - ignoring event: No field incident"
            )
            return

        inc = benedict(incident)

        self.ioc_inc_inc_integration.save_incident(inc)

        if message_type in new_created_msg_type:
            self.ioc_inc_inc_integration.save_inc_ioc(inc, incident)
            logger.info(
                f"companyId: {self.companyId} - event save: {message_type} - Adversary: {inc.adversaryId} - Status:{inc.status}"
            )
            return

        if message_type in updated_msg_type:
            self.msgs_throttle.add_msg(_id=inc.id, msg=inc, msg_dict=incident)
            return
