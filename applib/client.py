import json
import sys
from datetime import datetime, timezone
from http import HTTPStatus
from json import JSONDecodeError

import jwt
import requests
import urllib3
from loguru import logger as _logger
from requests import Session
from requests.adapters import HTTPAdapter
from sqlalchemy.sql.annotation import Annotated
from urllib3 import Retry

from applib.schemas.app import (
    ClientConfig,
    AuthConfig,
    ListPolicyRuleResponse,
    GetPolicyRuleResponse,
)
from applib.utils.client import (
    rule_modification_template,
    publish_policy_revision_template,
)


urllib3.disable_warnings()


class Auth:
    def __init__(self, config: AuthConfig):
        self._username = config.username
        self._password = config.password
        self._base_authentication_url = (
            str(config.base_authentication_url).strip("/") + "/"
        )
        self._authentication_path: str = config.authentication_path.strip("/")
        self._header_key = config.header_key
        self._header_value_prefix = config.header_value_prefix
        self._verify_ssl = config.verify_ssl
        self.__token = None
        self.__expired_date = None

        self.requests_timeout = config.requests_timeout
        self.integration_uuid = config.integration_uuid

        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        self._logger = _logger

    def ensure_authentication(self) -> bool:
        if (
            self.__token
            and self.__expired_date
            and datetime.now(timezone.utc) < self.__expired_date
        ):
            return True
        else:
            return self._obtain_token()

    def get_authentication_data(self) -> dict:
        return {
            self._header_key: f"{self._header_value_prefix.strip()} {self.__token}".strip()
        }

    def _obtain_token(self) -> bool:
        try:
            data = json.dumps({"username": self._username, "password": self._password})
            response = requests.post(
                url=self._base_authentication_url + self._authentication_path,
                data=data,
                headers=self._headers,
                timeout=self.requests_timeout,
                verify=self._verify_ssl,
            )
            try:
                rjson = response.json()
            except JSONDecodeError:
                rjson = {}

            status_code = response.status_code

            if status_code == HTTPStatus.OK and (token := rjson.get("access_token")):
                header = jwt.get_unverified_header(token)
                alg = header["alg"]
                payload = jwt.decode(
                    token,
                    key=None,
                    algorithms=[].extend(alg),
                    options={"verify_signature": False},
                )
                expired_date = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                self.__token = token
                self.__expired_date = expired_date
                return True

            self.__token = None
            self.__expired_date = None

            text = response.text.replace("\n", "").replace("\r", " ")
            if status_code in [
                HTTPStatus.UNAUTHORIZED,
                HTTPStatus.BAD_REQUEST,
                HTTPStatus.FORBIDDEN,
            ]:
                self._logger.warning(
                    f"Integration {self.integration_uuid} - Could not obtain token {status_code}:{text}"
                )
                return False
            else:
                self._logger.error(
                    f"Integration {self.integration_uuid} - Could not obtain token {status_code}:{text}"
                )
                return False

        except Exception as e:
            self._logger.error(
                f"Integration: {self.integration_uuid} - Something went wrong trying to obtain token = {e}"
            )
            return False


class Client:
    def __init__(self, config: ClientConfig, auth: Auth) -> None:
        self.base_url = str(config.base_url).rstrip("/") + "/"
        self._policy_rule_path = config.policy_rule_path
        self._policy_revision_path = config.policy_revision_path
        self.integration_uuid = config.integration_uuid
        self.requests_timeout = config.requests_timeout
        self.__auth = auth

        retry_strategy = Retry(
            total=3,
            backoff_factor=20,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        self.__http_adapter = HTTPAdapter(max_retries=retry_strategy)

        self.session = Session()
        self.session.verify = config.verify_ssl
        self.session.mount("https://", self.__http_adapter)
        self.session.headers = {"Accept": "application/json"}

        self._logger = _logger

    def refresh_session(self) -> None:
        self.session = Session()
        self.session.mount("https://", self.__http_adapter)
        self.session.headers = {"Accept": "application/json"}

    def client_is_ok(self) -> bool:
        return self.__auth.ensure_authentication()

    def _make_request(
        self,
        url_path: str,
        method: str,
        accepted_status_codes: list[int],
        data: str | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        action: str = "Default",
    ) -> requests.Response:
        if self.__auth.ensure_authentication():
            try:
                self.session.headers.update(self.__auth.get_authentication_data())
                response = self.session.request(
                    method=method,
                    url=self.base_url + url_path.lstrip("/"),
                    headers=headers,
                    data=data,
                    params=params,
                    timeout=self.requests_timeout,
                )

                status_code = response.status_code

                if status_code in accepted_status_codes:
                    return response

                text = response.text.replace("\n", " ").replace("\r", " ")

                if status_code in [HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN]:
                    self._logger.warning(
                        f"Integration: {self.integration_uuid} - Could not perform {action}. "
                        f"{status_code}:{text}"
                    )
                    response.raise_for_status()
                else:
                    self._logger.error(
                        f"Integration: {self.integration_uuid} - Could not perform {action}. "
                        f"{status_code}:{text}"
                    )
                    response.raise_for_status()

            except Exception as e:
                self._logger.critical(
                    f"Integration: {self.integration_uuid} - Something went wrong trying to {action} - {e}"
                )
                sys.exit(1)
        else:
            self._logger.critical(
                f"Integration: {self.integration_uuid} - Authentication failed."
            )
            sys.exit(1)

    def _list_policy_rules(self, params: dict | None = None):
        url_path = self._policy_rule_path

        payload = None
        headers = {"Content-Type": "application/json"}

        response = self._make_request(
            url_path,
            "GET",
            [HTTPStatus.OK],
            payload,
            params,
            headers=headers,
            action="list_policy_rules",
        )

        return response

    def filter_policy_rule(
        self,
        ruleset: str,
        fields: str = "ruleset_name,id",
        start_at: Annotated[int, "default 0"] = 0,
        max_results: Annotated[int, "default 1024"] = 1024,
    ):
        params = {
            "ruleset": ruleset,
            "fields": fields,
            "start_at": start_at,
            "max_results": max_results,
        }

        response = self._list_policy_rules(params)

        return ListPolicyRuleResponse.model_validate(response.json())

    def _get_a_policy_rule(self, rule_id: str, params: dict | None = None):
        url_path = self._policy_rule_path.rstrip("/") + f"/{rule_id}"

        payload = None
        headers = {"Content-Type": "application/json"}

        response = self._make_request(
            url_path,
            "GET",
            [HTTPStatus.OK],
            payload,
            params,
            headers=headers,
            action="get_a_policy_rule",
        )

        return response

    def get_policy_rule(self, rule_id: str, fields: str | None = None):
        """
        fields: comma separated string:
        comments, exclude_ports, attributes, author, ruleset_name,
        source, enabled, hit_count, icmp_matches, last_hit, section_position, destination, scope,
        port_ranges, last_change_time, id, state, action, network_profile,
        read_only, ip_protocols, hit_count_reset_time, ports, creation_time, exclude_port_ranges
        """
        params = None
        if fields:
            params = {"fields": fields}

        response = self._get_a_policy_rule(rule_id, params)

        return GetPolicyRuleResponse.model_validate(response.json())

    def _edit_a_policy_rule(self, rule_id: str, body: dict):
        url_path = self._policy_rule_path.rstrip("/") + f"/{rule_id}"

        params = None
        payload = json.dumps(body)
        headers = {"Content-Type": "application/json"}

        response = self._make_request(
            url_path,
            "PUT",
            [HTTPStatus.OK],
            payload,
            params,
            headers=headers,
            action="edit_a_policy_rule",
        )

        return response

    def edit_policy_rule(self, rule_id: str, indicators: list[str]):
        response = self.get_policy_rule(rule_id)
        rule = response.objects[0]
        body = rule_modification_template(rule, indicators)
        return self._edit_a_policy_rule(rule_id, body)

    def publish_segmentation_policy_changes(self, ruleset_name: str, comments: str):
        url_path = self._policy_revision_path.rstrip("/")
        body = publish_policy_revision_template(ruleset_name, comments)

        params = None
        payload = json.dumps(body)

        headers = {"Content-Type": "application/json"}

        response = self._make_request(
            url_path,
            "POST",
            [HTTPStatus.OK, HTTPStatus.BAD_REQUEST],
            payload,
            params,
            headers=headers,
            action="publish_segmentation_policy_changes",
        )

        return response
