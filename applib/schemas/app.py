from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel
from pydantic import HttpUrl

from applib.schemas.config import CompanyModel


class RuleName(StrEnum):
    lumu = "Lumu IOCs"


class CanaryIndicator(StrEnum):
    canary = "canary.lumu.net"
    canary_ip = "3.89.191.115"


class ListPolicyRuleResponse(BaseModel):
    fields: str
    filter: Any
    objects: list[dict]
    order: str
    order_direction: str
    start_at: int
    total: int


class GetPolicyRuleResponse(BaseModel):
    fields: str
    objects: list[dict]


class AuthConfig(BaseModel):
    username: str
    password: str
    base_authentication_url: HttpUrl
    authentication_path: str = "api/v3.0/authenticate"
    header_key: str = "Authorization"
    header_value_prefix: str = "Bearer "
    integration_uuid: UUID | str
    requests_timeout: int = 30
    verify_ssl: bool = False


class ClientConfig(BaseModel):
    base_url: HttpUrl
    policy_rule_path: str = "api/v4.0/visibility/policy/rules"
    policy_revision_path: str = "api/v4.0/visibility/policy/revisions"
    integration_uuid: UUID | str
    requests_timeout: int = 30
    verify_ssl: bool = False


class ControllerInput(BaseModel):
    integration_uuid: str
    clean: bool = False
    config: CompanyModel
    ioc_db_path: Path
