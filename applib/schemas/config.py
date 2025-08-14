import re
from typing import Literal, Annotated
from uuid import UUID

from pydantic import ConfigDict, Field, BaseModel, HttpUrl, ValidationError, constr
from loguru import logger as _logger


class IntegrationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LumuModel(IntegrationModel):
    uuid: UUID
    adversaryTypes: list[
        Literal["C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"]
    ] = Field(
        ["C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"],
        max_length=6,
        min_length=1,
    )
    days: int = Field(20, ge=1, le=100)


class ApiModel(IntegrationModel):
    url_management_server: Annotated[
        HttpUrl,
        Field(
            ...,
            description="Base URL of Guardicore API. Example: https://MANAGEMENT-SERVER:PORT/",
        ),
    ]
    username: Annotated[str, Field(..., min_length=3)]
    password: Annotated[str, Field(..., min_length=4)]


class AppModel(IntegrationModel):
    name: constr(
        min_length=3,
        max_length=20,
        strip_whitespace=True,
        pattern=re.compile(r"^[a-zA-Z0-9_\-]+$"),
    )
    clean: bool = False
    rule_set: constr(
        min_length=3,
        max_length=50,
        strip_whitespace=True,
        pattern=re.compile(r"^[a-zA-Z0-9_\-]+$"),
    )
    rule_id: Annotated[str | None, Field(None, min_length=1, max_length=60)]
    ioc: list[Literal["ip"]] = Field(
        [
            "ip",
        ],
        max_length=1,
        min_length=1,
    )
    provisioning: bool = True
    max_indicators: int = Field(5000, ge=1, le=5000)
    api: ApiModel


class CompanyModel(IntegrationModel):
    lumu: LumuModel
    app: AppModel


def config_validation(integration: dict) -> CompanyModel | None:
    try:
        config = CompanyModel.model_validate(integration)

    except ValidationError as errors:
        for error in errors.errors():
            _logger.critical(
                f"Parameter: {'.'.join((str(loc) for loc in error['loc']))} -> type:{error['type']} -> {error['msg']}"
            )
        return None
    else:
        return config
