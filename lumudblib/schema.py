from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IntegrationSquema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LumuSquema(IntegrationSquema):
    uuid: UUID
    defender_key: str
    hash_type: Literal["sha256", "sha1", "md5"] = Field("sha256")
    ioc_types: list[Literal["ip", "domain", "url", "hash"]] = Field(
        ["ip", "domain", "url", "hash"], max_length=4, min_length=1
    )
    adversary: list[
        Literal["C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"]
    ] = Field(
        ["C2C", "Malware", "Mining", "Spam", "Phishing", "Anonymizer"],
        max_length=6,
        min_length=1,
    )
    days: int = Field(3, ge=1, le=30)


class CompanySchema(IntegrationSquema):
    lumu: LumuSquema

    model_config = ConfigDict(extra="forbid")
