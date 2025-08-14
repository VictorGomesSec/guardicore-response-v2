import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Boolean, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql.functions import func
from sqlalchemy_utils import UUIDType, EmailType
from sqlalchemy.types import TypeDecorator

from lumudblib.models.db import Base


# Custom time to support timezone-aware datetimes
class DateTimeTimezone(TypeDecorator):
    """
    This class works as an enhancedDatetime with timezone
    """

    impl = DateTime
    cache_ok = False
    LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo

    def process_bind_param(self, value: datetime, dialect):
        if value.tzinfo is None:
            value = value.astimezone(self.LOCAL_TIMEZONE)

        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)


class IncidentStatusEnum(enum.Enum):
    muted = "muted"
    open = "open"
    closed = "closed"


class HashAlgorithmEnum(enum.Enum):
    sha256 = "sha256"
    sha1 = "sha1"
    md5 = "md5"


class IoCTypeEnum(enum.Enum):
    domain = "domain"
    ip = "ip"
    url = "url"
    hash = "hash"


class IoCModel(Base):
    __tablename__ = "iocs"

    id = Column(UUIDType(binary=False), primary_key=True, default=uuid.uuid4)
    type = Column(Enum(IoCTypeEnum), nullable=False)
    value = Column(String, nullable=False, index=True, unique=False)
    hash_type = Column(Enum(HashAlgorithmEnum), nullable=True)

    incident_id = Column(
        UUIDType(
            binary=False,
        ),
        ForeignKey("incidents.id"),
        nullable=True,
    )
    incident = relationship(
        "IncidentModel", foreign_keys=incident_id, back_populates="iocs"
    )

    active = Column(Boolean, default=True)
    created = Column(DateTimeTimezone(), server_default=func.now(), index=True)
    updated = Column(DateTimeTimezone(), server_default=func.now(), onupdate=func.now())


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(UUIDType(binary=False), primary_key=True)
    adversaryId = Column(String(500))
    adversaryTypes = Column(JSON, nullable=True)
    description = Column(String(500), nullable=True)
    status = Column(Enum(IncidentStatusEnum), default=IncidentStatusEnum.open)

    statusTimestamp = Column(DateTimeTimezone(), nullable=True)
    timestamp = Column(DateTimeTimezone(), nullable=True)
    firstContact = Column(DateTimeTimezone(), nullable=True)
    lastContact = Column(DateTimeTimezone(), nullable=True)

    iocs = relationship(
        "IoCModel", foreign_keys=[IoCModel.incident_id], back_populates="incident"
    )

    companyId = Column(
        UUIDType(
            binary=False,
        ),
        ForeignKey("companies.id"),
        nullable=True,
    )
    company = relationship(
        "CompanyModel", foreign_keys=companyId, back_populates="incidents"
    )

    active = Column(Boolean, default=True)
    created = Column(DateTimeTimezone(), server_default=func.now(), index=True)
    updated = Column(DateTimeTimezone(), server_default=func.now(), onupdate=func.now())


class CompanyModel(Base):
    __tablename__ = "companies"

    id = Column(UUIDType(binary=False), primary_key=True)
    name = Column(String(500), nullable=True)
    contact_name = Column(String(500), nullable=True)
    contact_email = Column(EmailType(), nullable=True)

    incidents = relationship(
        "IncidentModel",
        foreign_keys=[IncidentModel.companyId],
        back_populates="company",
    )

    active = Column(Boolean, default=True)
    created = Column(DateTimeTimezone(), server_default=func.now(), index=True)
    updated = Column(DateTimeTimezone(), server_default=func.now(), onupdate=func.now())
