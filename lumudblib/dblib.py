from datetime import datetime, timedelta
from typing import Literal, Generator

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc

from lumudblib.models.crud import IncidentCRUD, IoCCRUD, CompanyCRUD
from lumudblib.models.db import get_db
from lumudblib.models.models import IncidentStatusEnum, IoCTypeEnum, IncidentModel

URLList = list[str]
HASHList = list[str]
DOMAINList = list[str]
IPList = list[str]


class DbLib:
    def __init__(self):
        self.session = get_db()
        self.db = next(self.session)
        self.company_db: CompanyCRUD
        self.incident_db: IncidentCRUD
        self.ioc_db: IoCCRUD

    def close(self):
        next(self.session)

    def create_or_update_incident(
        self,
        _uuid,
        status: IncidentStatusEnum,
        adversaryId,
        adversaryTypes,
        description=None,
        statusTimestamp=None,
        timestamp=None,
        firstContact=None,
        lastContact=None,
        companyId=None,
    ):
        return self.incident_db.create_update(
            id=_uuid,
            status=status,
            adversaryId=adversaryId,
            adversaryTypes=adversaryTypes,
            description=description,
            statusTimestamp=statusTimestamp,
            timestamp=timestamp,
            firstContact=firstContact,
            lastContact=lastContact,
            companyId=companyId,
        )

    def create_or_update_company(
        self, _uuid, name: str, contact_name=None, contact_email=None
    ):
        return self.company_db.create_update(
            id=_uuid, name=name, contact_name=contact_name, contact_email=contact_email
        )

    def create_ioc(self, value, type: IoCTypeEnum, hash_type=None, incident_id=None):
        if isinstance(value, str):
            value = [value]
        result = []
        for v in value:
            result.append(
                self.ioc_db.safe_create_one(
                    value=v, type=type, incident_id=incident_id, hash_type=hash_type
                )
            )

        return result

    def create_ip(self, ioc: str | list, incident_id=None):
        return self.create_ioc(value=ioc, type=IoCTypeEnum.ip, incident_id=incident_id)

    def create_domain(self, ioc: str | list, incident_id=None):
        return self.create_ioc(
            value=ioc, type=IoCTypeEnum.domain, incident_id=incident_id
        )

    def create_url(self, ioc: str | list, incident_id=None):
        return self.create_ioc(value=ioc, type=IoCTypeEnum.url, incident_id=incident_id)

    def create_hash(
        self,
        ioc: str | list,
        incident_id=None,
        hash_type: Literal["sha256", "sha1", "md5"] = None,
    ):
        return self.create_ioc(
            value=ioc,
            type=IoCTypeEnum.hash,
            incident_id=incident_id,
            hash_type=hash_type,
        )

    def delete_ioc(self, ioc, incident_id=None):
        return self.ioc_db.delete_one(ioc, incident_id=incident_id)

    def get_inc_ioc(self, incident_id):
        """
        Get IOCs given a incident id
        :param incident_id:
        :return:
        """
        ips, domains, urls, hashes = [], [], [], []
        if self.incident_db.get_iocs(incident_id) is None:
            return [], [], [], []
        for ioc in self.incident_db.get_iocs(incident_id):
            match ioc.type.value:
                case "ip":
                    ips.append(ioc.value)
                case "domain":
                    domains.append(ioc.value)
                case "url":
                    urls.append(ioc.value)
                case "hash":
                    hashes.append(ioc.value)
        return ips, domains, urls, hashes

    def get_company_ioc(
        self, _id, _from: datetime = None, adversaryTypes: list | None = None
    ):
        """
        Get IOCs of a Company within datetime and filter adversary types,
        filter the IOCs muted incidents and repeated adversaries when a close and a mute are found
        :param _id:
        :param _from:
        :param adversaryTypes:
        :return:
        """
        if _from is None:
            _from = datetime.now(UTC) - timedelta(days=60)

        ips, domains, urls, hashes = [], [], [], []
        adversaries_repeated = self.company_db.get_inc_adversary_repeated_mute_close(
            _id, _from
        )
        for ioc in self.company_db.get_inc_not_muted_ioc(_id):
            if (
                ioc.incident.adversaryId in adversaries_repeated
                and ioc.incident.status != "open"
            ):
                continue
            result = set(ioc.incident.adversaryTypes).intersection(
                set([] if not adversaryTypes else adversaryTypes)
            )
            if not adversaryTypes or result:
                if ioc.incident.lastContact >= _from:
                    match ioc.type.value:
                        case "ip":
                            ips.append(ioc.value)
                        case "domain":
                            domains.append(ioc.value)
                        case "url":
                            urls.append(ioc.value)
                        case "hash":
                            hashes.append(ioc.value)
        return ips, domains, urls, hashes

    def get_company_ioc_sql(
        self, _id, _from: datetime = None, adversaryTypes: list | None = None
    ):
        """
        Get IOCs of a Company within datetime and filter adversary types,
        filter the IOCs muted incidents and repeated adversaries when a close and a mute are found
        :param _id:
        :param _from:
        :param adversaryTypes:
        :return:
        """
        if _from is None:
            _from = datetime.now(UTC) - timedelta(days=60)

        ips, domains, urls, hashes = [], [], [], []
        for ioc in self.company_db.get_inc_not_muted_ioc_sql(_id, _from):
            result = set(ioc.incident.adversaryTypes).intersection(
                set([] if not adversaryTypes else adversaryTypes)
            )
            if not adversaryTypes or result:
                if ioc.incident.lastContact.astimezone(_from.tzinfo) >= _from:
                    match ioc.type.value:
                        case "ip":
                            ips.append(ioc.value)
                        case "domain":
                            domains.append(ioc.value)
                        case "url":
                            urls.append(ioc.value)
                        case "hash":
                            hashes.append(ioc.value)
        return ips, domains, urls, hashes

    def get_company_ioc_type_sql_limit(
        self,
        _id,
        _from: datetime = None,
        adversaryTypes: list | None = None,
        ioc_type: IoCTypeEnum = IoCTypeEnum.ip,
        limit=1000,
    ) -> list[tuple[str, datetime]]:
        """
        Get IOCs of a Company within datetime and filter adversary types and IOC type order by lastContact and limit the outcome items
        filter the IOCs muted incidents and repeated adversaries when a close and a mute are found
        :param _id:
        :param _from:
        :param adversaryTypes:
        :param ioc_type:
        :param limit:
        :return:
        """
        if _from is None:
            _from = datetime.now(UTC) - timedelta(days=60)

        entries = []
        adversaries_repeated = self.company_db.get_inc_adversary_repeated_mute_close(
            _id, _from
        )
        for ioc in self.company_db.get_inc_not_muted_ioc_sql_limit_by_type(
            _id, _from, ioc_type, limit
        ):
            if (
                ioc.incident.adversaryId in adversaries_repeated
                and ioc.incident.status != "open"
            ):
                continue
            result = set(ioc.incident.adversaryTypes).intersection(
                set([] if not adversaryTypes else adversaryTypes)
            )
            if not adversaryTypes or result:
                entries.append((ioc.value, ioc.incident.lastContact))
        return entries

    def get_company_ioc_raw(self, _id, adversaryTypes: list | None = None):
        """
        Get IOCs of a company within all status
        :param _id:
        :param adversaryTypes:
        :return:
        """
        ips, domains, urls, hashes = [], [], [], []
        for ioc in self.company_db.get_inc_ioc_raw(_id):
            result = set(ioc.incident.adversaryTypes).intersection(
                set([] if not adversaryTypes else adversaryTypes)
            )
            if not adversaryTypes or result:
                match ioc.type.value:
                    case "ip":
                        ips.append(ioc.value)
                    case "domain":
                        domains.append(ioc.value)
                    case "url":
                        urls.append(ioc.value)
                    case "hash":
                        hashes.append(ioc.value)
        return ips, domains, urls, hashes

    def get_ioc_sql(self, _from: datetime = None):
        """
        Get all not muted IOCs
        :param _from:
        :return:
        """
        if _from is None:
            _from = datetime.now(UTC) - timedelta(days=60)

        ips, domains, urls, hashes = [], [], [], []
        for ioc in self.ioc_db.get_inc_not_muted_ioc_sql(_from):
            match ioc.type.value:
                case "ip":
                    ips.append(ioc.value)
                case "domain":
                    domains.append(ioc.value)
                case "url":
                    urls.append(ioc.value)
                case "hash":
                    hashes.append(ioc.value)
        return ips, domains, urls, hashes

    def get_ioc(
        self, _from: datetime = None
    ) -> tuple[IPList, DOMAINList, URLList, HASHList]:
        """
        Get all IOCs  which have incident associated and not muted
        :return:
        """
        if _from is None:
            _from = datetime.now(UTC) - timedelta(days=60)
        offset = 0
        limit = 1000

        ips = [
            ioc.value
            for ioc in self.ioc_db.get_all_ip(offset, limit)
            if (
                ioc.active
                and ioc.incident
                and ioc.incident.status != IncidentStatusEnum.muted
                and ioc.incident.lastContact >= _from
            )
        ]
        domains = [
            ioc.value
            for ioc in self.ioc_db.get_all_domain(offset, limit)
            if (
                ioc.active
                and ioc.incident
                and ioc.incident.status != IncidentStatusEnum.muted
                and ioc.incident.lastContact >= _from
            )
        ]
        urls = [
            ioc.value
            for ioc in self.ioc_db.get_all_url(offset, limit)
            if (
                ioc.active
                and ioc.incident
                and ioc.incident.status != IncidentStatusEnum.muted
                and ioc.incident.lastContact >= _from
            )
        ]
        hashes = [
            ioc.value
            for ioc in self.ioc_db.get_all_hash(offset, limit)
            if (
                ioc.active
                and ioc.incident
                and ioc.incident.status != IncidentStatusEnum.muted
                and ioc.incident.lastContact >= _from
            )
        ]
        return ips, domains, urls, hashes

    def get_ioc_raw(self) -> tuple[IPList, DOMAINList, URLList, HASHList]:
        """
        Get all IOC no matters if it has incident associated and its status
        :return:
        """
        offset = 0
        limit = 1000

        ips = [ioc.value for ioc in self.ioc_db.get_all_ip(offset, limit) if ioc.active]
        domains = [
            ioc.value for ioc in self.ioc_db.get_all_domain(offset, limit) if ioc.active
        ]
        urls = [
            ioc.value for ioc in self.ioc_db.get_all_url(offset, limit) if ioc.active
        ]
        hashes = [
            ioc.value for ioc in self.ioc_db.get_all_hash(offset, limit) if ioc.active
        ]
        return ips, domains, urls, hashes

    def get_incs(self) -> list[str]:
        return [str(inc.id) for inc in self.incident_db.get_all()]

    def get_company_incidents_and_ioc(
        self, _id
    ) -> Generator[IncidentModel, None, None]:
        for incident in self.company_db.get_incidents(_id):
            if incident.status != IncidentStatusEnum.muted:
                yield incident

    def delete_incs(self, _uuid):
        return self.incident_db.delete_one(_uuid)

    def delete_expired_incs_and_ioc(self, expired_date: datetime):
        return self.incident_db.delete_expired_items(expired_date)

    def __enter__(self):
        self.company_db = CompanyCRUD(self.db)
        self.incident_db = IncidentCRUD(self.db)
        self.ioc_db = IoCCRUD(self.db)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        next(self.session)
