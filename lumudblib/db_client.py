import logging
import os
import sys
from datetime import datetime, timedelta

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc

from sqlalchemy.exc import OperationalError

from lumudblib.models.models import IoCTypeEnum

_logger = logging.getLogger(__name__)


def get_local_iocs_raw(db_path):
    """
    Retrieve all LUMU local IOC with or without incident and status associated
    """
    try:
        if (
            not os.path.exists(db_path)
            or not os.path.isfile(db_path)
            or not os.stat(db_path).st_size
        ):
            exit("db_path not found or empty")
        os.environ["IOC_DB_PATH"] = db_path
        from lumudblib.dblib import DbLib

        with DbLib() as db_lib:
            ips, domains, urls, hashes = db_lib.get_ioc_raw()
        return ips, domains, urls, hashes
    except OperationalError as e:
        exit(f"{e.__class__} - {repr(e)} on {db_path} \n {e}")


def get_local_iocs(db_path, _from: datetime = None):
    """
    Retrieve all LUMU local IOC not muted incidents
    """
    try:
        if (
            not os.path.exists(db_path)
            or not os.path.isfile(db_path)
            or not os.stat(db_path).st_size
        ):
            exit("db_path not found or empty")
        os.environ["IOC_DB_PATH"] = db_path
        from lumudblib.dblib import DbLib

        with DbLib() as db_lib:
            if _from:
                _from = _from.replace(hour=0, minute=0, second=0, microsecond=0)
            ips, domains, urls, hashes = db_lib.get_ioc_sql(_from)
        return ips, domains, urls, hashes
    except OperationalError as e:
        exit(f"{e.__class__} - {repr(e)} on {db_path} \n {e}")


def get_local_company_iocs(
    db_path, _id, _from: datetime = None, adversaryTypes: list | None = None
):
    """
    Retrieve all LUMU local IOC not muted incidents
    """
    try:
        if (
            not os.path.exists(db_path)
            or not os.path.isfile(db_path)
            or not os.stat(db_path).st_size
        ):
            exit("db_path not found or empty")
        os.environ["IOC_DB_PATH"] = db_path
        from lumudblib.dblib import DbLib

        if _from:
            _from = _from.replace(hour=0, minute=0, second=0, microsecond=0)
        with DbLib() as db_lib:
            ips, domains, urls, hashes = db_lib.get_company_ioc_sql(
                _id, _from, adversaryTypes
            )
        return ips, domains, urls, hashes
    except OperationalError as e:
        exit(f"{e.__class__} - {repr(e)} on {db_path} \n {e}")


def get_local_company_iocs_type_limit(
    db_path,
    _id,
    _from: datetime = None,
    adversaryTypes: list | None = None,
    ioc_type: IoCTypeEnum = IoCTypeEnum.ip,
    limit=1000,
):
    """
    Retrieve all LUMU local IOC not muted incidents by ioc type(ip or domain or url or hash) with limit order by lastContact
    """
    try:
        if (
            not os.path.exists(db_path)
            or not os.path.isfile(db_path)
            or not os.stat(db_path).st_size
        ):
            exit("db_path not found or empty")
        os.environ["IOC_DB_PATH"] = db_path
        from lumudblib.dblib import DbLib

        if _from:
            _from = _from.replace(hour=0, minute=0, second=0, microsecond=0)
        with DbLib() as db_lib:
            entries = db_lib.get_company_ioc_type_sql_limit(
                _id, _from, adversaryTypes, ioc_type, limit
            )
        return entries
    except OperationalError as e:
        _logger.error(f"{e.__class__} - {repr(e)} on {db_path} \n {e}")
        sys.exit(1)


def clean_expired_records(days=90):
    try:
        from lumudblib.dblib import DbLib

        with DbLib() as db_lib:
            db_lib.delete_expired_incs_and_ioc(
                expired_date=datetime.now(UTC) - timedelta(days=days)
            )

    except OperationalError as e:
        print(f"{e.__class__} - {repr(e)} \n {e}")


def create_companies(companies: list[dict]):
    try:
        from lumudblib.dblib import DbLib

        with DbLib() as db_lib:
            for company in companies:
                _uuid = company.get("lumu", {}).get("uuid")
                name = company.get("lumu", {}).get("name")
                contact_name = company.get("lumu", {}).get("contact_name")
                contact_email = company.get("lumu", {}).get("contact_email")
                defender_key = company.get("lumu", {}).get("defender_key")
                if not (_uuid and defender_key):
                    msg = f"neither uuid nor defender_key are defined for at leat one of the companies"
                    raise ValueError(msg)
                db_lib.create_or_update_company(
                    _uuid=_uuid,
                    name=name,
                    contact_name=contact_name,
                    contact_email=contact_email,
                )
    except OperationalError as e:
        print(f"{e.__class__} - {repr(e)} \n {e}")


def get_company_incidents(db_path, companyId: str, _from: datetime):
    if (
        not os.path.exists(db_path)
        or not os.path.isfile(db_path)
        or not os.stat(db_path).st_size
    ):
        error_msg = "The IOC Local DB not found or empty, maybe there is not a IOC Manager running, start it first"
        _logger.error(error_msg)
        exit(error_msg)
    os.environ["IOC_DB_PATH"] = db_path
    try:
        from lumudblib.dblib import DbLib

        with DbLib() as db_lib:
            _from = _from.replace(hour=0, minute=0, second=0, microsecond=0)
            for incident in db_lib.get_company_incidents_and_ioc(companyId):
                if incident.lastContact >= _from:
                    yield incident

    except OperationalError as e:
        print(f"{e.__class__} - {repr(e)} \n {e}")


def get_company_incident_ioc(db_path, companyId: str, _from: datetime = None):
    """
       :param companyId:
       :param _from: corresponds ti the LastContactDatetime
       :return:
       [
           {'id': '4abebcd0-74b9-11ee-9638-e1399be0bcf8',
    'adversaryId': 'malware.wicar.org',
    'description': 'Malware family Exploit.Agent.Nt.Swf',
    'status': 'open',
    'statusTimestamp': datetime.datetime(2023, 11, 1, 4, 30, 26, 278000),
    'updated': datetime.datetime(2023, 11, 6, 1, 39, 51),
    'ioc': {'ip': [],
            'domain': ['malware.wicar.org'],
            'url': ['https://malware.wicar.org/data',
                    'http://malware.wicar.org/data'],
            'hash': ['fa9b55c8cf28b2df3218df833a4ff4865426645982bcabe89893c98bebbc4fb3',
                     '72befb5732d1dfa586c1d7db6865fc5c3b0e473f7d58428be66080679b57211f',
                     '6814c3d7e1d9741555d4bf3d8274a17d838db7be49c0d7a9d6b74bfc15f3a5dc',
                     'e2afad6e4bdd83d31516ccb993e39725e1ee0537943b3cc65e8370124b6f4d1f']},
    'companyId': '3aac00ce-229c-45ad-ada0-8585cec4f0e3'},
             ...
       ]
    """
    if _from is None:
        _from = datetime.now(UTC) - timedelta(days=60)
    _from = _from.replace(hour=0, minute=0, second=0, microsecond=0)
    if (
        not os.path.exists(db_path)
        or not os.path.isfile(db_path)
        or not os.stat(db_path).st_size
    ):
        error_msg = "The local IOC database is missing or it's empty . Please ensure the IOC Manager component is up and running"
        _logger.error(error_msg)
        exit(error_msg)
    os.environ["IOC_DB_PATH"] = db_path
    for incident in get_company_incidents(db_path, companyId, _from):
        inc = {
            "id": str(incident.id),
            "adversaryId": incident.adversaryId,
            "adversaryTypes": incident.adversaryTypes,
            "description": incident.description,
            "status": incident.status.value,
            "statusTimestamp": incident.statusTimestamp,
            "updated": incident.updated,
            "ioc": {"ip": [], "domain": [], "url": [], "hash": []},
            "companyId": companyId,
        }
        for ioc in incident.iocs:
            match ioc.type.value:
                case "ip":
                    inc["ioc"]["ip"].append(ioc.value)
                case "domain":
                    inc["ioc"]["domain"].append(ioc.value)
                case "url":
                    inc["ioc"]["url"].append(ioc.value)
                case "hash":
                    inc["ioc"]["hash"].append(ioc.value)
        yield inc
        inc.clear()
