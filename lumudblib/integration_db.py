import datetime
import logging

import lumulib.defender as lumu
from lumudblib.dblib import DbLib
from lumulib import defender
from lumulib.integration import LumuResponseIntegration, IOC_TYPES

_logger = logging.getLogger(__name__)


class CustomLumuDBIntegration(LumuResponseIntegration):
    def __init__(
        self, company_key, hash_type="sha256", companyId=None, ioc_types=IOC_TYPES
    ):
        self.companyId = companyId
        self.logger = logging.getLogger(__name__)
        self.hash_type = hash_type
        self._company_key = company_key
        self.stats = {
            "ip": {"collected": 0},
            "host": {"collected": 0},
            "url": {"collected": 0},
            "hash": {"collected": 0},
        }
        self.ioc = {"ip": [], "host": [], "url": [], "hash": []}
        self.init_lumu()
        self.incidents = []
        self.ioc_types_to_process(ioc_types)

    def init_lumu(self):
        self.lumu = defender.connect(company_key=self._company_key)

    def custom_get_inc_ioc(self, id, **incident):
        """
        get IOCs of one LUMU incident
        """
        self.incidents = [lumu.Incident(self.lumu, id, **incident)]
        self.process_incidents(ioc_types=self.ioc_types, hash_type=self.hash_type)
        ips = [ioc["ioc"] for ioc in self.ioc["ip"]]
        domains = [ioc["ioc"] for ioc in self.ioc["host"]]
        urls = [ioc["ioc"] for ioc in self.ioc["url"]]
        hashes = [ioc["ioc"] for ioc in self.ioc["hash"]]

        return ips, domains, urls, hashes

    def clear(self):
        self.incidents.clear()
        self.stats = {
            "ip": {"collected": 0},
            "host": {"collected": 0},
            "url": {"collected": 0},
            "hash": {"collected": 0},
        }
        self.ioc = {"ip": [], "host": [], "url": [], "hash": []}

    def save_incident(self, inc: lumu.Incident | object):
        with DbLib() as db_lib:
            _logger.debug(
                f"save_incident - Saving details of incident '{inc}' in local DB."
            )
            inc_db = db_lib.create_or_update_incident(
                _uuid=inc.id,
                status=inc.status,
                adversaryId=inc.adversaryId,
                adversaryTypes=inc.adversaryTypes,
                description=inc.description,
                statusTimestamp=datetime.datetime.fromisoformat(
                    inc.statusTimestamp[:-1]
                ),
                timestamp=datetime.datetime.fromisoformat(inc.timestamp[:-1]),
                firstContact=datetime.datetime.fromisoformat(inc.firstContact[:-1]),
                lastContact=datetime.datetime.fromisoformat(inc.lastContact[:-1]),
                companyId=self.companyId,
            )
        if inc_db:
            _logger.info(
                f"save_incident - CompanyId: {self.companyId} - Object created/updated in DB - Incident: {inc_db.id} - Adversary: {inc_db.adversaryId}"
            )
        return inc_db

    def save_inc_ioc(self, inc: lumu.Incident | object, inc_dict: dict):
        with DbLib() as db_lib:
            ips_db, domains_db, urls_db, hashes_db = db_lib.get_inc_ioc(inc.id)
            # print(ips_db, domains_db, urls_db, hashes_db)
            ips, domains, urls, hashes = self.custom_get_inc_ioc(**inc_dict)

            new_ips = list(set(ips).difference(set(ips_db)))
            new_domains = list(set(domains).difference(set(domains_db)))
            new_urls = list(set(urls).difference(set(urls_db)))
            new_hashes = list(set(hashes).difference(set(hashes_db)))

            del_ips = list(set(ips_db).difference(set(ips)))
            del_domains = list(set(domains_db).difference(set(domains)))
            del_urls = list(set(urls_db).difference(set(urls)))
            del_hashes = list(set(hashes_db).difference(set(hashes)))

            for del_ioc in del_ips + del_domains + del_urls + del_hashes:
                db_lib.delete_ioc(del_ioc, incident_id=inc.id)

            if "ip" in self.ioc_types:
                db_lib.create_ip(new_ips, inc.id)
            if "domain" in self.ioc_types:
                db_lib.create_domain(new_domains, inc.id)
            if "url" in self.ioc_types:
                db_lib.create_url(new_urls, inc.id)
            if "hash" in self.ioc_types:
                db_lib.create_hash(new_hashes, inc.id, hash_type=self.hash_type)

            self.logger.debug(
                f"companyId: {self.companyId} - {self.save_inc_ioc.__qualname__} - Process finished - Saved IOCs context for incident '{inc.id}'"
            )
            self.clear()
