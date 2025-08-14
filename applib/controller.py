import hashlib
from datetime import datetime, UTC, timedelta
from itertools import chain

from applib.app import App
from applib.schemas.app import CanaryIndicator
from applib.schemas.config import CompanyModel
from applib.transforms import transform_ips, transform_domains, transform_urls
from applib.utils.utils import CustomCacheFile as LastRegisterFile
from lumudblib.db_client import get_local_company_iocs_type_limit
from lumudblib.models.models import IoCTypeEnum as IoCTypeEnumSource
from loguru import logger as _logger

COMMENT = "Detected by Lumu"


class AppIntegrator:
    def __init__(
        self,
        integration_uuid: str,
        config: CompanyModel,
        app: App,
        last_register_file: LastRegisterFile,
        db_path: str = "./ioc.db",
    ):
        self.ioc_db_path = db_path
        self._integration_uuid = integration_uuid
        self._last_register_file = last_register_file
        self.companyId = config.lumu.uuid
        self.adversaryTypes = config.lumu.adversaryTypes
        self.ioc_days = config.lumu.days
        self.company_name = config.app.name
        self._ioc_types = config.app.ioc

        self._max = config.app.max_indicators

        self.ioc_from = datetime.now(UTC) - timedelta(days=self.ioc_days)
        self.__app = app

        self.comment = COMMENT
        self._canary_indicator: str = f"{CanaryIndicator.canary_ip.value}"

        self._logger = _logger

    def _get_indicators_footprint(self, indicators: set):
        sorted_indicators = tuple(sorted(indicators))
        hash_object = hashlib.sha256(str(sorted_indicators).encode())
        footprint = hash_object.hexdigest()
        self._logger.debug(f"Integration: {self._integration_uuid} - Calculated footprint: {footprint}. Related indicators: {indicators}")
        return footprint

    def detect_indicators_changes(self, indicators: set):
        value = self._get_indicators_footprint(indicators)

        if last_value := self._last_register_file.get_value(self._integration_uuid):
            if last_value == value:
                return None

        return value

    def sync_ioc(self):
        active_indicators = self.get_active_indicators()
        self._logger.info(
            f"Integration: {self._integration_uuid} - Starting SYNC work."
        )

        if not (value := self.detect_indicators_changes(active_indicators)):
            self._logger.info(
                f"Integration: {self._integration_uuid} - No Indicator changes were detected."
            )
            return False

        if self.__app.safe_update(list(active_indicators)):
            self._last_register_file.write_file(self._integration_uuid, value)
            self._logger.info(
                f"Integration: {self._integration_uuid} - Indicators updated."
            )
            return True

        return False

    def get_active_indicators(self):
        iterables = [
            iter(
                [self._canary_indicator],
            ),
        ]

        if "url" in self._ioc_types:
            urls = get_local_company_iocs_type_limit(
                self.ioc_db_path,
                self.companyId,
                self.ioc_from,
                self.adversaryTypes,
                IoCTypeEnumSource.url,
                self._max,
            )
            urls_transformed = (transform_urls(url[0]) for url in urls)
            iterables.append(urls_transformed)
            _logger.info(
                f"Integration: {self._integration_uuid} - Lumu URLs: {len(urls)}"
            )

        if "domain" in self._ioc_types:
            domains = get_local_company_iocs_type_limit(
                self.ioc_db_path,
                self.companyId,
                self.ioc_from,
                self.adversaryTypes,
                IoCTypeEnumSource.domain,
                self._max,
            )
            domains_transformed = chain(
                [transform_domains(domain[0]) for domain in domains]
            )
            iterables.append(domains_transformed)
            _logger.info(
                f"Integration: {self._integration_uuid} - Lumu domains: {len(domains)}"
            )

        if "ip" in self._ioc_types:
            ips = get_local_company_iocs_type_limit(
                self.ioc_db_path,
                self.companyId,
                self.ioc_from,
                self.adversaryTypes,
                IoCTypeEnumSource.ip,
                self._max,
            )
            ips_transformed = chain([transform_ips(ip[0]) for ip in ips])
            iterables.append(ips_transformed)
            _logger.info(f"Integration: {self._integration_uuid} - Lumu IPs: {len(ips)}")

        active_indicators = set()
        for record in chain(*iterables):
            if len(active_indicators) >= self._max:
                break
            active_indicators.add(record)

        return active_indicators

    def clean(self):
        active_indicators: set[str] = {self._canary_indicator}

        self._logger.info(
            f"Integration: {self._integration_uuid} - Starting CLEANING work."
        )

        if not (value := self.detect_indicators_changes(active_indicators)):
            self._logger.info(
                f"Integration: {self._integration_uuid} - No indicator changes were detected."
            )
            return False

        if self.__app.safe_update(list(active_indicators)):
            self._last_register_file.write_file(self._integration_uuid, value)
            self._logger.info(f"Integration: {self._integration_uuid} - Clean updated.")
            return True

        return False
