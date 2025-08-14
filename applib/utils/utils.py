import json
from json import JSONDecodeError
from pathlib import Path
from threading import RLock

from loguru import logger as _logger


class CustomCacheFile:
    def __init__(self, filename: str, rlock: RLock):
        self.filename = filename
        self._cache_file = Path.cwd() / Path(filename)
        self._rlock = rlock
        self._cache = {}

        self._cache_file.touch(exist_ok=True)

        self._logger = _logger

    def read_file(self):
        ids_ = {}
        try:
            with self._rlock:
                text = self._cache_file.read_text()
                if not text:
                    return ids_
                ids_ = json.loads(text)
            return ids_
        except JSONDecodeError as error:
            self._logger.warning(
                f"Error reading JSON file {self._cache_file.name}: {error.__class__} {error}"
            )
            return ids_

    def write_file(self, integration_uuid: str, value: str | int):
        try:
            with self._rlock:
                ids_ = self.read_file()
                ids_[integration_uuid] = value
                self._cache.update(ids_)
                self._cache_file.write_text(json.dumps(ids_, indent=2))
                return True
        except Exception as error:
            self._logger.warning(
                f"Error writing JSON file {self._cache_file.name}: {error}"
            )
            return False

    def get_value(self, integration_uuid: str) -> str | int | None:
        if id_ := self._cache.get(integration_uuid):
            return id_
        try:
            with self._rlock:
                ids_ = self.read_file()
                return ids_.get(integration_uuid)
        except Exception as error:
            self._logger.warning(
                f"Error reading JSON file {self._cache_file.name}: {error}"
            )
            return None
