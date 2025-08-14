from threading import Thread

from applib.app_build import AppBuilder
from applib.controller import AppIntegrator
from applib.schemas.app import ControllerInput
from applib.utils.utils import CustomCacheFile
from loguru import logger as _logger


class Worker:
    def __init__(
        self,
        rule_id_file: CustomCacheFile,
        last_register_file: CustomCacheFile,
    ):
        self.rule_id_file = rule_id_file
        self.last_register_file = last_register_file
        self.__integrators_threads = {}

        self._logger = _logger

    def init_integration(self, controller_input: ControllerInput):
        integration_uuid = controller_input.integration_uuid
        config = controller_input.config
        clean = controller_input.clean
        ioc_db_path = controller_input.ioc_db_path

        app = AppBuilder.build(integration_uuid, config, self.rule_id_file)

        controller = AppIntegrator(
            integration_uuid, config, app, self.last_register_file, ioc_db_path.name
        )

        if clean or config.app.clean:
            thread = Thread(
                target=controller.clean, name=f"Thread-{integration_uuid}", args=()
            )
        else:
            thread = Thread(
                target=controller.sync_ioc, name=f"Thread-{integration_uuid}", args=()
            )

        self.__integrators_threads[integration_uuid] = thread

    @property
    def integrators_threads(self):
        return self.__integrators_threads

    def run_threads(self):
        for companyId, thread_integration in self.__integrators_threads.items():
            thread_integration.start()

        for companyId, thread_integration in self.__integrators_threads.items():
            thread_integration.join()
            self._logger.info(f"{thread_integration.name} just finished")

        self.__integrators_threads.clear()
