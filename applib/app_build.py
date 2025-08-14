import sys

from loguru import logger as _logger

from applib.app import App, RuleIdFile
from applib.client import Auth, Client
from applib.schemas.app import AuthConfig, ClientConfig
from applib.schemas.config import CompanyModel


class AppBuilder:
    @staticmethod
    def build(
        integration_uuid: str,
        config: CompanyModel,
        rule_id_file: RuleIdFile,
    ) -> App:
        username = config.app.api.username
        password = config.app.api.password
        provisioning = config.app.provisioning
        rule_set = config.app.rule_set
        init_rule_id = config.app.rule_id
        base_url = config.app.api.url_management_server

        auth_config = AuthConfig(
            username=username,
            password=password,
            base_authentication_url=base_url,
            integration_uuid=integration_uuid,
        )
        auth = Auth(config=auth_config)

        client_config = ClientConfig(
            base_url=base_url,
            integration_uuid=integration_uuid,
        )

        client = Client(config=client_config, auth=auth)

        app = App(integration_uuid, provisioning, client, rule_id_file)

        if not app.safe_initialization(rule_set, init_rule_id):
            _logger.critical(
                f"Integration: {integration_uuid} - Failed to create initialize App instance."
            )
            sys.exit(1)

        return app
