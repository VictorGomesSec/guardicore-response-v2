from loguru import logger as _logger

from applib.client import Client
from applib.utils.utils import CustomCacheFile as RuleIdFile


class App:
    def __init__(
        self,
        integration_uuid: str,
        provisioning: bool,
        client: Client,
        rule_id_file: RuleIdFile,
    ):
        self._integration_uuid = integration_uuid
        self._description = "Managed by Lumu. Do not edit it manually."
        self._note = "Sent by Lumu integration."
        self._client = client
        self._rule_id_file = rule_id_file
        self._provisioning = provisioning

        self._rule_set = None

        self._logger = _logger

    def save_rule_id(self, rule_id: str):
        if not self._rule_id_file.write_file(self._integration_uuid, rule_id):
            self._logger.warning(
                f"Failed to save Rule ID {rule_id} for integration UUID {self._integration_uuid}"
            )

    def get_rule_id(self) -> str | None:
        rule_id = self._rule_id_file.get_value(self._integration_uuid)
        if not rule_id:
            self._logger.warning(
                f"Rule ID not found for integration UUID {self._integration_uuid}"
            )
            return None
        return rule_id

    def _commit_publishing(self, rule_set: str):
        if self._provisioning:
            response = self._client.publish_segmentation_policy_changes(rule_set, self._note)
            self._logger.info(
                f"Integration: {self._integration_uuid} - Segmentation policy changes published for rule set: {rule_set}, response: {response.status_code} - {response.text}"
            )
        return True

    def safe_update(self, indicators: list[str]):
        if not self._rule_set:
            self._logger.error(
                f"Integration: {self._integration_uuid} - Rule set not defined."
            )
            return None
        try:
            if not (rule_uuid := self.get_rule_id()):
                return None
            self._client.edit_policy_rule(rule_uuid, indicators)

            self._commit_publishing(self._rule_set)

            return True
        except Exception as error:
            self._logger.error(
                f"Integration: {self._integration_uuid} - Failed to update the Rule: {error.__class__} - {error}"
            )
            return None

    def safe_initialization(self, rule_set: str, init_rule_id: str = None):
        if rule_uuid := self.get_rule_id():
            self._logger.info(
                f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' already associated with ID: {rule_uuid}"
            )
            self._rule_set = rule_set
            return rule_uuid
        result = self._client.filter_policy_rule(rule_set, "ruleset_name,id")
        if result.total:
            rules_id = result.objects
            if len(rules_id) >= 1:
                if not init_rule_id:
                    self._logger.warning(
                        f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' is set on this rules {[rule['id'] for rule in rules_id]}"
                    )
                    self._logger.error(
                        f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' already exists in more than one rule, please use the rule_id input parameter on YML configuration."
                    )
                    return None
                else:
                    rule_uuid_first_digits = init_rule_id.split("-")[-1].lower()
                    for rule_uuid in [rule["id"] for rule in rules_id]:
                        if rule_uuid_first_digits in rule_uuid.lower():
                            self.save_rule_id(rule_uuid)
                            self._logger.info(
                                f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' associated with ID: {rule_uuid}"
                            )
                            self._rule_set = rule_set
                            return rule_uuid
                    else:
                        self._logger.error(
                            f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' not found for the ID: {init_rule_id}"
                        )
                        return None
            rule_uuid = rules_id[0]["id"]
            self.save_rule_id(rule_uuid)
            self._logger.info(
                f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' associated with ID: {rules_id[0]['id']}"
            )
            self._rule_set = rule_set
            return rule_uuid
        self._logger.error(
            f"Integration: {self._integration_uuid} - Rule Set '{rule_set}' not found."
        )
        return None
