import functools
import json
import logging

import lumulib.defender as lumu

_logger = logging.getLogger(__name__)

drop_msg_types = [
    "IncidentMarkedAsRead",
    "OpenIncidentsStatusUpdated",
    "IncidentIntegrationsResponseUpdated",
]

source_msg_type = context_msg_type = ["NewIncidentCreated", "IncidentUpdated"]
status_msg_type = ["IncidentClosed", "IncidentMuted", "IncidentUnmuted"]
status_msg_types = [
    "IncidentMuted",
    "IncidentUnmuted",
    "IncidentClosed",
    "IncidentCommentAdded",
]
comment_msg_type = ["IncidentCommentAdded"]
status_msg_create_type = ["NewIncidentCreated"]
status_msg_update_type = "IncidentUpdated"


class LumuClient:
    def __init__(self, lumu_app: lumu.Service):
        self.api = lumu_app
        self.labels = self._init_labels()

    @functools.lru_cache
    def get_lumu_incident(self, _id):
        return self.api.incidents[_id]

    def msg_fill_in(
        self,
        inc_msg,
        label_distribution=True,
        label_contact_summary=True,
        endpoints_affected=True,
    ):
        if not inc_msg.get("incident"):
            return inc_msg
        if label_distribution:
            # Populate labels distribution
            inc_msg["incident"]["labelDistribution"] = (
                self._populate_label_distribution(
                    inc_msg["incident"]["labelDistribution"]
                )
            )

        if label_contact_summary:
            # Enrich contactSummary label information
            try:
                label_from_contact_summary = inc_msg["contactSummary"].get("label", "0")
                inc_msg["contactSummary"]["label"] = self._get_label_data(
                    label_from_contact_summary
                )
            except KeyError as err:
                _logger.error(
                    f"msg_fill_in - {err.__class__}: {repr(err)} - {inc_msg['contactSummary']=}"
                )

        # Drop "openIncidentsStats"
        inc_msg.pop("openIncidentsStats", None)

        if endpoints_affected:
            endpoints = self.get_lumu_incident(inc_msg["incident"]["id"]).endpoints()

            inc_msg["endpoints"] = [
                (
                    self.labels.get(int(endpoint.label), {}).get(
                        "name", str(endpoint.label)
                    ),
                    endpoint.endpoint,
                )
                for endpoint in endpoints
            ]
        else:
            inc_msg["endpoints"] = []

        return inc_msg

    def _init_labels(self):
        """
        Method to init label information.

        Collect them from API and save them in memory
        """
        labels = {0: {"name": "Unlabeled activity", "relevance": 1}}
        # Set "Unlabeled activity"
        for label in self.api.labels:
            labels[label["id"]] = {
                "name": label["name"],
                "relevance": label["relevance"],
            }

        return labels

    def _populate_label_distribution(self, incident_labels: dict):
        """
        Method to populate label informacion for incident

        :param incident_labels: `dict` Dictionary with the distribution of contacts by label
        {
        "2840": 136,
        ...
        }
        :return: `dict` with reformatted distribution
        {
          "Headquarters": 136,
          ...
        }
        """
        dist_ = {}

        for k, v in incident_labels.items():
            try:
                # If label not exists in self.labels, the call api to update
                if not self.labels.get(int(k), None):
                    # Label not exist in memory, query and save it
                    new_label = self.api.labels[k]

                    self.labels[new_label["id"]] = {
                        "name": new_label["name"],
                        "relevance": new_label["relevance"],
                    }

                dist_[self.labels[int(k)]["name"]] = v
            except KeyError:
                dist_[k] = v

        return dist_

    def _get_label_data(self, label_id: str | int) -> dict:
        """
        Internal method to get label data from cache. If the record is not in cache, then
        collect it from Defender API

        Args:
            label_id (str|int): Lumu label ID "2840"

        Returns:
            A Dictionary with the danem and relevance of the label
            {
                "name": "Headquarters",
                "relevance": 3
            }
        """
        # If the label information is not present in cache, we need to pull it from Lumu API
        if not self.labels.get(int(label_id), None):
            new_label = self.api.labels[label_id]
            # Populate cache with the label data
            self.labels[new_label["id"]] = {
                "name": new_label["name"],
                "relevance": new_label["relevance"],
            }

        return self.labels[int(label_id)]

    @staticmethod
    def filter_msg_type(msg: str):
        message_json = json.loads(msg)
        msg_type = list(message_json.keys())[0]
        inc_msg = message_json[msg_type].copy()

        if msg_type in drop_msg_types:
            _logger.info(f"Dropping a message: {msg_type}")
            return "", {}
        return msg_type, inc_msg

    @staticmethod
    def format_input_msg(msg_type, inc_msg):
        msg_formatted = {}
        company_id = inc_msg["companyId"]
        incident_id = (
            inc_msg.get("incident", {}).get("id", None) or inc_msg["incidentId"]
        )
        url = (
            f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
        )

        if msg_type in status_msg_type:
            comment = inc_msg["comment"]

            msg_formatted.update(
                {
                    "companyId": company_id,
                    "comment": comment,
                    "incidentId": incident_id,
                    "url": url,
                    "incident": inc_msg["incident"],
                    "contactSummary": {},
                }
            )
            return incident_id, msg_type, comment, msg_formatted

        if msg_type in comment_msg_type:
            comment = inc_msg["comment"]

            msg_formatted.update(
                {
                    "companyId": company_id,
                    "comment": comment,
                    "incidentId": incident_id,
                    "url": url,
                    "incident": {},
                    "contactSummary": {},
                }
            )
            return incident_id, msg_type, comment, msg_formatted

        if msg_type in source_msg_type:
            comment = ""

            msg_formatted.update(
                {
                    "companyId": company_id,
                    "comment": comment,
                    "incidentId": incident_id,
                    "url": url,
                    "incident": inc_msg["incident"],
                    "contactSummary": inc_msg.get("contactSummary", {}),
                }
            )
            return incident_id, msg_type, comment, msg_formatted
