## Lumu Defender constants
# Base URL
BASE_URL = "https://defender.lumu.io"
# Requests conditions
MAX_ITEMS = 10240
RATE_LIMIT = 60
MAX_CALLS_PER_TIME = 40
# TODO: Review page and items usage. Maybe adding that on service layer?
PATH_LABELS = "/api/administration/labels"
PATH_USERS = "/api/administration/users"
# Have in mind the "special" URLs
# GET
# all - Retrieve incidents
# open - Retrieve open incidents
# muted - Retrieve muted incidents
# closed - Retrieve closed incidents
# POST: after {incident_uuid}
# mark-as-read - Mark incident as read
# mute - Mute incident
# unmute - Unmute incident
# close - Close incident
PATH_INCIDENTS = "/api/incidents"
# Special case. TODO: Review thoroughly
PATH_INCIDENTS_BY_ENDPOINT = "/api/incidents/{incident-uuid}/endpoints-contacts"
PATH_INCIDENTS_CONTEXT = "/{uuid}/context"
PATH_INCIDENTS_UPDATES = "/api/incidents/open-incidents/updates"
# TODO: Have in mind GET/POST capabilities
# Have in mind "special" URLs
# last - Last contacted adversaries
# last/list - Last contacted adversaries in list format
# Spambox
# spambox - Contacted adversaries related to Spambox
# spambox/last - Last contacted adversaries related to Spambox
# spambox/last/list - Last contacted adversaries related to Spambox in list format
PATH_CONTACTED_ADVERSARIES = "/api/adversarial-activity/contacted-adversaries"
# TODO: Have in mind GET/POST capabilities
# Have in mind "special" URLs
# last - Last affected endpoints
# last/list - Last affected endpoints in list format
PATH_AFFECTED_ENDPOINTS = "/api/adversarial-activity/affected-endpoints"
# TODO: Have in mind GET/POST capabilities
# last - Last Spambox adversaries
# last/list - Last Spambox adversaries in list format
PATH_SPAMBOX_ADVERSARIES = "/api/spambox/adversaries"
