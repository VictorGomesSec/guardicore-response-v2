# Copyright Lumu Technologies
"""The **lumulib.defender** module provides a Pythonic interface to the
`Lumu Defender REST API <TBD>`_,
allowing you programmatically access Lumu's resources.

The core of the library is the
:class:`Service` class, which encapsulates a connection to the server, and
provides access to the various aspects of Lumu's functionality, which are
exposed via the REST API. You connect to Lumu with the :func:`connect` function::

    import lumulib.defender as client
    service = client.connect(company_key='...')
    assert isinstance(service, client.Service)

:class:`Service` objects have fields for the various Defender resources (such as users,
labels, incidents, contacted_adversaries, affected_endpoints, spambox_contacted_adversaries, and spambox_adversaries). All of these fields are
:class:`Collection` objects::

    incidents = service.incidents
    my_incident = incidents['incident_id']

The individual elements of the collection, in this case *incidents*,
are subclasses of :class:`Entity`. An ``Entity`` object has fields for its
attributes, and methods that are specific to each kind of entity. For example::

    print(my_incident['adversaryId'])  # Or: print(my_incident['adversaryId'])
    my_incident.mark_as_read()  # Marks my_incident as read
"""

import logging

# Imports
import requests
from requests.exceptions import HTTPError
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from six.moves import urllib
from .decorators import RateLimit

from .constants.globals import DEFAULT_TIMEOUT
from .constants.defender import (
    MAX_ITEMS,
    BASE_URL,
    PATH_LABELS,
    PATH_USERS,
    PATH_INCIDENTS,
    PATH_INCIDENTS_CONTEXT,
    PATH_CONTACTED_ADVERSARIES,
    PATH_SPAMBOX_ADVERSARIES,
    PATH_AFFECTED_ENDPOINTS,
    PATH_INCIDENTS_UPDATES,
)
from .exceptions import IllegalOperationException, DeserializationException

# Logger
logger = logging.getLogger("LumuDefenderSDK")


def connect(**kwargs):
    """
    Function to return connection instance to Lumu Defender API.

    Shorthand for :meth:`Service.login`

    :param company_key: Lumu company's API key
    :type company_key: ``string``
    :return: A tested :class:`Service` instance
    """
    s = Service(**kwargs)
    return s


class Service(object):
    """
    Base class for all services
    """

    def __init__(self, **kwargs):
        self.base_url = BASE_URL
        # Adding timeout to client to avoid hangup
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.company_key = kwargs.get("company_key", "")
        # Session
        self.s = requests.Session()
        # Added proxy functionality
        if kwargs.get("proxies", None):
            self.s.proxies.update(kwargs.get("proxies", None))
            # Verify - Default value will be set to true
            self.s.verify = kwargs.get("verify", True)
        # Base URL query
        self.query = {"key": self.company_key}
        # Control of rate limit
        self.rate_limit = {}

    def _query(self, **query):
        """
        Builds the final query to attach company key

        :param query: ``string`` All query params
        :return: Full query string
        """
        q = self.query
        if query:
            q.update(query)
        return q

    @RateLimit(
        limit_header="RateLimit-Limit",
        reset_header="RateLimit-Reset",
        remaining_header="RateLimit-Remaining",
    )
    def _perform_request(self, method, path, **kwargs):
        """
        Function to encapsulate Web requests
        """
        url = urllib.parse.urljoin(self.base_url, path)
        try:
            r = self.s.request(method, url, timeout=self.timeout, **kwargs)
            r.raise_for_status()
            # Set rate limit control variable
            self._set_rate_limit_from_response(r)
            return r
        except HTTPError as e:
            logger.error(
                f'Cannot {method.upper()} to "{path}". Details: {e.response.status_code} - {e.response.reason}.'
            )
            # Debug
            logger.debug(f"Exception detail: {e}.")
            self._set_rate_limit_from_response(e.response)
            if e.response.status_code == 400:
                # Error in query
                raise DeserializationException(
                    f"{r.json()['name']} - {r.json()['detail']}"
                )
            # If an error different to Deserialization, the raise without changes
            raise

    def get(self, path, **kwargs):
        """
        Sends a GET request to a specific URL path related to the API.

        :param path: ``string`` A REST path segment
        :param query: Other query arguments
        :return: The response from the server
        """
        q = self._query(**kwargs)
        return self._perform_request("get", path, params=q)

    def post(self, path, **kwargs):
        """
        Sends a POST request to a specific URL path related to the API

        :param path: ``string`` A REST path segment
        :param kwargs: Request query and body params
        :return: The response from the server
        """
        b = kwargs.pop("body")
        # Added for supporting additional headers
        h = kwargs.pop("headers", None)
        q = self._query(**kwargs)

        return self._perform_request("post", path, params=q, json=b, headers=h)

    def _set_rate_limit_from_response(self, response):
        """
        Set internal rate limit control varible using response headers
        """
        for k, v in response.headers.items():
            if "X-RateLimit-" in k:
                # Add to rate_limit var
                key = k.split("X-RateLimit-")[-1].lower()
                self.rate_limit[key] = int(v)

    def get_rate_limit(self, key):
        """
        Return rate limit property
        """
        try:
            return self.rate_limit[key]
        except KeyError:
            logger.error("Key not found")
            return 0

    @property
    def labels(self):
        """
        Return the list of labels present in the Lumu ecosystem

        :return: A ``list`` of labels
        """
        return Labels(self)

    @property
    def users(self):
        """
        Returns the list of users present in Lumu account

        :return: A ``list`` of users
        """
        return Users(self)

    # Property used for getting specific incident using uuid
    # Also is used to query different incidents based on status
    @property
    def incidents(self):
        """
        Returns the collection of incidents detected by Lumu.

        :return: A :class:`Incidents` collection of :class:`Incident` entities
        """
        return Incidents(self)

    @property
    def incidentsContext(self):
        """
        Returns the collection of incidents detected by Lumu.

        :return: A :class:`Incidents` collection of :class:`Incident` entities
        """
        return IncidentContext(self)

    @property
    def contacted_adversaries(self):
        """
        Returns the collection of contacted adversaries detected by Lumu.

        :return: A :class:`Adversaries` collection of :class:`Adversary` entities
        """
        return Adversaries(self)

    @property
    def affected_endpoints(self):
        """
        Returns the collection of affected endpoints of the incidents detected by Lumu.

        :return: A :class:`AffectedEndpoints` collection of :class:`AffectedEndpoint` entities
        """
        return AffectedEndpoints(self)

    @property
    def spambox_contacted_adversaries(self):
        """
        Returns the collection of contacted adversaries related to Spambox detected by Lumu.

        :return: A :class:`Adversaries` collection of :class:`Adversary` entities
        """
        return Adversaries(self, path_segment="spambox")

    @property
    def spambox_adversaries(self):
        """
        Returns the collection of Spambox adversaries detected by Lumu.
        This particular collections is related to detected Spambox adversaries even if there are no connections to them.

        :return: A :class:`SpamboxAdversaries` collection of :class:`Adversary` entities
        """
        return SpamboxAdversaries(self)

    @property
    def incident_updates(self):
        """
        Service to collect incident updates
        """
        return IncidentUpdates(self)


class Endpoint(object):
    """
    Class that represents individual Lumu Defender API resources.
    Common functionality of :class:`Collection` and :class:`Entity`
    """

    def __init__(self, service, path):
        self.service = service
        self.path = path

    def get(self, path_segment="", **query):
        """
        Performs a GET operation on the path

        :param path_segment:``string`` A path segment
        :param query:``string`` Query parameters
        :return: Response from the server
        """
        path = (
            path_segment
            if path_segment.startswith("/")
            else self.path + "/" + path_segment
        )
        return self.service.get(path, **query)

    def post(self, path_segment="", **query):
        """
        Performs a POST operation on the path

        :param path_segment:``string`` A path segment
        :param query:``string`` Query parameters
        :return: Response from the server
        """
        path = path_segment if path_segment.startswith("/") else "/" + path_segment
        return self.service.post(path, **query)


class Entity(Endpoint):
    """
    Base class for Defender API entities in the REST API, such as
    user, label, incident, adversary, affected-endpoint, spambox-adversary.

    TODO: Should be addresed like a dictionary
    """

    # Way to handle specially named fields of the entity
    defaults = {}

    def __init__(self, service, path, **kwargs):
        # References parent constructor
        Endpoint.__init__(self, service, path)
        # Added special var to handle attributes
        self.content = None
        if kwargs:
            self.content = kwargs
        return

    def __contains__(self, item):
        # Overrides __contains__
        try:
            self[item]
        except (KeyError, AttributeError):
            # Item not found
            return False

    def __eq__(self, other):
        # TODO: Pending to implement if applies.
        pass

    def __getattr__(self, key):
        # TODO: Review implementation
        if key in self.content:
            return self.content[key]
        else:
            raise AttributeError(key)

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self):
        # Return content dict for printing purposes
        return str(self.content)

    def get(self, path_segment="", **query):
        return super(Entity, self).get(path_segment, **query)

    def post(self, path_segment="", **query):
        return super(Entity, self).post(path_segment, **query)

    def refresh(self, **kwargs):
        """
        Refresh entity.

        Query again server endpoint to get new status of entity
        """
        self.content = self._read(self.get(**kwargs))
        return self

    def _read(self, response):
        """
        Reads the current state of the entity from the server
        """
        return _load_lumu_entry(response)


class Collection(Endpoint):
    """
    This class represents a collection of entities.
    """

    def __init__(self, service, path, item=Entity):
        Endpoint.__init__(self, service, path)
        self.item = item
        self.null_count = -1

    def __contains__(self, name):
        """
        Check if an item with name name exists in this collection
        """
        try:
            self[name]
            return True
        except KeyError:
            return False

    def __getitem__(self, key):
        """
        Fetch an item called *key* from this collection.

        :param key: Key name of the object
        :type key: ``string``
        :return: An :class:`Entity` object
        """
        try:
            response = self.get(key)
            entry = self._load_list(response)[0]
            return entry[0]
        except HTTPError as e:
            # If the result code is 404, there is no entity with that name
            if e.response.status_code == 404:
                raise KeyError(key)
            else:
                raise

    def __iter__(self, **kwargs):
        """
        Iterate over the entities in the collection
        """
        for item in self.iter(**kwargs):
            yield item

    def __len__(self):
        pass

    def _load_list(self, response):
        """
        Converts *response* to a list of entities
        """
        entries, pag_info = _load_lumu_entries(response)
        # Added encapsulation in `self.item`` class
        entities = []

        for entry in entries:
            entity = self.item(self.service, **entry)
            entities.append(entity)
        return entities, pag_info

    def _load_object(self, response):
        """
        Converts *response* to a list of entities
        """
        entries = _load_lumu_entry(response)
        return entries

    def iterObject(self, page=1, items=100, max_items=MAX_ITEMS, count=None, **kwargs):
        """
        Iterates over the collection.

        Returns an interator

        :param page: The page number to return (optional).
        :type page: ``integer``
        :param items: The number of items per page to return (optional).
        :type items: ``integer``
        :param max_items: The max number of items that will be returned
        :type max_items: ``integer``
        :param count: The number of entities to load (optional).
        :type count: ``integer``
        :param kwargs: Additional arguments (optional) FOR LATER USE!
        :type kwargs: ``dict``
        """
        assert items is None or items > 0
        if count is None:
            count = self.null_count
        fetched = 0
        # This cycle controls if count is deliberately defined
        while count == self.null_count or fetched < count:
            # Time to get elements
            # Workaround: Used dict to pass **query params because max-items uses a hyphen
            # Added capabilities for filtering with post body
            if "body" in kwargs.keys():
                response = self.post(
                    **{"page": page, "items": items, "max-items": max_items}, **kwargs
                )
            else:
                if "uuid" in kwargs.keys():
                    if "uuid" in self.path:
                        self.path = self.path.replace("{uuid}", str(kwargs["uuid"]))
                        del kwargs["uuid"]
                response = self.get(
                    **{"page": page, "items": items, "max-items": max_items}, **kwargs
                )
                count = count - 1
                # Check response to handle max number of request in a period of time
            if response:
                entries = self._load_object(response)
                return entries
            else:
                logger.info("Reached max requests. Breaking iter.")
                break

    def iter(self, page=1, items=100, max_items=MAX_ITEMS, count=None, **kwargs):
        """
        Iterates over the collection.

        Returns an interator

        :param page: The page number to return (optional).
        :type page: ``integer``
        :param items: The number of items per page to return (optional).
        :type items: ``integer``
        :param max_items: The max number of items that will be returned
        :type max_items: ``integer``
        :param count: The number of entities to load (optional).
        :type count: ``integer``
        :param kwargs: Additional arguments (optional) FOR LATER USE!
        :type kwargs: ``dict``
        """
        assert items is None or items > 0
        if count is None:
            count = self.null_count
        fetched = 0
        # This cycle controls if count is deliberately defined
        while count == self.null_count or fetched < count:
            # Time to get elements
            # Workaround: Used dict to pass **query params because max-items uses a hyphen
            # Added capabilities for filtering with post body
            if "body" in kwargs.keys():
                response = self.post(
                    **{"page": page, "items": items, "max-items": max_items}, **kwargs
                )
            else:
                response = self.get(
                    **{"page": page, "items": items, "max-items": max_items}, **kwargs
                )
            # Check response to handle max number of request in a period of time
            if response:
                entries, pag_info = self._load_list(response)
                N = len(entries)
                fetched += N
                for entry in entries:
                    yield entry
                # Getting next page
                page = pag_info.get("next", None)
                # We have already collected all pages
                if page is None:
                    break
                logger.debug("page={}, fetched={}, N={}".format(page, fetched, N))
            else:
                logger.info("Reached max requests. Breaking iter.")
                break

    def list(self, count=None, **kwargs):
        """
        Retrieves a list of entities in this collection.

        All collection is loaded at once and it is returned as a list

        :param count: The maximun number of entities to return (optional).
        :type count: ``integer``
        :param kwargs: Additional arguments (optional):
            - "page" (``integer``): The first page to return
            - "items" (``integer``): Limit the number of results per page (optional).
            - "max_items" (``integer``): Limit the number of results of the query (optional).
        :type kwargs: ``dict``
        :return: A ``list`` of entities
        """
        return list(self.iter(count=count, **kwargs))

    def object(self, count=None, **kwargs):
        """
        Retrieves a list of entities in this collection.

        All collection is loaded at once and it is returned as a list

        :param count: The maximun number of entities to return (optional).
        :type count: ``integer``
        :param kwargs: Additional arguments (optional):
            - "page" (``integer``): The first page to return
            - "items" (``integer``): Limit the number of results per page (optional).
            - "max_items" (``integer``): Limit the number of results of the query (optional).
        :type kwargs: ``dict``
        :return: A ``list`` of entities
        """
        return self.iterObject(count=count, **kwargs)

    def get(self, name="", **query):
        """
        Performs a GET request to the server on the collection

        :param name: Entity name
        :type name: ``string``
        """
        path = self.path if name == "" or name is None else self.path + "/" + name
        return super(Collection, self).get(path, **query)

    def post(self, name="", action="", **query):
        """
        Performs a POST request to the server on the collection.

        Useful for filtering requirements defined on the body of the request

        :param name: Entity name
        :type name: ``string``
        :param action: Action to be ran. Particularly for incidents
        :param query: dict of query params (optional)
        :type query: ``dict``
        """
        # Get path if there is name
        path = self.path if name == "" or name is None else self.path + "/" + name
        # Get path if there is action
        path = path if action == "" or action is None else path + "/" + action
        return super(Collection, self).post(path, **query)


# Collection of entities
class Labels(Collection):
    """
    This class provides access to labels.

    TODO: Add more documentation
    """

    def __init__(self, service):
        Collection.__init__(self, service, PATH_LABELS, item=Label)


class Users(Collection):
    """
    This class provides access to users

    TODO: Add more documentation
    """

    def __init__(self, service):
        Collection.__init__(self, service, PATH_USERS, item=User)


class Incidents(Collection):
    """
    This class provides access to incidents

    :param service: Service instance
    :type service:``Service``
    """

    def __init__(self, service, **kwargs):
        Collection.__init__(self, service, PATH_INCIDENTS, item=Incident)

    def __getitem__(self, key):
        """
        Override for Collection.

        For getting a particular incident, we need to append to the URL the word details to the key
        """
        key = key if key.endswith("/details") else key + "/details"
        item = Collection.__getitem__(self, key)
        return item

    def _retrieve(self, action="all", **kwargs):
        """
        Internal method in charge of querying incident searches

        :param action: Additional string to query incident by status or all (default "all").
        :type action: ``string``
        :param fromDate: Start date (optional).
        :type fromDate: ``string`` (formated datetime).
        :param toDate: Start date (optional).
        :type toDate: ``string`` (formated datetime).
        :param status: List of status to query (optional).
        :type status: ``list``
        :param adversary-types: List of adversary types to query (optional).
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :return: A ``list`` of incidents
        """
        filter = {"body": kwargs}
        return self.list(action=action, **filter)

    def get_all(self, **kwargs):
        """
        Retrieve incidents

        :param fromDate: Start date (optional).
        :type fromDate: ``string`` (formated datetime).
        :param toDate: Start date (optional).
        :type toDate: ``string`` (formated datetime).
        :param status: List of status to query (optional).
        :type status: ``list``
        :param adversary-types: List of adversary types to query (optional).
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :return: A ``list`` of incidents
        """
        return self._retrieve(action="all", **kwargs)

    def get_open(self, **kwargs):
        """
        Retrieve open incidents

        :param adversary-types: List of adversary types to query (optional).
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :return: A ``list`` of incidents
        """
        return self._retrieve(action="open", **kwargs)

    def get_muted(self, **kwargs):
        """
        Retrieve muted incidents

        :param adversary-types: List of adversary types to query (optional).
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :return: A ``list`` of incidents
        """
        return self._retrieve(action="muted", **kwargs)

    def get_closed(self, **kwargs):
        """
        Retrieve closed incidents

        :param adversary-types: List of adversary types to query (optional).
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :return: A ``list`` of incidents
        """
        return self._retrieve(action="closed", **kwargs)


class IncidentContext(Collection):
    def _context(self, action="context", **kwargs):
        filter = {}
        return self.object(action=2, **kwargs)

    def __init__(self, service, **kwargs):
        Collection.__init__(
            self, service, PATH_INCIDENTS + PATH_INCIDENTS_CONTEXT, item=Incident
        )

    def get_context(self, **kwargs):
        return self._context(action="context", **kwargs)


class IncidentEndpoints(Collection):
    """
    This class represents Endpoints related to a particular incident
    """

    def __init__(self, service, path, **kwargs):
        # For this particular case, we need to provide path
        # The path is related to the incident
        self.filter = {}
        if kwargs:
            for k, v in kwargs.items():
                self.filter[k] = v
        Collection.__init__(self, service, path, item=IncidentEndpoint)

    def iter(self):
        """
        Override for main iter funcion to deliver additional params to main iter function
        """
        filter_ = {"body": self.filter}
        entries = Collection.iter(self, **filter_)
        for entry in entries:
            # Encapsulating
            yield entry


class Adversaries(Collection):
    """
    This class represents adversaries detected on Lumu
    """

    def __init__(self, service, path_segment=""):
        # Added condition to handle contacted adversaries spambox
        path = (
            PATH_CONTACTED_ADVERSARIES
            if path_segment == ""
            else PATH_CONTACTED_ADVERSARIES + "/" + path_segment
        )
        Collection.__init__(self, service, path, item=Adversary)

    def _get_adversaries(self, name="", **kwargs):
        """
        Internal method that takes charge of ways to get adversary information
        """
        return self.list(name=name, **kwargs)

    def get_all(self, **kwargs):
        """
        Get contacted adversaries using filter

        :param fromDate: Start date (optional).
        :type fromDate: ``string`` (formated datetime).
        :param toDate: Start date (optional).
        :type toDate: ``string`` (formated datetime).
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :param endpoints: List of ids of contacting endpoints (default "all").
        :type endpoints: ``list``
        :return: A ``list`` of adversaries
        """
        # Filter
        # All filter go in the body
        filter = {"body": kwargs} if kwargs else {}
        return self._get_adversaries(name="", **filter)

    def last_contacted(self, **kwargs):
        """
        Get last contacted adversaries using filter.

        :param hours: The number of past hours you want to narrow your results to (default 1).
        :type hours: ``integer``.
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :param endpoints: List of ids of contacting endpoints (default "all").
        :type endpoints: ``list``
        :return: A ``list`` of adversaries
        """
        # Filter
        post_params = {"adversary-types", "labels", "endpoints"}
        filter = (
            {"body": kwargs} if any(k in kwargs.keys() for k in post_params) else kwargs
        )
        return self._get_adversaries(name="last", **filter)

    # Get last contacted adversaries list
    def last_contacted_list(self, **kwargs):
        """
        Query last contacted adversary list.

        It makes only one request to the server. The method depends on the filter defined on instance creation.

        TODO: Check application on real environments
        """
        post_params = {"adversary-types", "labels", "endpoints"}
        # Because we have only one page, we set that
        query = {"page": 1}
        method = "get"
        # Check filters
        query.update(
            {"body": kwargs} if any(k in kwargs.keys() for k in post_params) else kwargs
        )
        method = "post" if "body" in query.keys() else "get"
        # Query ready. Time to get data from the server
        method = getattr(self, method)
        response = method(name="last/list", **query)
        # Return the content. It is a byte that needs decoding (carriage return and line feed)
        return str(response.content.decode())


class SpamboxAdversaries(Collection):
    """
    This class represents adversaries related to Spambox.

    Spambox Adversaries are fetched from a different
    endpoint from the contacted ones. This means these adversaries could be contacted or not
    """

    def __init__(self, service, **kwargs):
        Collection.__init__(self, service, PATH_SPAMBOX_ADVERSARIES, item=Adversary)

    def _get_adversaries(self, name="", **kwargs):
        """
        Internal method that takes charge of ways to get adversary information
        """
        return self.list(name=name, **kwargs)

    def get_all(self, **kwargs):
        """
        Get contacted adversaries using filter

        :param fromDate: Start date (optional).
        :type fromDate: ``string`` (formated datetime).
        :param toDate: Start date (optional).
        :type toDate: ``string`` (formated datetime).
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :return: A ``list`` of adversaries
        """
        # Filter
        # All filter go in the body
        filter = {"body": kwargs} if kwargs else {}
        return self._get_adversaries(name="", **filter)

    def last(self, **kwargs):
        """
        Get a detailed list of adversarial hosts found on your Spambox, within a specified number of past hours.

        :param hours: The number of past hours you want to narrow your results to (default 1).
        :type hours: ``integer``.
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :return: A ``list`` of adversaries
        """
        # Filter
        filter = {"body": kwargs} if "adversary-types" in kwargs.keys() else kwargs
        return self._get_adversaries(name="last", **filter)

    # Get last spambox list
    def last_list(self, **kwargs):
        """
        Get a detailed list of adversarial hosts found on your Spambox, within a specified number of past hours in a plain text format.

        It makes only one request to the server. The method depends on the filter defined on instance creation.

        TODO: Check application on real environments
        """
        # Because we have only one page, we set that
        query = {"page": 1}
        # Adding kwargs
        query.update(kwargs)
        # Just using GET method. According to the documentation there is no parameter to pass in the body
        response = self.get(name="last/list", **query)
        # Return the content. It is a byte that needs decoding (carriage return and line feed)
        return str(response.content.decode())


class AffectedEndpoints(Collection):
    """
    This class represents affected endpoints
    """

    def __init__(self, service, **kwargs):
        Collection.__init__(
            self, service, PATH_AFFECTED_ENDPOINTS, item=AffectedEndpoint
        )

    def _get_endpoints(self, name="", **kwargs):
        """
        Internal method that takes charge of ways to get adversary information
        """
        return self.list(name=name, **kwargs)

    def get_all(self, **kwargs):
        """
        Get affected endpoints using filter

        :param fromDate: Start date (optional).
        :type fromDate: ``string`` (formated datetime).
        :param toDate: Start date (optional).
        :type toDate: ``string`` (formated datetime).
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :param adversaries: List of adversarial hosts (default "all").
        :type adversaries: ``list``
        :return: A ``list`` of adversaries
        """
        # Filter
        # All filter go in the body
        filter = {"body": kwargs} if kwargs else {}
        return self._get_endpoints(name="", **filter)

    def last_affected(self, **kwargs):
        """
        Get last affected endpoints using filter.

        :param hours: The number of past hours you want to narrow your results to (default 1).
        :type hours: ``integer``.
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :param adversaries: List of adversarial hosts (default "all").
        :type adversaries: ``list``
        :return: A ``list`` of adversaries
        """
        # Filter
        post_params = {"adversary-types", "labels", "endpoints"}
        filter = (
            {"body": kwargs} if any(k in kwargs.keys() for k in post_params) else kwargs
        )
        return self._get_endpoints(name="last", **filter)

    # Get last affected endpoints list
    def last_affected_list(self, **kwargs):
        """
        Query last affected endpoints list.

        It makes only one request to the server. The method depends on the filter defined on instance creation.

        :param hours: The number of past hours you want to narrow your results to (default 1).
        :type hours: ``integer``.
        :param adversary-types: List of adversary types detected ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"] (default "all").
        :type adversary-types: ``list``
        :param labels: List of labels to query (optional).
        :type labels: ``list``
        :param adversaries: List of adversarial hosts (default "all").
        :type adversaries: ``list``
        :param endpoint-identification-type: Type of endpoint ["IP", "ID"] (default "ID")
        """
        post_params = {"adversary-types", "labels", "endpoints"}
        # Because we have only one page, we set that
        query = {"page": 1}
        method = "get"
        # Check filters
        query.update(
            {"body": kwargs} if any(k in kwargs.keys() for k in post_params) else kwargs
        )
        method = "post" if "body" in query.keys() else "get"
        # Query ready. Time to get data from the server
        method = getattr(self, method)
        response = method(name="last/list", **query)
        # Return the content. It is a byte that needs decoding (carriage return and line feed)
        return str(response.content.decode())


class IncidentUpdates(Collection):
    """
    Endpoint to collect incident updates using REST API instead of Web sockets
    """

    def __init__(self, service, **kwargs):
        Collection.__init__(self, service, PATH_INCIDENTS_UPDATES)

    def get(self, offset=0, time=5):
        """
        Method to get latest updates based on the offset parameter

        :param offset: `int` Offset to collect updates
        :param time: `int` Time in secons to wait
        :return: `dict` Dictioary with attributes "updates" (list of updates) and "offset"
        """
        # Build requests parameters
        query = {
            "time": time,
        }

        if offset:
            query.update({"offset": offset})

        path = self.path
        return super(Collection, self).get(path, **query).json()


# Single entities
class Label(Entity):
    """
    This class represents a single label

    TODO: Add more documentation
    """

    def __init__(self, service, id, **kwargs):
        path = PATH_LABELS + "/" + str(id)
        kwargs.update({"id": id})
        Entity.__init__(self, service, path, **kwargs)

    @property
    def id(self):
        return self.content.get("id", None)

    @property
    def name(self):
        return self.content.get("name", None)

    @property
    def relevance(self):
        return self.content.get("relevance", None)


class User(Entity):
    """
    This class represents a single user

    TODO: Add more documentation
    TODO: Implement all properties
    """

    def __init__(self, service, id, **kwargs):
        path = PATH_USERS + "/" + str(id)
        kwargs.update({"id": id})
        Entity.__init__(self, service, path, **kwargs)

    @property
    def id(self):
        return self.content.get("id")

    @property
    def name(self):
        return self.content.get("name", None)

    @property
    def role(self):
        return self.content.get("role", None)


class Incident(Entity):
    """
    This class represents a single incident

    TODO: Add more documentation
    """

    def __init__(self, service, id, **kwargs):
        path = PATH_INCIDENTS + "/" + id
        kwargs.update({"id": id})
        Entity.__init__(self, service, path, **kwargs)

    def endpoints(self, **kwargs):
        """
        Property-like for getting endpoints related to the incident

        :param kwargs: Additional paramenters (optional).
            - "endpoints" (``list``): List of strings with endpoints (optional).
            - "labels" (``list``): List of strings with label ids (optional).
        :type kwargs: ``list``
        """
        path = self.path + "/endpoints-contacts"
        query = {"body": {}}
        for k, v in kwargs.items():
            query["body"].update({k: v})

        # Querying endpoints
        # We use a Collection of Endpoints with the required params
        # Adding endpoints to content
        self.content["endpoints"] = IncidentEndpoints(self.service, path, **kwargs)
        return self.content["endpoints"]

    def _update_incident(self, action, comment="", user_id=None):
        """
        Update incident.

        Base method for mute, unmute, read, close

        :param action: Action to be executed on incident ("mark-as-read", "mute", "unmute", "close").
        :type action: ``string``
        :param comment: Comment to be added in the incident log.
        :type comment: ``string``
        :param user_id: Lumu user id to be associated with the task (optional).
        :type user_id: ``integer``
        """
        # Supported actions
        actions = ["mark-as-read", "mute", "unmute", "close"]
        if action not in actions:
            raise IllegalOperationException(
                f"Update action '{action}' is not supported on an incident."
            )

        path = self.path + "/" + action
        # Prepare complimentary data
        query = {"body": {"comment": comment}}
        # Add additional header for user, if applies
        if user_id:
            query["headers"] = {"Lumu-User-Id": str(user_id)}
        # Time to update incident
        self.post(path, **query)

    def mark_as_read(self):
        """
        Mark incident as read.
        """
        self._update_incident(action="mark-as-read")
        # Refresh incident after mark as read
        return self.refresh()

    def mute(self, comment="", user_id=None):
        """
        Mute incident.

        :param comment: Comment to be added in the incident log.
        :type comment: ``string``
        :param user_id: Lumu user id to be associated with the task (optional).
        :type user_id: ``integer``
        """
        self._update_incident(action="mute", comment=comment, user_id=user_id)
        return self.refresh()

    def unmute(self, comment="", user_id=None):
        """
        Unmute incident.

        :param comment: Comment to be added in the incident log.
        :type comment: ``string``
        :param user_id: Lumu user id to be associated with the task (optional).
        :type user_id: ``integer``
        """
        self._update_incident(action="unmute", comment=comment, user_id=user_id)
        return self.refresh()

    def close(self, comment="", user_id=None):
        """
        Close incident.

        :param comment: Comment to be added in the incident log.
        :type comment: ``string``
        :param user_id: Lumu user id to be associated with the task (optional).
        :type user_id: ``integer``
        """
        self._update_incident(action="close", comment=comment, user_id=user_id)
        return self.refresh()

    def refresh(self):
        """
        Overrides :meth:refresh from :class:Entity, adding details at the end of the URL
        """
        # Pass path_segment details
        return super(Incident, self).refresh(path_segment="details")

    def context(self, hash_type="sha256"):
        """
        Collect context from incident.

        Presents MITRE related information, file hashes, threath details and additional resources.

        :param hash_type: {str} Hash type to be queried (default sha256) ["md5", "sha1", "sha256"]
        :return: {dict} Incident context information
        """
        # Add query string
        params = {"hash": hash_type}
        # Load context is not present in content
        if not self.content.get("context"):
            path = self.path + "/context"
            # Collect incident context
            response = self.get(path, **params)
            self.content["context"] = _load_lumu_entry(response)

        return self.content["context"]


class IncidentEndpoint(Entity):
    """
    This class represents a single endpoint. This endpoint is related to an incident
    """

    def __init__(self, service, **kwargs):
        path = ""
        Entity.__init__(self, service, path, **kwargs)


class Adversary(Entity):
    """
    This class represents a contacted adversary
    """

    def __init__(self, service, **kwargs):
        # Path is set to empty string because there is no way to access directly
        path = ""
        Entity.__init__(self, service, path, **kwargs)


class AffectedEndpoint(Entity):
    """
    This class represents and affected endpoint
    """

    def __init__(self, service, **kwargs):
        # Path is set to empty string because there is no way to access directly
        path = ""
        super().__init__(service, path, **kwargs)


# Other utils
def _load_lumu_entry(response):
    """
    Returns lumu record

    :param response: Response to be analyzed
    :type response: ``requests.models.Response``
    :return: Lumu record
    :rtype: ``dict``
    """
    data = response.json()
    if isinstance(data, list):
        raise Exception("Fetch multiple entries")
    else:
        return data


def _load_lumu_entries(response):
    """
    Function to return entities based on response.

    Have in mind that the pagination info is included in endpoints that return more results that can be returned in a single response.

    Here a Response example:

        {
            "labels": [
                {
                    "id": 1,
                    "name": "Sales",
                    "relevance": 3
                },
                {
                    "id": 2,
                    "name": "Customers",
                    "relevance": 1
                },
            ],
            "paginationInfo": {
                "page": 2,
                "items": 2,
                "next": 3,
                "prev": 1
            }
        }

    Keys: [entity name, paginationInfo]

    :param response: Response to be analyzed
    :type response: ``requests.models.Response``
    :return: Entries and pagination info (optional).
    :rtype: List of dicts
    """
    # Call load function to return Record or Record list
    # Workaround: Add data type validation
    data = response.json()
    # Lets analyze if there is pagination info
    # Workaround: pagination for contacted-adversaries
    pag = data.pop("paginationInfo", None)
    pag = pag if "pagination" not in data.keys() else data.pop("pagination", None)
    # If the pag is none, then we have only one record
    if pag is None:
        return [data], pag
    # The key remaining is the one with the data according to the example
    entries = data[list(data.keys())[0]]

    return entries, pag
