# Ratelimit validation
# Headers of interest
# - RateLimit-Reset: number of seconds needed to reset the limit
# - RateLimit-Remaining: remaining requests
# - X-RateLimit-Remaining-Day: remaining requests per day
# - X-RateLimit-Limit-Day: max requests per day
import logging
from time import sleep

from requests import Response
from requests.exceptions import HTTPError

from .exceptions import NotValidObjectException, MissingHeaderException

logger = logging.getLogger("LumuDefenderSDK.rate_limit")


class RateLimit(object):
    """
    Class to encapsulate decorator logic
    """

    def __init__(
        self,
        limit_header="X-RateLimit-Limit",
        reset_header="X-RateLimit-Reset",
        remaining_header="X-RateLimit-Remaining",
        percentage=0,
    ) -> None:
        """
        Decorator object to control rate limit in API calls. Assumming reset time in seconds

        :param limit_header: `str` Header name who holds the limit header data
        :param reset_header: `str` Header name who holds the reset time for the rate limit
        :param remaining_header: `str` Header name who holds the remaining requests
        :param percentage: `double` Percentage of remaining requests to be checked and sleep the process
        """
        self.limit_header = limit_header
        self.reset_header = reset_header
        self.remaining_header = remaining_header
        self.percentage = percentage

    def extract_limit_data(self, response: Response) -> tuple:
        """
        Extracts rate limit data based on the provided headers

        :param response: `Response` HTTP response
        :return: `tuple` rate limit, rate reset limit, remaining rate limit
        """
        result_headers = response.headers
        if not all(
            header in result_headers
            for header in [self.limit_header, self.reset_header, self.remaining_header]
        ):
            raise MissingHeaderException("One of the headers is missing")
        rt_limit = int(result_headers[self.limit_header])
        rt_reset = int(result_headers[self.reset_header])
        rt_remaining = int(result_headers[self.remaining_header])

        return rt_limit, rt_reset, rt_remaining

    def __call__(self, func, *args, **kwargs):
        """
        Decorator logic
        """

        def wrapper(*args, **kwargs):
            # Run the function
            try:
                result = func(*args, **kwargs)
                if not isinstance(result, Response):
                    raise NotValidObjectException()
                # Check headers
                rt_limit, rt_reset, rt_remaining = self.extract_limit_data(result)
                if rt_remaining / rt_limit <= self.percentage:
                    logger.warning(
                        f"The rate limit is about to be reached. Sleeping for {rt_reset} seconds"
                    )
                    sleep(rt_reset)
                return result
            except HTTPError as e:
                if e.response.status_code == 429:
                    # Check headers
                    rt_limit, rt_reset, rt_remaining = self.extract_limit_data(
                        e.response
                    )
                    # TODO: Test if the rt_reset greater than 60 applies
                    if rt_remaining > 60:
                        logger.error(
                            f"Maximum limit of requests per day have been reached."
                        )
                        raise
                    logger.warning(
                        f"Rate limit has been reached. Sleeping for {rt_reset} seconds"
                    )
                    sleep(rt_reset)

                return func(*args, **kwargs)

        return wrapper
