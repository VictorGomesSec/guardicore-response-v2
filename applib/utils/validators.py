from loguru import logger as _logger
from validators import domain, ipv6, ipv4


def valid_indicator(indicator):
    if any([domain(indicator), ipv4(indicator), ipv6(indicator)]):
        return indicator
    raise ValueError(f"Invalid indicator: {indicator}")


def valid_indicators(indicators):
    for indicator in indicators:
        try:
            yield valid_indicator(indicator)
        except ValueError as e:
            _logger.warning(f"{e}")
