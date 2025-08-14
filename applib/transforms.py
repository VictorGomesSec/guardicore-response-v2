import re
from urllib.parse import urlparse


def transform_domains(domain: str):
    domain_stripped = re.sub(r"^.{1,5}://", "", domain)
    domain_without_at = re.sub(r".+@", ".", domain_stripped).strip(". ")
    return domain_without_at


def transform_ips(ip: str):
    ip_without_mask = ip.split("/")[0]
    return ip_without_mask


def transform_urls(url: str):
    pattern = re.compile(r"^https?://")
    if not pattern.search(url):
        return ""
    clean_url = urlparse(url)._replace(fragment="", query="").geturl()
    return clean_url
