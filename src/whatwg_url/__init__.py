from .parser import UrlParser, Url, UrlParserError, OPAQUE_ORIGIN
from .urllib import urlparse, urljoin

__all__ = [
    "parse_url",
    "normalize_url",
    "is_valid_url",
    "UrlParser",
    "Url",
    "UrlParserError",
    "OPAQUE_ORIGIN",
    "urlparse",
    "urljoin",
]
__version__ = "dev"


def parse_url(url: str, base=None, encoding="utf-8") -> Url:
    parser = UrlParser()
    return parser.parse(url, base=base, encoding=encoding)


def normalize_url(url: str, base=None, encoding="utf-8") -> str:
    return parse_url(url, base=base, encoding=encoding).href


def is_valid_url(url: str, encoding="utf-8") -> bool:
    try:
        parse_url(url, encoding=encoding)
        return True
    except UrlParserError:
        return False
