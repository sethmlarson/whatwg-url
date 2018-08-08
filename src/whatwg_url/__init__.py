from .parser import UrlParser, Url, UrlParserError
from .parseresult import ParseResult

__all__ = [
    "parse_url",
    "normalize_url",
    "is_valid_url",
    "UrlParser",
    "Url",
    "UrlParserError",
    "urlparse",
    "ParseResult",
]
__version__ = "dev"


def parse_url(url: str, base=None, encoding="utf-8") -> Url:
    url = Url()
    if isinstance(base, str):
        base = parse_url(base, encoding=encoding)
    parser = UrlParser(url, base=base, encoding=encoding)
    return parser.parse(data)


def normalize_url(url: str, base=None, encoding="utf-8") -> str:
    return parse_url(url, base=base, encoding=encoding).href


def is_valid_url(url: str, encoding="utf-8") -> bool:
    try:
        parse_url(url)
        return True
    except UrlParserError:
        return False


def urlparse(urldata: str, base=None, encoding="utf-8") -> ParseResult:
    raise NotImplementedError("TODO")
