from .parser import UrlParser, Url, UrlParserError

__all__ = ["urlparse", "UrlParser", "Url", "UrlParserError"]
__version__ = 'dev'


def urlparse(data: str, base=None) -> Url:
    url = Url()
    if isinstance(base, str):
        base = urlparse(base)
    parser = UrlParser(url, base=base)
    return parser.parse(data)
