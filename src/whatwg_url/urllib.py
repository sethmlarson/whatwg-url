import collections
from .parser import UrlParser, Url


class ParseResultMixin(object):
    def geturl(self):
        return self.url.href

    @property
    def username(self):
        if self.url.password:
            return self.url.username or ""
        return self.url.username

    @property
    def password(self):
        return self.url.password

    @property
    def hostname(self):
        return self.url.hostname

    @property
    def port(self):
        return self.url.port


class ParseResult(
    collections.namedtuple(
        "ParseResult", ["scheme", "netloc", "path", "params", "query", "fragment"]
    ),
    ParseResultMixin,
):
    slots = ()

    def __new__(cls, scheme, netloc, path, params, query, fragment, url):
        parse_result = super(ParseResult, cls).__new__(
            cls,
            scheme or "",
            netloc or "",
            path or "",
            params or "",
            query or "",
            fragment or "",
        )
        parse_result.url = url
        return parse_result


def urlparse(urlstring: str, scheme="", allow_fragments=True, encoding="utf-8"):
    parser = UrlParser(Url())
    url = parser.parse(urlstring, encoding=encoding)
    if scheme != "":
        url.scheme = scheme
    if not allow_fragments:
        _add_url_fragment_to_path(url)
    return ParseResult(
        url.scheme, url.authority, url.path, "", url.query, url.fragment, url
    )


def urljoin(base, url, allow_fragments=True, encoding="utf-8"):
    parser = UrlParser(Url())
    url = parser.parse(url, base=base, encoding=encoding)
    if not allow_fragments:
        _add_url_fragment_to_path(url)
    return url.href


def _add_url_fragment_to_path(url):
    if len(url._path):
        url._path[-1] += "#" + url.fragment
    else:
        url._path.append("#" + url.fragment)
    url.fragment = None
