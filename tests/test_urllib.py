import pytest
from whatwg_url import urlparse as whatwg_urlparse, urljoin as whatwg_urljoin

try:
    from urllib.parse import urlparse as urllib_urlparse, urljoin as urllib_urljoin
except ImportError:
    from urlparse import urlparse as urllib_urlparse, urljoin as urllib_urljoin


@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.com/",
        "http://user:pass@www.example.com/",
        "http://:pass@www.example.com/",
        "http://user@www.example.com/",
        "http://www.example.com:432/",
        "http://www.example.com/?a=1;B=c",
        "http://www.example.com/#Fragment",
        "http://username:password@www.example.com:1234/?query=string#fragment",
    ],
)
def test_assert_same_urlparse_result(url):
    urllib_result = urllib_urlparse(url)
    whatwg_result = whatwg_urlparse(url)

    assert urllib_result.netloc == whatwg_result.netloc
    assert urllib_result.hostname == whatwg_result.hostname
    assert urllib_result.port == whatwg_result.port
    assert urllib_result.path == whatwg_result.path
    assert urllib_result.query == whatwg_result.query
    assert urllib_result.fragment == whatwg_result.fragment
    assert urllib_result.username == whatwg_result.username
    assert urllib_result.password == whatwg_result.password
    assert tuple(urllib_result) == tuple(whatwg_result)


@pytest.mark.parametrize(
    ["base", "url", "expected"],
    [
        ("http://www.google.com/", "", "http://www.google.com/"),
        ("http://www.google.com/", "/", "http://www.google.com/"),
        ("http://www.google.com/", "maps/", "http://www.google.com/maps/"),
        ("http://www.google.com/", "one/two/", "http://www.google.com/one/two/"),
        ("http://www.google.com/mail", "/maps/", "http://www.google.com/maps/"),
        ("http://www.google.com/", "./", "http://www.google.com/"),
        ("http://www.google.com/maps", "..", "http://www.google.com/"),
        (
            "http://www.google.com/",
            "https://www.google.com/",
            "https://www.google.com/",
        ),
        (
            "http://www.google.com/",
            "https://maps.google.com/",
            "https://maps.google.com/",
        ),
        (
            "https://www.google.com/",
            "https://www.google.com:1234/",
            "https://www.google.com:1234/",
        ),
        (
            "https://www.google.com/",
            "?query=string",
            "https://www.google.com/?query=string",
        ),
        ("https://www.google.com/", "#fragment", "https://www.google.com/#fragment"),
        (
            "http://www.google.com/",
            "http://user:pass@www.google.com/",
            "http://user:pass@www.google.com/",
        ),
        (
            "http://www.google.com/",
            "http://user@www.google.com/",
            "http://user@www.google.com/",
        ),
        (
            "http://www.google.com/",
            "http://:pass@www.google.com/",
            "http://:pass@www.google.com/",
        ),
    ],
)
def test_assert_same_urljoin_result(base, url, expected):
    urllib_result = urllib_urljoin(base, url)
    whatwg_result = whatwg_urljoin(base, url)

    assert urllib_result == expected
    assert whatwg_result == expected
