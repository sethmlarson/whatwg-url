import whatwg_url


def test_url_scheme():
    url = whatwg_url.parse_url("http://www.google.com:443")
    url.scheme = "https"

    assert url.scheme == "https"
    assert url.port is None
    assert url.href == "https://www.google.com/"

    url.scheme = "http"

    assert url.scheme == "http"
    assert url.port is None
    assert url.href == "http://www.google.com/"


def test_url_host():
    url = whatwg_url.parse_url("https://www.google.com")
    url.hostname = "example.com"

    assert url.hostname == "example.com"
    assert url.href == "https://example.com/"


def test_url_port():
    url = whatwg_url.parse_url("https://www.example.com")
    url.port = 123

    assert url.port == 123
    assert url.host == "www.example.com:123"
    assert url.href == "https://www.example.com:123/"

    url.port = 443

    assert url.port is None
    assert url.host == "www.example.com"
    assert url.href == "https://www.example.com/"


def test_url_user_info():
    url = whatwg_url.parse_url("https://github.com")

    url.username = "username"

    assert url.username == "username"
    assert url.password is None
    assert url.href == "https://username@github.com/"

    url.password = "password"

    assert url.username == "username"
    assert url.password == "password"
    assert url.href == "https://username:password@github.com/"

    url.username = None

    assert url.username is None
    assert url.password == "password"
    assert url.href == "https://:password@github.com/"

    url.password = None

    assert url.username is None
    assert url.password is None
    assert url.href == "https://github.com/"


def test_url_query():
    url = whatwg_url.parse_url("https://www.google.com")
    url.query = "?a=1"

    assert url.query == "a=1"
    assert url.href == "https://www.google.com/?a=1"

    url.query = ""

    assert url.query == ""
    assert url.href == "https://www.google.com/?"

    url.query = None

    assert url.query is None
    assert url.href == "https://www.google.com/"


def test_url_fragment():
    url = whatwg_url.parse_url("https://www.google.com")
    url.fragment = "abc"

    assert url.fragment == "abc"
    assert url.href == "https://www.google.com/#abc"

    url.fragment = ""

    assert url.fragment == ""
    assert url.href == "https://www.google.com/#"

    url.fragment = None

    assert url.fragment is None
    assert url.href == "https://www.google.com/"


def test_url_origin():
    url = whatwg_url.parse_url("https://www.google.com")

    assert url.origin == ("https", "www.google.com", None, None)


def test_url_opaque_origin():
    url = whatwg_url.parse_url("file:///var/tmp/file")

    assert tuple(url.origin) == (None, None, None, None)
    assert not url.origin == url.origin
    assert url.origin != url.origin


def test_url_blob_origin():
    url = whatwg_url.parse_url("blob:https://www.google.com")

    assert url.origin == whatwg_url.parse_url("https://www.google.com").origin
