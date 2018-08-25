# -*- coding: utf-8 -*-
# Source for these URLs:
# https://www.blackhat.com/docs/us-17/thursday/
# us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-
# Parser-In-Trending-Programming-Languages.pdf

import pytest
import whatwg_url


def test_spaces_with_multiple_ipv4_addresses():
    url = whatwg_url.parse_url("http://1.1.1.1 &@2.2.2.2# @3.3.3.3")

    assert url.username == "1.1.1.1%20&"
    assert url.password is None
    assert url.hostname == "2.2.2.2"
    assert url.fragment == "%20@3.3.3.3"


def test_fragment_with_hostname():
    url = whatwg_url.parse_url("http://google.com#@evil.com/")

    assert url.hostname == "google.com"
    assert url.fragment == "@evil.com/"


def test_multiple_ats_within_authority():
    url = whatwg_url.parse_url("http://foo@evil.com:80@google.com/")

    assert url.hostname == "google.com"
    assert url.username == "foo%40evil.com"
    assert url.password == "80"


def test_multiple_ats_and_space_within_authority():
    url = whatwg_url.parse_url("http://foo@evil.com:80 @google.com/")

    assert url.hostname == "google.com"
    assert url.username == "foo%40evil.com"
    assert url.password == "80%20"


def test_unicode_double_dot_if_stripped_bom():
    url = whatwg_url.parse_url("http://orange.tw/sandbox/ＮＮ/passwd")

    assert url.hostname == "orange.tw"
    assert url.path == "/sandbox/%EF%BC%AE%EF%BC%AE/passwd"


def test_host_contains_tab_in_authority():
    url = whatwg_url.parse_url("http://127.0.0.1\tfoo.google.com")

    assert url.host == "127.0.0.1foo.google.com"


def test_host_contains_tab_in_authority_single_or_double_encoded():
    with pytest.raises(whatwg_url.UrlParserError):
        whatwg_url.parse_url("http://127.0.0.1%09foo.google.com")

    with pytest.raises(whatwg_url.UrlParserError):
        whatwg_url.parse_url("http://127.0.0.1%2509foo.google.com")


def test_injection_within_authority():
    with pytest.raises(whatwg_url.UrlParserError):
        whatwg_url.parse_url("https://127.0.0.1\r\nSET foo 0 60 5\r\n:443/")


def test_backslash_within_authority():
    url = whatwg_url.parse_url("http://localhost\\@google.com:12345")

    assert url.hostname == "localhost"
    assert url.port is None
    assert url.path == "/@google.com:12345"


def test_relative_url_with_url_contained():
    url = whatwg_url.parse_url(
        url="/redirect?target=http://localhost:61020/", base="https://www.google.com"
    )

    assert url.scheme == "https"
    assert url.hostname == "www.google.com"
    assert url.path == "/redirect"
    assert url.query == "target=http://localhost:61020/"
