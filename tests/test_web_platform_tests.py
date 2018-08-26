import io
import json
import pytest
import os
import whatwg_url


with io.open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata.json"), "rb"
) as f:
    testdata = f.read()
    if not isinstance(testdata, str):
        testdata = testdata.decode("utf-8")
    testdata = json.loads(testdata, encoding="utf-8")
    testdata = [x for x in testdata if isinstance(x, dict)]


def assert_with_empty(a, b):
    def f(x):
        return "" if x is None else x

    assert f(a) == f(b)


@pytest.mark.parametrize("testdata", testdata)
def test_web_platform_tests(testdata):
    if testdata["input"].startswith("blob:"):
        pytest.skip("blob")

    if "href" in testdata and "about:blank" in testdata["href"]:
        pytest.skip("about:blank")

    base = testdata.get("base", None)
    if base == "about:blank":
        base = None
    else:
        base = whatwg_url.parse_url(base)

    if testdata.get("failure", False):
        with pytest.raises(whatwg_url.UrlParserError):
            whatwg_url.parse_url(testdata["input"], base=base)

    else:
        url = whatwg_url.parse_url(testdata["input"], base=base)

        assert_with_empty(url._username, testdata.get("username", None))
        assert_with_empty(url._password, testdata.get("password", None))
        assert_with_empty(url.path, testdata.get("pathname", None))

        port = testdata.get("port", None)
        if port is not None and port != "":
            port = int(port)
        if port == "":
            port = None

        assert_with_empty(url._port, port)
        assert url.href == testdata.get("href", None)
