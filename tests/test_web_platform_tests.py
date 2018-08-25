import json
import pytest
import os
import whatwg_url


with open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata.json"), "rb"
) as f:
    testdata = json.loads(f.read(), encoding="utf-8")
    testdata = [x for x in testdata if isinstance(x, dict)]


def assert_with_empty(a, b):
    def f(x):
        return "" if x is None else x

    assert f(a) == f(b)


@pytest.mark.parametrize("testdata", testdata)
def test_web_platform_tests(testdata):

    print(testdata)

    if testdata["input"].startswith("blob:"):
        pytest.skip("blob")

    if "href" in testdata and "about:blank" in testdata["href"]:
        pytest.skip("about:blank")

    base = testdata.get("base", None)
    if base == "about:blank":
        base = None
    else:
        base = whatwg_url.parse_url(base)
        print(base.href)

    if testdata.get("failure", False):
        with pytest.raises(whatwg_url.UrlParserError):
            whatwg_url.parse_url(testdata["input"], base=base)

    else:
        print("\nREAL VALUES\n")

        url = whatwg_url.parse_url(testdata["input"], base=base)

        print("FINAL URL", str(url))

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
