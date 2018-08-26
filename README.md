# whatwg-url

[![Travis](https://img.shields.io/travis/SethMichaelLarson/whatwg-url/master.svg)](https://travis-ci.org/SethMichaelLarson/whatwg-url)
[![Codecov](https://img.shields.io/codecov/c/github/SethMichaelLarson/whatwg-url/master.svg)](https://codecov.io/gh/SethMichaelLarson/whatwg-url)
[![PyPI](https://badge.fury.io/py/whatwg-url.svg)](https://pypi.org/project/whatwg-url)

Python implementation of the [WHATWG URL Living Standard](https://url.spec.whatwg.org/).

The latest revision that this package implements of the standard is August 7th, 2018 ([`commit 49060c7`](https://github.com/whatwg/url/commit/49060c74d3047602a572f9e88a6a1101f4fd32f3))

## Getting Started

Install the `whatwg-url` package using `pip`.

`python -m pip install whatwg-url`

And use the module like so:

```python
import whatwg_url

url = whatwg_url.parse_url("https://www.google.com")
print(url)
# Url(scheme='https', hostname='www.google.com', port=None, path='', query='', fragment='')
```

## Features

### Compatibility with `urllib.parse.urlparse()`

```python
import whatwg_url

parseresult = whatwg_url.urlparse("https://seth:larson@www.google.com:1234/maps?query=string#fragment")

print(parseresult.scheme)  # 'https'
print(parseresult.netloc)  # 'www.google.com:1234'
print(parseresult.userinfo)  # 'seth:larson'
print(parseresult.path)  # '/maps'
print(parseresult.params)  # ''
print(parseresult.query)  # 'query=string'
print(parseresult.fragment)  # 'fragment'
print(parseresult.username)  # 'seth'
print(parseresult.password)  # 'larson'
print(parseresult.hostname)  # 'www.google.com'
print(parseresult.port)  # 1234
print(parseresult.geturl())  # 'https://seth:larson@www.google.com:1234/maps?query=string#fragment'
```

### URL Normalization

The WHATWG URL specification describes methods of normalizing URL inputs to usable URLs.
It handles percent-encodings, default ports, paths, IPv4 and IPv6 addresses, IDNA (2008 and 2003), multiple slashes after scheme, etc.

```python
import whatwg_url

print(whatwg_url.normalize_url("https://////www.google.com"))  # https://www.google.com
print(whatwg_url.normalize_url("https://www.google.com/dir1/../dir2"))  # https://www.google.com/dir2
print(whatwg_url.normalize_url("https://你好你好"))  # https://xn--6qqa088eba/
print(whatwg_url.normalize_url("https://０Ｘｃ０．０２５０．０１"))  # https://192.168.0.1/
```

### URL Validation

```python
print(whatwg_url.is_valid_url("https://www.google.com"))  # True
print(whatwg_url.is_valid_url("https://www .google.com"))  # False
```

### Relative URLs

HTTP redirects often contain relative URLs (via the `Location` header) that need to be applied to the current URL location.
Specifying the `base` parameter allows for giving relative URLs as input and the changes be applied to a new `URL` object.

```python
import whatwg_url

url = whatwg_url.parse_url("../dev?a=1#f", base="https://www.google.com/maps")
print(url.href)  # https://www.google.com/dev?a=1#f
```

### URL Property Mutators

Modifying properties on a `URL` object use the parser and "state overrides" to properly mutate the `URL` object.

```python
url = whatwg_url.parse_url("http://www.google.com:443")

print(url.scheme)  # 'http'
print(url.port)  # 443

url.scheme = 'https'

print(url.scheme)  # 'https'
print(url.port)  # None
```

### "Splatable"

The module is a single file which allows for easy vendoring into projects.

## License

[Apache-2.0](https://github.com/SethMichaelLarson/whatwg-url/blob/master/LICENSE)
