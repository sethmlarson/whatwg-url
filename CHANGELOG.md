# Changelog

## Unreleased

### Added

- Added `UrlParser` and `Url`.
- Added `UrlParser.parse_host()`
- Added `UrlParser.parse_ipv4_host()`.
- Added `Url.origin`.
- Added `Url.authority`
- Added `urlparse` and `urljoin` to be compatible with
  [`urllib3.parse.urlparse`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse)
  and [`urllib.parse.urljoin`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urljoin).
- Added support for Python 2.7

### Removed

- Removed dependency on the `attrs` package.
