"""Python implementation of the WHATWG URL Living Standard"""

import string
import re
import ipaddress
import collections
import encodings.idna as idna2003
import idna
import six


__all__ = [
    "parse_url",
    "normalize_url",
    "is_valid_url",
    "UrlParser",
    "Url",
    "UrlParserError",
    "urlparse",
    "urljoin",
    "ParseResult",
]
__version__ = "2018.8.26"
__license__ = "Apache-2.0"


def parse_url(url, base=None, encoding="utf-8"):
    """
    Parses a URL from a string input with an optional base URL.
    If the input URL is a relative URL then it will be parsed as
    relative to the base URL.

    :param str url: URL input string
    :param str base: Optional base URL to use while parsing.
    :param encoding: Character encoding to use for parsing the URL, defaults to UTF-8.
    :rtype: Url
    :raises: UrlParserError
    :return: The parsed URL.
    """
    parser = UrlParser()
    return parser.parse(url, base=base, encoding=encoding)


def normalize_url(url, base=None, encoding="utf-8"):
    """Normalizes a URL input with and optional base URL.

    :param str url: URL input to normalize.
    :param str base: Optional base URL to parse relative to.
    :param str encoding: Character encoding to parse with. Defaults to UTF-8.
    :rtype
    :raises: UrlParserError
    :return: The normalized URL as a string.
    """
    return parse_url(url, base=base, encoding=encoding).href


def is_valid_url(url, base=None, encoding="utf-8"):
    """Determines if a URL is a valid URL.

    :param str url: URL input to validate
    :param str base: Optional base URL to parse relative to.
    :param str encoding: Character encoding to parse with. Defaults to UTF-8.
    :rtype: bool
    :return: True if the given URL is a valid URL, False otherwise.
    """
    try:
        parse_url(url, base=base, encoding=encoding)
        return True
    except UrlParserError:
        return False


class _OpaqueOrigin(tuple):
    def __eq__(self, _):
        return False

    def __ne__(self, _):
        return True


def b(x, encoding="ascii"):
    if isinstance(x, six.text_type):
        return x.encode(encoding)
    return x


ASCII_ALPHA = set(string.ascii_letters)
ASCII_DIGITS = set(string.digits)
ASCII_ALPHANUMERIC = ASCII_ALPHA | ASCII_DIGITS
TWO_ASCII_HEX = re.compile(r"^[a-fA-F0-9]{2}")
URL_CODEPOINTS = ASCII_ALPHANUMERIC | set("!$&'()*+,-./:;=?@_~")
SCHEME_CHARS = ASCII_ALPHANUMERIC | set("+-.")
NONCHARACTERS = {
    0xfdd0,
    0xfdd1,
    0xfdd2,
    0xfdd3,
    0xfdd4,
    0xfdd5,
    0xfdd6,
    0xfdd7,
    0xfdd8,
    0xfdd9,
    0xfdda,
    0xfddb,
    0xfddc,
    0xfddd,
    0xfdde,
    0xfddf,
    0xfde0,
    0xfde1,
    0xfde2,
    0xfde3,
    0xfde4,
    0xfde5,
    0xfde6,
    0xfde7,
    0xfde8,
    0xfde9,
    0xfdea,
    0xfdeb,
    0xfdec,
    0xfded,
    0xfdee,
    0xfdef,
    0xfffe,
    0xffff,
    0x1fffe,
    0x1ffff,
    0x2fffe,
    0x2ffff,
    0x3fffe,
    0x3ffff,
    0x4fffe,
    0x4ffff,
    0x5fffe,
    0x5ffff,
    0x6fffe,
    0x6ffff,
    0x7fffe,
    0x7ffff,
    0x8fffe,
    0x8ffff,
    0x9fffe,
    0x9ffff,
    0xafffe,
    0xaffff,
    0xbfffe,
    0xbffff,
    0xcfffe,
    0xcffff,
    0xdfffe,
    0xdffff,
    0xefffe,
    0xeffff,
    0xffffe,
    0xfffff,
    0x10fffe,
    0x10ffff,
}

SINGLE_DOT_PATH_SEGMENTS = {".", "%2e", "%2E"}
DOUBLE_DOT_PATH_SEGMENTS = {
    "..",
    ".%2e",
    ".%2E",
    "%2e.",
    "%2e%2e",
    "%2e%2E",
    "%2E.",
    "%2E%2e",
    "%2E%2E",
}

C0_PERCENT_ENCODE = set([chr(x) for x in range(0x20)])
FRAGMENT_PERCENT_ENCODE = set(' "<>`') | C0_PERCENT_ENCODE
PATH_PERCENT_ENCODE = set("#?{}") | FRAGMENT_PERCENT_ENCODE
USERINFO_PERCENT_ENCODE = set("/:;=@[\\]^|") | PATH_PERCENT_ENCODE

FORBIDDEN_HOST_CODE_POINTS = {
    "\x00",
    "\t",
    "\x0a",
    "\x0d",
    " ",
    "#",
    "%",
    "/",
    ":",
    "?",
    "@",
    "[",
    "\\",
    "]",
}

WINDOWS_DRIVE_LETTER = re.compile(r"^([a-zA-Z][:|])(?:[/\\?#]|$)")
NORMALIZED_WINDOWS_DRIVE_LETTER = re.compile(r"^[a-zA-Z][:]$")

AUTHORITY_DELIMITERS = {"", "/", "?", "#"}
PATH_DELIMITERS = {"", "/", "\\", "?", "#"}

HEX_CHAR_MAP = dict(
    [
        (b(_x + _y), b(chr(int(_x + _y, 16)), "charmap"))
        for _x in string.hexdigits
        for _y in string.hexdigits
    ]
)

IDNA_DOTS_REGEX = re.compile(u"[\u002e\u3002\uff0e\uff61]")


SPECIAL_SCHEMES = {
    "ftp": 21,
    "gopher": 70,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "file": None,
}


PARSER_STATE_SCHEME_START = 1
PARSER_STATE_SCHEME = 2
PARSER_STATE_NO_SCHEME = 3
PARSER_STATE_SPECIAL_RELATIVE_OR_AUTHORITY = 4
PARSER_STATE_PATH_OR_AUTHORITY = 5
PARSER_STATE_RELATIVE = 6
PARSER_STATE_RELATIVE_SLASH = 7
PARSER_STATE_SPECIAL_AUTHORITY_SLASHES = 8
PARSER_STATE_SPECIAL_AUTHORITY_IGNORE_SLASHES = 9
PARSER_STATE_AUTHORITY = 10
PARSER_STATE_HOST = 11
PARSER_STATE_HOSTNAME = 12
PARSER_STATE_PORT = 13
PARSER_STATE_FILE = 14
PARSER_STATE_FILE_SLASH = 15
PARSER_STATE_FILE_HOST = 16
PARSER_STATE_PATH_START = 17
PARSER_STATE_PATH = 18
PARSER_STATE_CANNOT_BE_BASE_URL = 19
PARSER_STATE_QUERY = 20
PARSER_STATE_FRAGMENT = 21


class UrlParserError(ValueError):
    pass


class _UrlParserReturn(Exception):
    pass


class Url(object):
    def __init__(
        self,
        scheme=None,
        hostname=None,
        port=None,
        username=None,
        password=None,
        query=None,
        fragment=None,
        path=None,
        cannot_be_base_url=False,
        encoding="utf-8",
    ):
        if path is None:
            path = []

        self._scheme = scheme
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._query = query
        self._fragment = fragment
        self._path = path

        self.encoding = encoding
        self.cannot_be_base_url = cannot_be_base_url

    @property
    def scheme(self):
        return self._scheme

    @property
    def hostname(self):
        return self._hostname

    @property
    def port(self):
        return self._port

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def query(self):
        return self._query

    @property
    def fragment(self):
        return self._fragment

    @property
    def host(self):
        if self._port is None:
            return self._hostname
        return "%s:%s" % (self._hostname, self._port)

    @property
    def path(self):
        if self.cannot_be_base_url:
            return self._path[0]
        else:
            return "".join(["/%s" % x for x in self._path])

    @scheme.setter
    def scheme(self, scheme):
        parser = UrlParser(self)
        parser.parse(
            scheme + ":",
            encoding=self.encoding,
            state_override=PARSER_STATE_SCHEME_START,
        )

    @username.setter
    def username(self, username):
        self._username = username

    @password.setter
    def password(self, password):
        self._password = password

    @hostname.setter
    def hostname(self, hostname):
        parser = UrlParser(self)
        parser.parse(
            hostname, encoding=self.encoding, state_override=PARSER_STATE_HOSTNAME
        )

    @port.setter
    def port(self, port):
        parser = UrlParser(self)
        parser.parse(str(port), state_override=PARSER_STATE_PORT)

    @path.setter
    def path(self, path):
        if self.cannot_be_base_url:
            return

        self._path = []
        parser = UrlParser(self)
        parser.parse(path, state_override=PARSER_STATE_PATH_START)

    @query.setter
    def query(self, query):
        if query is None:
            self._query = None
            return

        if query.startswith("?"):
            query = query[1:]

        self._query = ""
        parser = UrlParser(self)
        parser.parse(query, encoding=self.encoding, state_override=PARSER_STATE_QUERY)

    @fragment.setter
    def fragment(self, fragment):
        if fragment is None:
            self._fragment = None
            return

        if fragment.startswith("#"):
            fragment = fragment[1:]

        self._fragment = ""
        parser = UrlParser(self)
        parser.parse(
            fragment, encoding=self.encoding, state_override=PARSER_STATE_FRAGMENT
        )

    @property
    def includes_credentials(self):
        """Determines if a URL includes credentials"""
        return bool(self._username) or bool(self._password)

    @property
    def origin(self):
        if self.scheme == "blob":
            try:
                url = parse_url(self._path[0], encoding=self.encoding)
            except UrlParserError:
                return _OpaqueOrigin((None, None, None, None))
            return url.origin

        elif self.scheme in SPECIAL_SCHEMES and self.scheme != "file":
            return self.scheme, self.hostname, self.port, None

        else:
            return _OpaqueOrigin((None, None, None, None))

    @property
    def authority(self):
        output = []
        if self.includes_credentials:
            if self._username:
                output.append(self._username)
            if self._password:
                output.append(":" + self._password)
            output.append("@")

        output.append(self._hostname)
        if self._port is not None:
            output.append(":%s" % self._port)
        return "".join(output)

    @property
    def href(self):
        output = [self._scheme + ":"]
        if self._hostname is not None:
            output.append("//")

            if self.includes_credentials:
                if self._username:
                    output.append(self._username)
                if self._password:
                    output.append(":" + self._password)
                output.append("@")

            output.append(self._hostname)
            if self._port is not None:
                output.append(":%s" % self._port)

        if self._hostname is None and self._scheme == "file":
            output.append("//")

        if self.cannot_be_base_url:
            output.append(self._path[0])
        else:
            output.append(self.path)

        if self._query is not None:
            output.append("?" + self._query)

        if self._fragment is not None:
            output.append("#" + self._fragment)

        return "".join(output)

    def __repr__(self):
        return ("<%s scheme=%r hostname=%r port=%r path=%r query=%r fragment=%r>") % (
            self.__class__.__name__,
            self._scheme,
            self._hostname,
            self._port,
            self.path,
            self._query,
            self._fragment,
        )

    def __str__(self):
        return self.href


class UrlParser(object):
    def __init__(self, url=None):
        if url is None:
            url = Url()

        self.url = url
        self.base = None
        self.state_override = None
        self.validation_error = False

        self._state = None
        self._pointer = 0
        self._buffer = ""
        self._at_flag = False
        self._square_brace_flag = False
        self._password_token_seen_flag = False

        self._state_handlers = {
            PARSER_STATE_SCHEME_START: self._on_scheme_start,
            PARSER_STATE_SCHEME: self._on_scheme,
            PARSER_STATE_NO_SCHEME: self._on_no_scheme,
            PARSER_STATE_SPECIAL_RELATIVE_OR_AUTHORITY: (
                self._on_special_relative_or_authority
            ),
            PARSER_STATE_PATH_OR_AUTHORITY: self._on_path_or_authority,
            PARSER_STATE_RELATIVE: self._on_relative,
            PARSER_STATE_RELATIVE_SLASH: self._on_relative_slash,
            PARSER_STATE_SPECIAL_AUTHORITY_SLASHES: self._on_special_authority_slashes,
            PARSER_STATE_SPECIAL_AUTHORITY_IGNORE_SLASHES: (
                self._on_special_authority_ignore_slashes
            ),
            PARSER_STATE_AUTHORITY: self._on_authority,
            PARSER_STATE_HOST: self._on_host_or_hostname,
            PARSER_STATE_HOSTNAME: self._on_host_or_hostname,
            PARSER_STATE_PORT: self._on_port,
            PARSER_STATE_FILE: self._on_file,
            PARSER_STATE_FILE_SLASH: self._on_file_slash,
            PARSER_STATE_FILE_HOST: self._on_file_host,
            PARSER_STATE_PATH_START: self._on_path_start,
            PARSER_STATE_PATH: self._on_path,
            PARSER_STATE_CANNOT_BE_BASE_URL: self._on_cannot_be_base_url,
            PARSER_STATE_QUERY: self._on_query,
            PARSER_STATE_FRAGMENT: self._on_fragment,
        }

    def parse(self, data, base=None, encoding=None, state_override=None):
        self.reset()

        if isinstance(base, str):
            base_parser = UrlParser()
            base = base_parser.parse(base, encoding=encoding)
        self.base = base

        self.state_override = state_override
        self._state = state_override or PARSER_STATE_SCHEME_START

        if encoding is None:
            self.encoding = self.url.encoding or "utf-8"
        else:
            self.encoding = encoding

        self.url.encoding = self.encoding

        while data and _is_c0_control_or_space(data[0]):
            self.validation_error = True
            data = data[1:]

        while data and _is_c0_control_or_space(data[-1]):
            self.validation_error = True
            data = data[:-1]

        before_len = len(data)
        data = data.replace("\t", "").replace("\n", "").replace("\r", "")

        if len(data) < before_len:
            self.validation_error = True

        try:
            end_pointer = len(data)

            while self._pointer < end_pointer or (
                end_pointer == 0 and self._pointer == 0
            ):
                if end_pointer > 0:
                    self._call_state_handler(
                        self._state, data[self._pointer], data[self._pointer + 1 :]
                    )

                while self._pointer == end_pointer:
                    self._call_state_handler(self._state, "", "")

        except _UrlParserReturn:
            pass

        return self.url

    def _call_state_handler(self, state, c, remaining):
        self._state_handlers[state](c, remaining)
        self._pointer += 1

    def parse_host(self, host, is_not_special=False):
        # IPv6 parsing
        if host.startswith("["):
            if not host.endswith("]"):
                self.validation_error = True
                raise UrlParserError()

            try:
                return "[%s]" % ipaddress.IPv6Address(host[1:-1])
            except ipaddress.AddressValueError:
                raise UrlParserError()

        # Opaque-host parsing
        if is_not_special:
            codepoints = set(host)
            if "%" in codepoints:
                codepoints.remove("%")
            if codepoints.intersection(FORBIDDEN_HOST_CODE_POINTS):
                self.validation_error = True
                raise UrlParserError()

            return "".join([_percent_encode(c, C0_PERCENT_ENCODE) for c in host])

        try:
            domain = _string_percent_decode(host).decode("utf-8")
        except UnicodeDecodeError:
            raise UrlParserError()

        try:
            ascii_domain = _domain_to_ascii(domain).decode("utf-8").lower()
        except (idna.IDNAError, UnicodeError) as e:
            self.validation_error = True
            raise UrlParserError()

        # Contains forbidden host codepoint
        if set(ascii_domain).intersection(FORBIDDEN_HOST_CODE_POINTS):
            raise UrlParserError()

        # IPv4 parsing
        return self.parse_ipv4_host(ascii_domain)

    def parse_ipv4_host(self, ascii_domain):
        """Attempts to parse a domain as an IPv4 address with
        a lot of parsing rules for decimal, octal, hex, different
        numbers of separators, etc.
        """
        parts = ascii_domain.split(".")

        if parts[-1] == "":
            self.validation_error = True
            if len(parts) > 1:
                parts.pop(-1)

        if len(parts) > 4:
            return ascii_domain

        numbers = []
        for part in parts:
            if part == "":
                return ascii_domain

            n, flag = _parse_ipv4_number(part)
            if n is None:
                return ascii_domain

            numbers.append(n)

        for i, number in enumerate(numbers):
            if number > 255:
                self.validation_error = True
                if i < len(numbers) - 1:
                    raise UrlParserError()

        if numbers[-1] >= 256 ** (5 - len(numbers)):
            self.validation_error = True
            raise UrlParserError()

        ipv4 = numbers.pop(-1)
        for i, number in enumerate(numbers):
            ipv4 += number * (256 ** (3 - i))

        output = []
        for _ in range(4):
            output.insert(0, str(ipv4 % 256))
            ipv4 //= 256

        return ".".join(output)

    def reset(self):
        self.validation_error = False
        self._pointer = 0
        self._buffer = ""
        self._at_flag = False
        self._square_brace_flag = False
        self._password_token_seen_flag = False

    def shorten_url_path(self):
        path_len = len(self.url._path)
        if path_len == 0:
            return
        if (
            self.url.scheme == "file"
            and path_len == 1
            and NORMALIZED_WINDOWS_DRIVE_LETTER.match(self.url._path[0]) is not None
        ):
            return
        self.url._path.pop(-1)

    def _on_scheme_start(self, c, _):
        """Handles the START SCHEME state."""
        if c in ASCII_ALPHA:
            self._buffer += c.lower()
            self._state = PARSER_STATE_SCHEME

        elif self.state_override is None:
            self._state = PARSER_STATE_NO_SCHEME
            self._pointer -= 1

        else:
            self.validation_error = True
            raise UrlParserError()

    def _on_scheme(self, c, remaining):
        """Handles the SCHEME state."""
        if c in SCHEME_CHARS:
            self._buffer += c.lower()

        elif c == ":":
            if self.state_override is not None:
                if (self._buffer in SPECIAL_SCHEMES) != (
                    self.url.scheme in SPECIAL_SCHEMES
                ):
                    raise _UrlParserReturn()

                elif (
                    self.url.includes_credentials or self.url.port is not None
                ) and self._buffer == "file":
                    raise _UrlParserReturn()

                elif self.url.scheme == "file" and (
                    self.url.hostname is None or self.url.hostname == ""
                ):
                    raise _UrlParserReturn()

            self.url._scheme = self._buffer

            if self.state_override is not None:
                if (
                    self.url.scheme in SPECIAL_SCHEMES
                    and SPECIAL_SCHEMES[self.url.scheme] == self.url.port
                ):
                    self.url._port = None
                raise _UrlParserReturn()

            self._buffer = ""

            if self.url.scheme == "file":
                if not remaining.startswith("//"):
                    self.validation_error = True
                self._state = PARSER_STATE_FILE

            elif (
                self.url.scheme in SPECIAL_SCHEMES
                and self.base is not None
                and self.base.scheme == self.url.scheme
            ):
                self._state = PARSER_STATE_SPECIAL_RELATIVE_OR_AUTHORITY

            elif self.url.scheme in SPECIAL_SCHEMES:
                self._state = PARSER_STATE_SPECIAL_AUTHORITY_SLASHES

            elif remaining.startswith("/"):
                self._state = PARSER_STATE_PATH_OR_AUTHORITY
                self._pointer += 1

            else:
                self.url.cannot_be_base_url = True
                self.url._path.append("")
                self._state = PARSER_STATE_CANNOT_BE_BASE_URL

        elif self.state_override is None:
            self._buffer = ""
            self._state = PARSER_STATE_NO_SCHEME
            self._pointer = -1

        else:
            self.validation_error = True
            raise UrlParserError()

    def _on_no_scheme(self, c, _):
        """Handles the NO SCHEME state"""
        if self.base is None or (self.base.cannot_be_base_url and c != "#"):
            self.validation_error = True
            raise UrlParserError()

        elif self.base.cannot_be_base_url and c == "#":
            self.url._scheme = self.base.scheme
            self.url._path = self.base._path[:]
            self.url._query = self.base.query
            self.url._fragment = ""
            self.url.cannot_be_base_url = True
            self._state = PARSER_STATE_FRAGMENT

        elif self.base.scheme != "file":
            self._state = PARSER_STATE_RELATIVE
            self._pointer -= 1

        else:
            self._state = PARSER_STATE_FILE
            self._pointer -= 1

    def _on_special_relative_or_authority(self, c, remaining):
        """Handles the SPECIAL RELATIVE OR AUTHORITY state"""
        if c == "/" and remaining.startswith("/"):
            self._state = PARSER_STATE_SPECIAL_AUTHORITY_IGNORE_SLASHES
            self._pointer += 1

        else:
            self.validation_error = True
            self._state = PARSER_STATE_RELATIVE
            self._pointer -= 1

    def _on_path_or_authority(self, c, _):
        """Handles the PATH OR AUTHORITY state"""
        if c == "/":
            self._state = PARSER_STATE_AUTHORITY
        else:
            self._state = PARSER_STATE_PATH
            self._pointer -= 1

    def _on_relative(self, c, _):
        """Handles the RELATIVE state"""
        self.url._scheme = self.base.scheme

        if c == "":
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port
            self.url._path = self.base._path[:]
            self.url._query = self.base.query

        elif c == "/":
            self._state = PARSER_STATE_RELATIVE_SLASH

        elif c == "?":
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port
            self.url._path = self.base._path[:]
            self.url._query = ""

            self._state = PARSER_STATE_QUERY

        elif c == "#":
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port
            self.url._path = self.base._path[:]
            self.url._query = self.base.query
            self.url._fragment = ""

            self._state = PARSER_STATE_FRAGMENT

        else:
            if self.url.scheme in SPECIAL_SCHEMES and c == "\\":
                self.validation_error = True
                self._state = PARSER_STATE_RELATIVE_SLASH

            else:
                self.url._username = self.base.username
                self.url._password = self.base.password
                self.url._hostname = self.base.hostname
                self.url._port = self.base.port
                self.url._path = self.base._path[:]

                if len(self.url._path):
                    self.url._path.pop(-1)

                self._state = PARSER_STATE_PATH
                self._pointer -= 1

    def _on_relative_slash(self, c, _):
        if self.url.scheme in SPECIAL_SCHEMES and (c == "/" or c == "\\"):
            if c == "\\":
                self.validation_error = True
            self._state = PARSER_STATE_SPECIAL_AUTHORITY_IGNORE_SLASHES

        elif c == "/":
            self._state = PARSER_STATE_AUTHORITY

        else:
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port

            self._pointer -= 1
            self._state = PARSER_STATE_PATH

    def _on_special_authority_slashes(self, c, remaining):
        """Handles the SPECIAL AUTHORITY SLASHES state"""
        if c == "/" and remaining.startswith("/"):
            self._state = PARSER_STATE_SPECIAL_AUTHORITY_IGNORE_SLASHES
            self._pointer += 1

        else:
            self.validation_error = True
            self._state = PARSER_STATE_SPECIAL_AUTHORITY_IGNORE_SLASHES
            self._pointer -= 1

    def _on_special_authority_ignore_slashes(self, c, _):
        """Handles the SPECIAL AUTHORITY IGNORE SLASHES state"""
        if c != "/" and c != "\\":
            self._state = PARSER_STATE_AUTHORITY
            self._pointer -= 1

        else:
            self.validation_error = True

    def _on_authority(self, c, _):
        """Handles the AUTHORITY state"""
        if c == "@":
            self.validation_error = True

            if self._at_flag:
                self._buffer = "%40" + self._buffer

            self._at_flag = True

            for char in self._buffer:
                if not self._password_token_seen_flag and char == ":":
                    self._password_token_seen_flag = True
                    continue

                if self._password_token_seen_flag:
                    if self.url.password is None:
                        self.url._password = ""
                    self.url._password += _percent_encode(char, USERINFO_PERCENT_ENCODE)
                else:
                    if self.url.username is None:
                        self.url._username = ""
                    self.url._username += _percent_encode(char, USERINFO_PERCENT_ENCODE)

            self._buffer = ""

        elif c in AUTHORITY_DELIMITERS or (
            self.url.scheme in SPECIAL_SCHEMES and c == "\\"
        ):
            if self._at_flag and self._buffer == "":
                self.validation_error = True
                raise UrlParserError()

            self._pointer -= len(self._buffer) + 1
            self._buffer = ""
            self._state = PARSER_STATE_HOST

        else:
            self._buffer += c

    def _on_host_or_hostname(self, c, _):
        """Handles the HOST and HOSTNAME states"""
        if self.state_override is not None and self.url.scheme == "file":
            self._pointer -= 1
            self._state = PARSER_STATE_FILE_HOST

        elif c == ":" and not self._square_brace_flag:
            if self._buffer == "":
                self.validation_error = True
                raise UrlParserError()

            self.url._hostname = self.parse_host(
                self._buffer, self.url.scheme not in SPECIAL_SCHEMES
            )
            self._buffer = ""
            self._state = PARSER_STATE_PORT

            if self.state_override == PARSER_STATE_HOSTNAME:
                raise _UrlParserReturn()

        elif c in AUTHORITY_DELIMITERS or (
            c == "\\" and self.url.scheme in SPECIAL_SCHEMES
        ):
            self._pointer -= 1

            if self.url.scheme in SPECIAL_SCHEMES and self._buffer == "":
                self.validation_error = True
                raise UrlParserError()

            elif (
                self.state_override is not None
                and self._buffer == ""
                and (self.url.includes_credentials or self.url.port is not None)
            ):
                self.validation_error = True
                raise _UrlParserReturn()

            self.url._hostname = self.parse_host(
                self._buffer, self.url.scheme not in SPECIAL_SCHEMES
            )

            self._buffer = ""
            self._state = PARSER_STATE_PATH_START

            if self.state_override is not None:
                raise _UrlParserReturn()

        else:
            if c == "[":
                self._square_brace_flag = True
            elif c == "]":
                self._square_brace_flag = False
            self._buffer += c

    def _on_port(self, c, _):
        """Handles the PORT state"""
        if c in ASCII_DIGITS:
            self._buffer += c

        elif (
            c in PATH_DELIMITERS
            or (c == "\\" and self.url.scheme in SPECIAL_SCHEMES)
            or self.state_override is not None
        ):
            if self._buffer != "":
                try:
                    port = int(self._buffer)
                except ValueError as e:
                    six.raise_from(UrlParserError(), e)

                if port > 2 ** 16 - 1:
                    self.validation_error = True
                    raise UrlParserError()

                self.url._port = (
                    None if port == SPECIAL_SCHEMES.get(self.url.scheme, None) else port
                )
                self._buffer = ""

            if self.state_override:
                raise _UrlParserReturn()

            self._state = PARSER_STATE_PATH_START
            self._pointer -= 1

        else:
            self.validation_error = True
            raise UrlParserError()

    def _on_file(self, c, remaining):
        """Handles the FILE state"""
        self.url._scheme = "file"

        if c == "/" or c == "\\":
            if c == "\\":
                self.validation_error = True
            self._state = PARSER_STATE_FILE_SLASH

        elif self.base is not None and self.base.scheme == "file":
            if c == "":
                self.url._hostname = self.base.hostname
                self.url._path = self.base._path[:]
                self.url._query = self.base.query

            elif c == "?":
                self.url._hostname = self.base.hostname
                self.url._path = self.base._path[:]
                self.url._query = ""

                self._state = PARSER_STATE_QUERY

            elif c == "#":
                self.url._hostname = self.base.hostname
                self.url._path = self.base._path[:]
                self.url._query = self.base.query
                self.url._fragment = ""

                self._state = PARSER_STATE_FRAGMENT

            else:
                match = WINDOWS_DRIVE_LETTER.search(c + remaining)
                if match is None:
                    self.url._hostname = self.base.hostname
                    self.url._path = self.base._path[:]
                    self.shorten_url_path()

                else:
                    self.validation_error = True

                self._state = PARSER_STATE_PATH
                self._pointer -= 1

        else:
            self._state = PARSER_STATE_PATH
            self._pointer -= 1

    def _on_file_slash(self, c, remaining):
        """Handles the FILE SLASH state"""
        if c == "/" or c == "\\":
            if c == "\\":
                self.validation_error = True
            self._state = PARSER_STATE_FILE_HOST

        else:
            if (
                self.base is not None
                and self.base.scheme == "file"
                and WINDOWS_DRIVE_LETTER.search(c + remaining) is None
            ):
                if (
                    len(self.base._path) > 0
                    and NORMALIZED_WINDOWS_DRIVE_LETTER.match(self.base._path[0])
                    is not None
                ):
                    self.url._path.append(self.base._path[0])

                else:
                    self.url._hostname = self.base.hostname

            self._state = PARSER_STATE_PATH
            self._pointer -= 1

    def _on_file_host(self, c, _):
        """Handles the FILE HOST state"""
        if c in PATH_DELIMITERS:
            self._pointer -= 1

            if (
                self.state_override is None
                and WINDOWS_DRIVE_LETTER.match(self._buffer) is not None
            ):
                self.validation_error = True
                self._state = PARSER_STATE_PATH

            elif self._buffer == "":
                self.url._hostname = ""

                if self.state_override is not None:
                    raise _UrlParserReturn()

                self._state = PARSER_STATE_PATH_START

            else:
                self.url._hostname = self.parse_host(
                    self._buffer, self.url.scheme not in SPECIAL_SCHEMES
                )

                if self.url.hostname == "localhost":
                    self.url._hostname = ""

                if self.state_override is not None:
                    raise _UrlParserReturn()

                self._buffer = ""
                self._state = PARSER_STATE_PATH_START

        else:
            self._buffer += c

    def _on_path_start(self, c, _):
        """Handles the PATH START state"""
        if self.url.scheme in SPECIAL_SCHEMES:
            if c == "\\":
                self.validation_error = True

            self._state = PARSER_STATE_PATH

            if c != "/" and c != "\\":
                self._pointer -= 1

        elif self.state_override is None and c == "?":
            self.url._query = ""
            self._state = PARSER_STATE_QUERY

        elif self.state_override is None and c == "#":
            self.url._fragment = ""
            self._state = PARSER_STATE_FRAGMENT

        elif c != "":
            self._state = PARSER_STATE_PATH

            if c != "/":
                self._pointer -= 1

    def _on_path(self, c, remaining):
        """Handles the PATH state"""
        cond = c == "\\" and self.url.scheme in SPECIAL_SCHEMES
        if (
            c == ""
            or c == "/"
            or cond
            or (self.state_override is None and (c == "?" or c == "#"))
        ):
            if cond:
                self.validation_error = True

            if self._buffer in DOUBLE_DOT_PATH_SEGMENTS:
                self.shorten_url_path()

                if not (c == "/" or cond):
                    self.url._path.append("")

            elif self._buffer in SINGLE_DOT_PATH_SEGMENTS and not (c == "/" or cond):
                self.url._path.append("")

            elif self._buffer not in SINGLE_DOT_PATH_SEGMENTS:
                if (
                    self.url.scheme == "file"
                    and len(self.url._path) == 0
                    and WINDOWS_DRIVE_LETTER.match(self._buffer) is not None
                ):
                    if self.url.hostname != "" and self.url.hostname is not None:
                        self.validation_error = True
                        self.url._hostname = ""

                    self._buffer = self._buffer[0] + ":" + self._buffer[2:]

                self.url._path.append(self._buffer)

            self._buffer = ""

            if self.url.scheme == "file" and c in PATH_DELIMITERS:
                while len(self.url._path) > 1 and self.url._path[0] == "":
                    self.validation_error = True
                    self.url._path.pop(0)

            if c == "?":
                self.url._query = ""
                self._state = PARSER_STATE_QUERY

            elif c == "#":
                self.url._fragment = ""
                self._state = PARSER_STATE_FRAGMENT

        else:
            if c != "%" and not _is_url_codepoint(c):
                self.validation_error = True
            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True
            self._buffer += _percent_encode(c, PATH_PERCENT_ENCODE)

    def _on_cannot_be_base_url(self, c, remaining):
        """Handles the CANNOT BE BASE URL state"""
        if c == "?":
            self.url._query = ""
            self._state = PARSER_STATE_QUERY

        elif c == "#":
            self.url._fragment = ""
            self._state = PARSER_STATE_FRAGMENT

        else:
            if c != "" and c != "%" and not _is_url_codepoint(c):
                self.validation_error = True

            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True

            if c != "":
                self.url._path[0] += _percent_encode(c, C0_PERCENT_ENCODE)

    def _on_query(self, c, remaining):
        """Handles the QUERY state"""
        if self.encoding != "utf-8" and (
            self.url.scheme == "ws"
            or self.url.scheme == "wss"
            or self.url.scheme not in SPECIAL_SCHEMES
        ):
            self.encoding = "utf-8"

        if self.state_override is None and c == "#":
            self.url._fragment = ""
            self._state = PARSER_STATE_FRAGMENT

        elif c != "":
            if c != "%" and not _is_url_codepoint(c):
                self.validation_error = True

            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True

            bytes_ = c.encode(self.encoding)

            if bytes_.startswith(b"&#") and bytes_.endswith(b";"):
                self.url._query += (b"%26%23" + bytes_[2:-1] + b"%3B").decode("ascii")

            else:
                is_special = self.url.scheme in SPECIAL_SCHEMES
                for byte in _iterbytes(bytes_):
                    if (
                        byte < 0x21
                        or byte > 0x7e
                        or byte == 0x22
                        or byte == 0x23
                        or byte == 0x3c
                        or byte == 0x3e
                        or (is_special and byte == 0x27)
                    ):
                        self.url._query += "%" + _hex(byte)
                    else:
                        self.url._query += chr(byte)

    def _on_fragment(self, c, remaining):
        if c == "":
            pass

        elif c == "\x00":
            self.validation_error = True

        else:
            if c != "%" and _is_url_codepoint(c):
                self.validation_error = True

            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True

            self.url._fragment += _percent_encode(c, FRAGMENT_PERCENT_ENCODE)


def _string_percent_decode(data):
    bytes_ = data.encode("utf-8")
    return _percent_decode(bytes_)


def _percent_encode(c, encode_set):
    if c in encode_set or ord(c) > 0x7e:
        if not isinstance(c, bytes):
            c = c.encode("utf-8")
        return "".join(["%" + _hex(x) for x in _iterbytes(c)])
    return c


def _is_url_codepoint(c):
    if c in URL_CODEPOINTS:
        return True
    c_ord = ord(c)
    return (
        0xa0 <= c_ord <= 0x10fffd
        and not 0xd800 <= c_ord <= 0xdfff
        and not 0xfdd0 <= c_ord <= 0xfdef
        and c_ord not in NONCHARACTERS
    )


def _is_c0_control_or_space(c):
    return c == " " or 0 <= ord(c) <= 0x1f


def _percent_decode(bytes_):
    output = []
    skip = 0

    def is_hex(x):
        x = _byte2int(x)
        return 0x30 <= x <= 0x39 or 0x41 <= x <= 0x46 or 0x61 <= x <= 0x66

    for i, byte in enumerate(_iterbytes(bytes_)):
        if skip:
            skip -= 1
            continue
        if byte != 0x25:
            output.append(_int2byte(byte))
        elif (
            i + 2 >= len(bytes_)
            or not is_hex(bytes_[i + 1])
            or not is_hex(bytes_[i + 2])
        ):
            output.append(_int2byte(byte))
        else:
            value = int(bytes_[i + 1 : i + 3].decode("ascii").lower(), 16)
            skip = 2
            output.append(_int2byte(value))

    return b"".join(output)


def _domain_to_ascii(domain, strict=False):
    """Attempt to encode with IDNA 2008 first, if that fails
    then attempt to encode with IDNA 2003.
    """
    try:
        return idna.encode(
            domain, strict=strict, std3_rules=strict, uts46=True, transitional=False
        )
    except idna.IDNAError:
        if isinstance(domain, (bytes, bytearray)):
            domain = domain.decode("ascii")
        domain = idna.uts46_remap(domain, std3_rules=strict, transitional=False)
        trailing_dot = False
        result = []
        if strict:
            labels = domain.split(".")
        else:
            labels = IDNA_DOTS_REGEX.split(domain)

        if not labels or labels == [""]:
            raise idna.IDNAError("Empty domain")
        if labels[-1] == "":
            del labels[-1]
            trailing_dot = True

        for label in labels:
            try:
                s = idna2003.ToASCII(label)
            except UnicodeError:
                if strict:
                    raise
                result.append(label.encode("utf-8"))
                continue
            if s:
                result.append(s)
            else:
                raise idna.IDNAError("Empty label")
        if trailing_dot:
            result.append(b"")
        s = b".".join(result)
        if not idna.valid_string_length(s, trailing_dot):
            raise idna.IDNAError("Domain too long")
        return s


def _parse_ipv4_number(input_):
    """Parses a single IPv4 number"""

    r = 10

    try:
        if len(input_) >= 2:
            if input_[:2].lower() == "0x":
                r = 16
                input_ = input_[2:]

            elif input_.startswith("0"):
                r = 8
                input_ = input_[1:]

        if input_ == "":
            return 0, False

        return int(input_, r), r != 10
    except ValueError:
        return None, False


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


def urlparse(urlstring, scheme="", allow_fragments=True, encoding="utf-8"):
    """Compatible with urllib.parse.urlparse().
    See documentation of urlparse() for more information.
    """
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
    """Compatible with urllib.parse.urljoin()
    See documentation of urljoin() for more information.
    """
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


def _iterbytes(bytes_):
    if six.PY3:
        return bytes_
    else:
        return [ord(x) for x in bytes_]


def _byte2int(byte):
    if not isinstance(byte, int):
        return ord(byte)
    return byte


def _int2byte(i):
    if six.PY3:
        return i.to_bytes(length=1, byteorder="little")
    return chr(i)


def _hex(x):
    return hex(_byte2int(x))[2:].zfill(2).upper()
