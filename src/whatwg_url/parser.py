import enum
import string
import typing
import re
import ipaddress
import idna
import attr
import encodings.idna as idna2003


class _OpaqueOrigin(object):
    def __eq__(self, _):
        return False


OPAQUE_ORIGIN = _OpaqueOrigin()
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

WINDOWS_DRIVE_LETTER = re.compile(r"^[a-zA-Z][:|][/\\?#]?")
NORMALIZED_WINDOWS_DRIVE_LETTER = re.compile(r"^[a-zA-Z][:]$")

AUTHORITY_DELIMITERS = {"", "/", "?", "#"}
PATH_DELIMITERS = {"", "/", "?", "#"}

_HEX_CHAR_MAP = dict(
    [
        ((a + b).encode("ascii"), chr(int(a + b, 16)).encode("charmap"))
        for a in string.hexdigits
        for b in string.hexdigits
    ]
)

IDNA_DOTS_REGEX = re.compile(u'[\u002e\u3002\uff0e\uff61]')


SPECIAL_SCHEMES = {
    "ftp": 21,
    "gopher": 70,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "file": None,
}


class UrlParserError(ValueError):
    pass


class _UrlParserReturn(Exception):
    pass


@attr.s
class Url:
    _scheme = attr.ib(default=None)  # type: typing.Optional[str]
    _hostname = attr.ib(default=None)  # type: typing.Optional[str]
    _port = attr.ib(default=None)  # type: typing.Optional[int]
    _username = attr.ib(default=None)  # type: typing.Optional[str]
    _password = attr.ib(default=None)  # type: typing.Optional[str]
    _query = attr.ib(default=None)  # type: typing.Optional[str]
    _fragment = attr.ib(default=None)  # type: typing.Optional[str]
    _path = attr.ib(default=attr.Factory(list))  # type: typing.List[str]

    cannot_be_base_url = attr.ib(type=bool, default=False)  # type: bool
    encoding = attr.ib(type=str, default='utf-8')  # type: str

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
    def host(self) -> str:
        if self._port is None:
            return self._hostname
        return f"{self._hostname}:{self._port}"

    @property
    def path(self) -> str:
        if self.cannot_be_base_url:
            return self._path[0]
        else:
            return "".join([f"/{x}" for x in self._path])

    @scheme.setter
    def scheme(self, scheme: str):
        parser = UrlParser(self, encoding=self.encoding)
        parser.parse(scheme + ':', state_override=ParserState.SCHEME_START)

    @username.setter
    def username(self, username: str):
        self._username = username

    @password.setter
    def password(self, password: str):
        self._password = password

    @hostname.setter
    def hostname(self, hostname: str):
        parser = UrlParser(self, encoding=self.encoding)
        parser.parse(hostname, state_override=ParserState.HOSTNAME)

    @port.setter
    def port(self, port: int):
        parser = UrlParser(self, encoding=self.encoding)
        parser.parse(str(port), state_override=ParserState.PORT)

    @path.setter
    def path(self, path: str):
        if self.cannot_be_base_url:
            return

        self._path = []
        parser = UrlParser(self, encoding=self.encoding)
        parser.parse(path, state_override=ParserState.PATH_START)

    @query.setter
    def query(self, query: str):
        if query is None:
            self._query = None
            return

        if query.startswith('?'):
            query = query[1:]

        self._query = ''
        parser = UrlParser(self, encoding=self.encoding)
        parser.parse(query, state_override=ParserState.QUERY)

    @fragment.setter
    def fragment(self, fragment: str):
        if fragment is None:
            self._fragment = None
            return

        if fragment.startswith('#'):
            fragment = fragment[1:]

        self._fragment = ''
        parser = UrlParser(self, encoding=self.encoding)
        parser.parse(fragment, state_override=ParserState.FRAGMENT)

    @property
    def includes_credentials(self) -> bool:
        """Determines if a URL includes credentials"""
        return bool(self._username) or bool(self._password)

    @property
    def origin(self):
        if self.scheme == 'blob':
            url = Url()
            parser = UrlParser(url)
            try:
                parser.parse(self.path[0], encoding=self.encoding)
            except UrlParserError:
                return OPAQUE_ORIGIN
            return url.origin

        elif self.scheme in SPECIAL_SCHEMES and self.scheme != 'file':
            return (self.scheme, self.hostname, self.port, None)

        else:
            return OPAQUE_ORIGIN

    @property
    def href(self) -> str:
        output = [f"{self._scheme}:"]
        if self._hostname is not None:
            output.append("//")

            if self.includes_credentials:
                if self._username:
                    output.append(self._username)
                if self._password:
                    output.append(f":{self._password}")
                output.append("@")

            output.append(self._hostname)
            if self._port is not None:
                output.append(f":{self._port}")

        if self._hostname is None and self._scheme == "file":
            output.append("//")

        if self.cannot_be_base_url:
            output.append(self._path[0])
        else:
            output.append(self.path)

        if self._query is not None:
            output.append(f"?{self._query}")

        if self._fragment is not None:
            output.append(f"#{self._fragment}")

        return "".join(output)

    def __repr__(self):
        return f"<{self.__class__.__name__} scheme={self._scheme:r} hostname={self._hostname:r} port={self._port:r} query={self._query:r} fragment={self._fragment:r}>"

    def __str__(self):
        return self.href


class ParserState(enum.IntEnum):
    SCHEME_START = 1
    SCHEME = 2
    NO_SCHEME = 3
    SPECIAL_RELATIVE_OR_AUTHORITY = 4
    PATH_OR_AUTHORITY = 5
    RELATIVE = 6
    RELATIVE_SLASH = 7
    SPECIAL_AUTHORITY_SLASHES = 8
    SPECIAL_AUTHORITY_IGNORE_SLASHES = 9
    AUTHORITY = 10
    HOST = 11
    HOSTNAME = 12
    PORT = 13
    FILE = 14
    FILE_SLASH = 15
    FILE_HOST = 16
    PATH_START = 17
    PATH = 18
    CANNOT_BE_BASE_URL = 19
    QUERY = 20
    FRAGMENT = 21


class UrlParser(object):
    def __init__(self, url, base=None, encoding="utf-8"):
        super().__init__()
        self.url = url
        self.base = base
        self.encoding = encoding
        self.state_override = None
        self.validation_error = False

        self._state = None
        self._pointer = 0
        self._buffer = ""
        self._at_flag = False
        self._square_brace_flag = False
        self._password_token_seen_flag = False

        self._state_handlers = {
            ParserState.SCHEME_START: self._on_scheme_start,
            ParserState.SCHEME: self._on_scheme,
            ParserState.NO_SCHEME: self._on_no_scheme,
            ParserState.SPECIAL_RELATIVE_OR_AUTHORITY: self._on_special_relative_or_authority,
            ParserState.PATH_OR_AUTHORITY: self._on_path_or_authority,
            ParserState.RELATIVE: self._on_relative,
            ParserState.RELATIVE_SLASH: self._on_relative_slash,
            ParserState.SPECIAL_AUTHORITY_SLASHES: self._on_special_authority_slashes,
            ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES: self._on_special_authority_ignore_slashes,
            ParserState.AUTHORITY: self._on_authority,
            ParserState.HOST: self._on_host_or_hostname,
            ParserState.HOSTNAME: self._on_host_or_hostname,
            ParserState.PORT: self._on_port,
            ParserState.FILE: self._on_file,
            ParserState.FILE_SLASH: self._on_file_slash,
            ParserState.FILE_HOST: self._on_file_host,
            ParserState.PATH_START: self._on_path_start,
            ParserState.PATH: self._on_path,
            ParserState.CANNOT_BE_BASE_URL: self._on_cannot_be_base_url,
            ParserState.QUERY: self._on_query,
            ParserState.FRAGMENT: self._on_fragment,
        }

    def parse(self, data: str, encoding=None, state_override=None) -> Url:
        self.reset()
        self.state_override = state_override

        self._state = state_override or ParserState.SCHEME_START

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

        print("DATA", repr(data))

        try:
            end_pointer = len(data)

            while self._pointer < end_pointer or (
                end_pointer == 0 and self._pointer == 0
            ):
                if end_pointer > 0:
                    print(
                        self._state,
                        repr(self._buffer),
                        repr(data[self._pointer]),
                        repr(data[self._pointer + 1 :]),
                        self.url,
                    )
                    self._state_handlers[self._state](
                        data[self._pointer], data[self._pointer + 1 :]
                    )
                    self._pointer += 1

                while self._pointer == end_pointer:
                    print(self._state, repr(self._buffer), "EOF", self.url)
                    self._state_handlers[self._state]("", "")
                    self._pointer += 1

        except _UrlParserReturn:
            pass

        return self.url

    def parse_host(self, host: str, is_not_special: bool = None) -> str:
        if is_not_special is None:
            is_not_special = False

        # IPv6 parsing
        if host.startswith("["):
            if not host.endswith("]"):
                self.validation_error = True
                raise UrlParserError()

            try:
                return f"[{str(ipaddress.IPv6Address(host[1:-1]))}]"
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

            return "".join([percent_encode(c, C0_PERCENT_ENCODE) for c in host])

        # Domain to ASCII
        domain = string_percent_decode(host).decode("utf-8")
        print("DOMAIN", domain)

        try:
            ascii_domain = domain_to_ascii(domain).decode('utf-8').lower()
            print("IDNA", ascii_domain)
        except (idna.IDNAError, UnicodeError):
            self.validation_error = True
            raise UrlParserError()

        # Contains forbidden host codepoint
        if set(ascii_domain).intersection(FORBIDDEN_HOST_CODE_POINTS):
            raise UrlParserError()

        # IPv4 parsing
        return self.parse_ipv4_host(ascii_domain)

    def parse_ipv4_host(self, ascii_domain: str) -> str:
        """Attempts to parse a domain as an IPv4 address with
        a lot of parsing rules for decimal, octal, hex, different
        numbers of separators, etc.
        """

        def parse_ipv4_number(input_: str):
            """Parses a single IPv4 number"""
            print(f"Parsing {input_}")
            try:
                if len(input_) >= 2:
                    if input_[:2].lower() == '0x':
                        return int(input_[2:], 16), True

                    elif input_.startswith('0'):
                        return int(input_[1:], 8), True

                if input_ == '':
                    return 0, False

                return int(input_), False
            except ValueError:
                return None, False

        parts = ascii_domain.split('.')

        if parts[-1] == '':
            self.validation_error = True
            if len(parts) > 1:
                parts.pop(-1)

        if len(parts) > 4:
            return ascii_domain

        numbers = []
        for part in parts:
            if part == '':
                return ascii_domain

            n, flag = parse_ipv4_number(part)
            if n is None:
                return ascii_domain

            numbers.append(n)

        for number in numbers[:-1]:
            if number > 255:
                self.validation_error = True

        if numbers[-1] > 256 ** (5 - len(numbers)):
            self.validation_error = True
            raise UrlParserError()

        ipv4 = numbers[-1]
        numbers.pop(-1)
        for i, number in enumerate(numbers):
            ipv4 += number * (256 ** (3 - i))

        output = []
        for _ in range(4):
            output.insert(0, str(ipv4 % 256))
            ipv4 //= 256

        return '.'.join(output)

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

    def _on_scheme_start(self, c: str, _):
        """Handles the START SCHEME state."""
        if c in ASCII_ALPHA:
            self._buffer += c.lower()
            self._state = ParserState.SCHEME

        elif self.state_override is None:
            self._state = ParserState.NO_SCHEME
            self._pointer -= 1

        else:
            self.validation_error = True
            raise UrlParserError()

    def _on_scheme(self, c: str, remaining: str):
        """Handles the SCHEME state."""
        if c in SCHEME_CHARS:
            self._buffer += c.lower()

        elif c == ":":
            if self.state_override is not None:
                if (
                    (self._buffer in SPECIAL_SCHEMES)
                    != (self.url.scheme in SPECIAL_SCHEMES)
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
                self._state = ParserState.FILE

            elif (
                self.url.scheme in SPECIAL_SCHEMES
                and self.base is not None
                and self.base.scheme == self.url.scheme
            ):
                self._state = ParserState.SPECIAL_RELATIVE_OR_AUTHORITY

            elif self.url.scheme in SPECIAL_SCHEMES:
                self._state = ParserState.SPECIAL_AUTHORITY_SLASHES

            elif remaining.startswith("/"):
                self._state = ParserState.PATH_OR_AUTHORITY
                self._pointer += 1

            else:
                self.url.cannot_be_base_url = True
                self.url._path.append("")
                self._state = ParserState.CANNOT_BE_BASE_URL

        elif self.state_override is None:
            self._buffer = ""
            self._state = ParserState.NO_SCHEME
            self._pointer = -1

        else:
            self.validation_error = True
            raise UrlParserError()

    def _on_no_scheme(self, c: str, _):
        """Handles the NO SCHEME state"""
        if self.base is None or (self.base.cannot_be_base_url and c != "#"):
            self.validation_error = True
            raise UrlParserError()

        elif self.base.cannot_be_base_url and c == "#":
            self.url._scheme = self.base.scheme
            self.url._path = self.base._path.copy()
            self.url._query = self.base.query
            self.url._fragment = ""
            self.url.cannot_be_base_url = True
            self._state = ParserState.FRAGMENT

        elif self.base.scheme != "file":
            self._state = ParserState.RELATIVE
            self._pointer -= 1

        else:
            self._state = ParserState.FILE
            self._pointer -= 1

    def _on_special_relative_or_authority(self, c: str, remaining: str):
        """Handles the SPECIAL RELATIVE OR AUTHORITY state"""
        if c == "/" and remaining.startswith("/"):
            self._state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
            self._pointer += 1

        else:
            self.validation_error = True
            self._state = ParserState.RELATIVE
            self._pointer -= 1

    def _on_path_or_authority(self, c: str, _):
        """Handles the PATH OR AUTHORITY state"""
        if c == "/":
            self._state = ParserState.AUTHORITY
        else:
            self._state = ParserState.PATH
            self._pointer -= 1

    def _on_relative(self, c: str, _):
        """Handles the RELATIVE state"""
        self.url._scheme = self.base.scheme

        if c == "":
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port
            self.url._path = self.base._path.copy()
            self.url._query = self.base.query

        elif c == "/":
            self._state = ParserState.RELATIVE_SLASH

        elif c == "?":
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port
            self.url._path = self.base._path.copy()
            self.url._query = ""

            self._state = ParserState.QUERY

        elif c == "#":
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port
            self.url._path = self.base._path.copy()
            self.url._query = self.base.query
            self.url._fragment = ""

            self._state = ParserState.FRAGMENT

        else:
            if self.url.scheme in SPECIAL_SCHEMES and c == "\\":
                self.validation_error = True
                self._state = ParserState.RELATIVE_SLASH

            else:
                self.url._username = self.base.username
                self.url._password = self.base.password
                self.url._hostname = self.base.hostname
                self.url._port = self.base.port
                self.url._path = self.base._path.copy()

                if len(self.url._path):
                    self.url._path.pop(-1)

                self._state = ParserState.PATH
                self._pointer -= 1

    def _on_relative_slash(self, c: str, _):
        if self.url.scheme in SPECIAL_SCHEMES and (c == "/" or c == "\\"):
            if c == "\\":
                self.validation_error = True
            self._state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES

        elif c == "/":
            self._state = ParserState.AUTHORITY

        else:
            self.url._username = self.base.username
            self.url._password = self.base.password
            self.url._hostname = self.base.hostname
            self.url._port = self.base.port

            self._pointer -= 1
            self._state = ParserState.PATH

    def _on_special_authority_slashes(self, c: str, remaining: str):
        """Handles the SPECIAL AUTHORITY SLASHES state"""
        if c == "/" and remaining.startswith("/"):
            self._state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
            self._pointer += 1

        else:
            self.validation_error = True
            self._state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
            self._pointer -= 1

    def _on_special_authority_ignore_slashes(self, c: str, _):
        """Handles the SPECIAL AUTHORITY IGNORE SLASHES state"""
        if c != "/" and c != "\\":
            self._state = ParserState.AUTHORITY
            self._pointer -= 1

        else:
            self.validation_error = True

    def _on_authority(self, c: str, _):
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
                    self.url._password += percent_encode(char, USERINFO_PERCENT_ENCODE)
                else:
                    if self.url.username is None:
                        self.url._username = ""
                    self.url.username += percent_encode(char, USERINFO_PERCENT_ENCODE)

            self._buffer = ""

        elif c in AUTHORITY_DELIMITERS or (
            self.url.scheme in SPECIAL_SCHEMES and c == "\\"
        ):
            if self._at_flag and self._buffer == "":
                self.validation_error = True
                raise UrlParserError()

            self._pointer -= len(self._buffer) + 1
            self._buffer = ""
            self._state = ParserState.HOST

        else:
            self._buffer += c

    def _on_host_or_hostname(self, c: str, _):
        """Handles the HOST and HOSTNAME states"""
        if self.state_override is not None and self.url.scheme == "file":
            self._pointer -= 1
            self._state = ParserState.FILE_HOST

        elif c == ":" and not self._square_brace_flag:
            if self._buffer == "":
                self.validation_error = True
                raise UrlParserError()

            self.url._hostname = self.parse_host(
                self._buffer, self.url.scheme not in SPECIAL_SCHEMES
            )
            self._buffer = ""
            self._state = ParserState.PORT

            if self.state_override == ParserState.HOSTNAME:
                raise _UrlParserReturn()

        elif c in PATH_DELIMITERS or (c == "\\" and self.url.scheme in SPECIAL_SCHEMES):
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
            self._state = ParserState.PATH_START

            if self.state_override is not None:
                raise _UrlParserReturn()

        else:
            if c == "[":
                self._square_brace_flag = True
            elif c == "]":
                self._square_brace_flag = False
            self._buffer += c

    def _on_port(self, c: str, _):
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
                    raise UrlParserError from e

                if port > 2 ** 16 - 1:
                    self.validation_error = True
                    raise UrlParserError()

                self.url._port = (
                    None if port == SPECIAL_SCHEMES.get(self.url.scheme, None) else port
                )
                self._buffer = ""

            if self.state_override:
                raise _UrlParserReturn()

            self._state = ParserState.PATH_START
            self._pointer -= 1

        else:
            self.validation_error = True
            raise UrlParserError()

    def _on_file(self, c: str, remaining: str):
        """Handles the FILE state"""
        self.url._scheme = "file"

        if c == "//" or c == "\\":
            if c == "\\":
                self.validation_error = True
            self._state = ParserState.FILE_SLASH

        elif self.base is not None and self.base.scheme == "file":
            if c == "":
                self.url._hostname = self.base.hostname
                self.url._path = self.base._path.copy()
                self.url._query = self.base.query

            elif c == "?":
                self.url._hostname = self.base.hostname
                self.url._path = self.base._path.copy()
                self.url._query = ""

                self._state = ParserState.QUERY

            elif c == "#":
                self.url._hostname = self.base.hostname
                self.url._path = self.base._path.copy()
                self.url._query = self.base.query
                self.url._fragment = ""

                self._state = ParserState.FRAGMENT

            else:
                match = WINDOWS_DRIVE_LETTER.search(c + remaining)
                if match is None:
                    self.url._hostname = self.base.hostname
                    self.url._path = self.base._path.copy()
                    self.shorten_url_path()

                else:
                    self.validation_error = True

        else:
            self._state = ParserState.PATH
            self._pointer -= 1

    def _on_file_slash(self, c: str, remaining: str):
        """Handles the FILE SLASH state"""
        if c == "/" or c == "\\":
            if c == "\\":
                self.validation_error = True
            self._state = ParserState.FILE_HOST

        else:
            if (
                self.base is not None
                and self.base.scheme == "file"
                and WINDOWS_DRIVE_LETTER.search(c + remaining) is not None
            ):
                if (
                    len(self.base._path) > 0
                    and NORMALIZED_WINDOWS_DRIVE_LETTER.match(self.base._path[0])
                    is not None
                ):
                    self.url._path.append(self.base._path[0])

                else:
                    self.url._hostname = self.base.hostname

            self._state = ParserState.PATH
            self._pointer -= 1

    def _on_file_host(self, c: str, _):
        """Handles the FILE HOST state"""
        if c in PATH_DELIMITERS:
            self._pointer -= 1

            if (
                self.state_override is not None
                and WINDOWS_DRIVE_LETTER.match(self._buffer) is not None
            ):
                self.validation_error = True
                self._state = ParserState.PATH

            elif self._buffer == "":
                self.url._hostname = ""

                if self.state_override is not None:
                    raise _UrlParserReturn()

                self._state = ParserState.PATH_START

            else:
                self.url._hostname = self.parse_host(
                    self._buffer, self.url.scheme not in SPECIAL_SCHEMES
                )

                if self.url.hostname == "localhost":
                    self.url._hostname = ""

                if self.state_override is not None:
                    raise _UrlParserReturn()

                self._buffer = ""
                self._state = ParserState.PATH_START

        else:
            self._buffer += c

    def _on_path_start(self, c: str, _):
        """Handles the PATH START state"""
        if self.url.scheme in SPECIAL_SCHEMES:
            if c == "\\":
                self.validation_error = True

            self._state = ParserState.PATH

            if c != "/" and c != "\\":
                self._pointer -= 1

        elif self.state_override is None and c == "?":
            self.url._query = ""
            self._state = ParserState.QUERY

        elif self.state_override is None and c == "#":
            self.url._fragment = ""
            self._state = ParserState.FRAGMENT

        elif c != "":
            self._state = ParserState.PATH

            if c != "/":
                self._pointer -= 1

    def _on_path(self, c: str, remaining: str):
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

            print(self.url._path)
            self._buffer = ""

            if self.url.scheme == "file" and c in PATH_DELIMITERS:
                while len(self.url._path) > 1 and self.url._path[0] == "":
                    self.validation_error = True
                    self.url._path.pop(0)

            if c == "?":
                self.url._query = ""
                self._state = ParserState.QUERY

            elif c == "#":
                self.url._fragment = ""
                self._state = ParserState.FRAGMENT

        else:
            if c != "%" and not _is_url_codepoint(c):
                self.validation_error = True
            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True
            self._buffer += percent_encode(c, PATH_PERCENT_ENCODE)

    def _on_cannot_be_base_url(self, c: str, remaining: str):
        """Handles the CANNOT BE BASE URL state"""
        if c == "?":
            self.url._query = ""
            self._state = ParserState.QUERY

        elif c == "#":
            self.url._fragment = ""
            self._state = ParserState.FRAGMENT

        else:
            if c != "" and c != "%" and not _is_url_codepoint(c):
                self.validation_error = True

            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True

            if c != "":
                self.url._path[0] += percent_encode(c, C0_PERCENT_ENCODE)

    def _on_query(self, c: str, remaining: str):
        """Handles the QUERY state"""
        if self.encoding != "utf-8" and (
            self.url.scheme == "ws"
            or self.url.scheme == "wss"
            or self.url.scheme not in SPECIAL_SCHEMES
        ):
            self.encoding = "utf-8"

        if self.state_override is None and c == "#":
            self.url._fragment = ""
            self._state = ParserState.FRAGMENT

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
                for byte in bytes_:
                    if (
                        byte < 0x21
                        or byte > 0x7e
                        or byte == 0x22
                        or byte == 0x23
                        or byte == 0x3c
                        or byte == 0x3e
                        or (is_special and byte == 0x27)
                    ):
                        self.url._query += f"%{byte:02X}"
                    else:
                        self.url._query += chr(byte)

    def _on_fragment(self, c: str, remaining: str):
        if c == "":
            pass

        elif c == "\x00":
            self.validation_error = True

        else:
            if c != "%" and _is_url_codepoint(c):
                self.validation_error = True

            if c == "%" and TWO_ASCII_HEX.search(remaining) is None:
                self.validation_error = True

            self.url._fragment += percent_encode(c, FRAGMENT_PERCENT_ENCODE)


def string_percent_decode(data: str) -> bytes:
    bytes_ = data.encode("utf-8")
    return percent_decode(bytes_)


def percent_encode(c: str, encode_set: typing.Set[str]) -> str:
    if c in encode_set or ord(c) > 0x7e:
        return "".join([f"%{x:02X}" for x in c.encode("utf-8")])
    return c


def _is_url_codepoint(c: str) -> bool:
    if c in URL_CODEPOINTS:
        return True
    c_ord = ord(c)
    return (
        0xa0 <= c_ord <= 0x10fffd
        and not 0xd800 <= c_ord <= 0xdfff
        and not 0xfdd0 <= c_ord <= 0xfdef
        and c_ord not in NONCHARACTERS
    )


def _is_c0_control_or_space(c: str) -> bool:
    return c == " " or 0 <= ord(c) <= 0x1f


def percent_decode(bytes_: bytes) -> bytes:
    output = []
    skip = 0

    def is_hex(x):
        return 0x30 <= x <= 0x39 or 0x41 <= x <= 0x46 or 0x61 <= x <= 0x66

    for i, byte in enumerate(bytes_):
        if skip:
            skip -= 1
            continue
        if byte != 0x25:
            output.append(byte.to_bytes(length=1, byteorder="little"))
        elif (
            i + 2 >= len(bytes_)
            or not is_hex(bytes_[i + 1])
            or not is_hex(bytes_[i + 2])
        ):
            output.append(byte.to_bytes(length=1, byteorder="little"))
        else:
            value = int(bytes_[i + 1 : i + 3].decode("ascii").lower(), 16)
            skip = 2
            output.append(value.to_bytes(length=1, byteorder="little"))

    return b"".join(output)


def domain_to_ascii(domain: str, strict=False) -> bytes:
    """Attempt to encode with IDNA 2008 first, if that fails
    then attempt to encode with IDNA 2003.
    """
    try:
        return idna.encode(domain, strict=strict, std3_rules=strict, uts46=True, transitional=False)
    except idna.IDNAError:
        domain = idna.uts46_remap(domain, std3_rules=strict, transitional=False)
        trailing_dot = False
        result = []
        if strict:
            labels = domain.split('.')
        else:
            labels = IDNA_DOTS_REGEX.split(domain)
        if not labels or labels == ['']:
            raise idna.IDNAError('Empty domain')
        if labels[-1] == '':
            del labels[-1]
            trailing_dot = True
        for label in labels:
            try:
                s = idna2003.ToASCII(label)
            except UnicodeError as e:
                if strict:
                    raise
                result.append(label)
                continue
            if s:
                result.append(s)
            else:
                raise idna.IDNAError('Empty label')
        if trailing_dot:
            result.append(b'')
        s = b'.'.join(result)
        if strict and not idna.valid_string_length(s, trailing_dot):
            raise idna.IDNAError('Domain too long')
        return s