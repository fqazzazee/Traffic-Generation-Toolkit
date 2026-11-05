"""TLS handshakes with per-client fingerprints, certificates and app data.

A sensor fingerprints TLS clients by their ClientHello (JA3 / JA4: version,
cipher suites, extensions, groups, point formats, signature algorithms, ALPN)
and inventories servers by the certificate they present (Zeek ``x509.log``,
CTD). Each :class:`ClientTemplate` reproduces one real client family — Windows
SChannel (10 / 7 / XP / 2000), Chrome and Firefox on the desktop, OpenSSL/curl
on Linux, the CrowdStrike Falcon sensor — so hosts of different OSes carry
different JA3/JA4 hashes while each family stays stable.

:func:`session` builds one full TLS conversation for one TCP connection: the
ClientHello, a server flight consistent with what the client offered (TLS 1.3:
ServerHello + ChangeCipherSpec + encrypted records; TLS 1.2 and older:
ServerHello + Certificate [+ ServerKeyExchange] + ServerHelloDone, then
ClientKeyExchange / ChangeCipherSpec / Finished both ways), then encrypted
application-data records. A server that cannot meet the client (SSL 3.0 against
a modern server, no common suite) answers with a fatal alert instead.

Randoms, session ids, keys and ciphertext are deterministic pseudo-random bytes
derived from the connection (addresses, ports, ``meta['cycle']`` if set), so a
build is reproducible while every connection differs.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Byte helpers
# ---------------------------------------------------------------------------


class _Rand:
    """Deterministic byte stream (SHA-256 in counter mode) for one session."""

    def __init__(self, *seed) -> None:
        self.seed = "|".join(map(str, seed)).encode()
        self.n = 0

    def bytes(self, k: int) -> bytes:
        out = b""
        while len(out) < k:
            out += hashlib.sha256(self.seed + struct.pack("!I", self.n)).digest()
            self.n += 1
        return out[:k]

    def int(self, lo: int, hi: int) -> int:
        return lo + int.from_bytes(self.bytes(4), "big") % (hi - lo + 1)


def _u8(b: bytes) -> bytes:
    return struct.pack("!B", len(b)) + b


def _u16(b: bytes) -> bytes:
    return struct.pack("!H", len(b)) + b


def _u24(b: bytes) -> bytes:
    return struct.pack("!I", len(b))[1:] + b


def _list16(vals) -> bytes:
    return b"".join(struct.pack("!H", v) for v in vals)


def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!H", etype) + _u16(data)


def _hs(mtype: int, body: bytes) -> bytes:
    return struct.pack("!B", mtype) + _u24(body)


def _record(ctype: int, version: int, body: bytes) -> bytes:
    return struct.pack("!BHH", ctype, version, len(body)) + body


# ---------------------------------------------------------------------------
# ASN.1 DER — just enough for an X.509 v3 certificate
# ---------------------------------------------------------------------------
def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + content


def _seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _int(v: int) -> bytes:
    return _der(0x02, v.to_bytes((v.bit_length() + 8) // 8 or 1, "big"))


def _oid(dotted: str) -> bytes:
    p = [int(x) for x in dotted.split(".")]
    out = bytes([40 * p[0] + p[1]])
    for v in p[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return _der(0x06, out)


_ATTR = {"C": ("2.5.4.6", 0x13), "ST": ("2.5.4.8", 0x0C),
         "L": ("2.5.4.7", 0x0C), "O": ("2.5.4.10", 0x0C),
         "OU": ("2.5.4.11", 0x0C), "CN": ("2.5.4.3", 0x0C),
         "DC": ("0.9.2342.19200300.100.1.25", 0x16)}


def _name(rdns: Tuple[Tuple[str, str], ...]) -> bytes:
    """X.501 Name from (attr, value) pairs, most significant first."""
    return _seq(*(_der(0x31, _seq(_oid(_ATTR[a][0]),
                                  _der(_ATTR[a][1], v.encode())))
                  for a, v in rdns))


def _utctime(y: int, mo: int, d: int, h: int = 0, mi: int = 0) -> bytes:
    return _der(0x17, f"{y % 100:02d}{mo:02d}{d:02d}{h:02d}{mi:02d}00Z".encode())


_SHA256_RSA = _seq(_oid("1.2.840.113549.1.1.11"), b"\x05\x00")

# Issuing CA per name space: the domain's AD CS enterprise CA for internal
# hosts, the public CA that actually issues the vendor's names otherwise.
ISSUERS = {
    "corp": (("DC", "local"), ("DC", "corp"), ("CN", "corp-PKI01-CA")),
    "digicert": (("C", "US"), ("O", "DigiCert Inc"),
                 ("CN", "DigiCert Global G2 TLS RSA SHA256 2020 CA1")),
    "letsencrypt": (("C", "US"), ("O", "Let's Encrypt"), ("CN", "R11")),
}


def issuer_for(cn: str) -> Tuple[Tuple[str, str], ...]:
    if cn.endswith((".cloudsink.net", ".crowdstrike.com")):
        return ISSUERS["digicert"]
    if cn.endswith(".local") or "." not in cn:
        return ISSUERS["corp"]
    return ISSUERS["letsencrypt"]


SERVER_AUTH, CLIENT_AUTH = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"


def certificate(cn: str, rnd: Optional[_Rand] = None,
                issuer: Optional[Tuple[Tuple[str, str], ...]] = None,
                subject: Optional[Tuple[Tuple[str, str], ...]] = None,
                san: Tuple[Tuple[int, str], ...] = (),
                eku: Tuple[str, ...] = (SERVER_AUTH,),
                key_usage: bytes = b"\x05\xa0",
                extra: Tuple[bytes, ...] = ()) -> bytes:
    """A syntactically valid X.509 v3 server certificate (DER) for ``cn``:
    RSA-2048 key, SAN = ``cn``, serverAuth EKU. The signature is random bytes
    (nobody verifies it); everything else parses like a real leaf cert.

    For other leaf kinds: ``subject`` (RDN pairs, default ``CN=cn``),
    ``san`` ((GeneralName tag, value) pairs, default ``dNSName cn``), ``eku``
    OIDs (e.g. :data:`CLIENT_AUTH` for a TLS client certificate),
    ``key_usage`` (BIT STRING content) and ``extra`` DER-encoded extensions
    appended after the standard four (a role extension, ...)."""
    rnd = rnd or _Rand("cert", cn)
    issuer = issuer or issuer_for(cn)
    serial = int.from_bytes(rnd.bytes(16), "big") >> 1 | 1 << 120
    # enterprise CA: two-year certs; public CA: 13 months (397-day cap)
    corp = issuer == ISSUERS["corp"]
    mo, d = rnd.int(1, 10), rnd.int(1, 28)
    nb = _utctime(2025 if corp else 2026, mo, d, rnd.int(0, 23), rnd.int(0, 59))
    na = _utctime(2027, mo, d, 23, 59) if corp else \
        _utctime(2027, mo + 1, d, 23, 59)
    modulus = int.from_bytes(rnd.bytes(256), "big") | (1 << 2047) | 1
    spki = _seq(_seq(_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
                _der(0x03, b"\x00" + _seq(_int(modulus), _int(65537))))
    san = _seq(*(_der(tag, v.encode()) for tag, v in (san or ((0x82, cn),))))
    exts = _seq(
        _seq(_oid("2.5.29.15"), _der(0x01, b"\xff"),            # keyUsage
             _der(0x04, _der(0x03, key_usage))),     # digitalSig, keyEnc
        _seq(_oid("2.5.29.37"),                                # extKeyUsage
             _der(0x04, _seq(*(_oid(o) for o in eku)))),       # serverAuth
        _seq(_oid("2.5.29.17"), _der(0x04, san)),              # subjectAltName
        _seq(_oid("2.5.29.19"), _der(0x04, _seq())),           # CA:FALSE
        *extra)
    tbs = _seq(_der(0xA0, _int(2)), _int(serial), _SHA256_RSA, _name(issuer),
               _seq(nb, na), _name(subject or (("CN", cn),)), spki,
               _der(0xA3, exts))
    return _seq(tbs, _SHA256_RSA, _der(0x03, b"\x00" + rnd.bytes(256)))


# ---------------------------------------------------------------------------
# Cipher suites
# ---------------------------------------------------------------------------
_AEAD_GCM = {0xC02B, 0xC02C, 0xC02F, 0xC030, 0x009C, 0x009D, 0x009E, 0x009F}
_AEAD_CHACHA = {0xCCA8, 0xCCA9, 0xCCAA}
_TLS13 = {0x1301: 32, 0x1302: 48, 0x1303: 32}          # suite -> hash length
_MAC = {0x0004: 16, 0x0005: 20}                        # RC4 (stream)
_SHA256_CBC = {0xC023, 0xC027, 0x003C, 0x003D, 0x0067, 0x006B, 0x0040, 0x006A}
_SHA384_CBC = {0xC024, 0xC028}
_DES_CBC = {0x000A, 0x0013, 0x0009, 0x0012, 0x0062, 0x0063, 0x0006}
_ECDHE = {0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028,
          0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9}
_DHE = {0x0033, 0x0039, 0x0067, 0x006B, 0x009E, 0x009F, 0xCCAA, 0x0013,
        0x0032, 0x0038, 0x0040, 0x006A}


def _tls12_only(cs: int) -> bool:
    return cs in _AEAD_GCM or cs in _AEAD_CHACHA or cs in _SHA256_CBC \
        or cs in _SHA384_CBC


def _sealed(cs: int, version: int, n: int, rnd: _Rand) -> bytes:
    """Ciphertext of an ``n``-byte plaintext under ``cs`` (record body)."""
    if version >= 0x0304:
        return rnd.bytes(n + 1 + 16)                   # inner type + tag
    if cs in _AEAD_GCM:
        return rnd.bytes(8 + n + 16)                   # explicit nonce + tag
    if cs in _AEAD_CHACHA:
        return rnd.bytes(n + 16)
    if cs in _MAC:
        return rnd.bytes(n + _MAC[cs])
    mac = 48 if cs in _SHA384_CBC else 32 if cs in _SHA256_CBC else 20
    block = 8 if cs in _DES_CBC else 16
    body = -(-(n + mac + 1) // block) * block
    return rnd.bytes((block if version >= 0x0302 else 0) + body)


# ---------------------------------------------------------------------------
# Client templates
# ---------------------------------------------------------------------------
_SIGALGS_SCHANNEL = (0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403,
                     0x0503, 0x0203, 0x0202, 0x0601, 0x0603)


@dataclass(frozen=True)
class ClientTemplate:
    key: str
    label: str
    version: int                       # ClientHello.client_version
    ciphers: Tuple[int, ...]
    exts: Tuple[str, ...] = ()         # extension order; () = no extensions
    record: int = 0x0301               # record-layer version of the hello
    groups: Tuple[int, ...] = ()
    point_formats: Tuple[int, ...] = (0,)
    sigalgs: Tuple[int, ...] = ()
    alpn: Tuple[str, ...] = ()
    versions: Tuple[int, ...] = ()     # supported_versions (TLS 1.3 capable)
    key_shares: Tuple[int, ...] = ()
    sid_len: int = 32                  # legacy session id length
    grease: bool = False               # RFC 8701 GREASE (Chromium)
    pad_to: int = 0                    # BoringSSL padding target (512)
    upload: Tuple[int, int] = (300, 900)      # app-data request size range
    download: Tuple[int, int] = (400, 4000)   # app-data response size range


TEMPLATES: Dict[str, ClientTemplate] = {t.key: t for t in (
    ClientTemplate(
        "chrome", "Chrome 120 on Windows", 0x0303,
        (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
         0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035),
        ("grease", "server_name", "extended_master_secret",
         "renegotiation_info", "supported_groups", "ec_point_formats",
         "session_ticket", "alpn", "status_request", "signature_algorithms",
         "signed_certificate_timestamp", "key_share",
         "psk_key_exchange_modes", "supported_versions",
         "compress_certificate", "application_settings", "grease2",
         "padding"),
        groups=(0x001D, 0x0017, 0x0018),
        sigalgs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                 0x0601),
        alpn=("h2", "http/1.1"), versions=(0x0304, 0x0303),
        key_shares=(0x001D,), grease=True, pad_to=512),
    ClientTemplate(
        "firefox", "Firefox 120", 0x0303,
        (0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C,
         0xC030, 0xC00A, 0xC009, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F,
         0x0035),
        ("server_name", "extended_master_secret", "renegotiation_info",
         "supported_groups", "ec_point_formats", "session_ticket", "alpn",
         "status_request", "delegated_credentials", "key_share",
         "supported_versions", "signature_algorithms",
         "psk_key_exchange_modes", "record_size_limit"),
        groups=(0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101),
        sigalgs=(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401,
                 0x0501, 0x0601, 0x0203, 0x0201),
        alpn=("h2", "http/1.1"), versions=(0x0304, 0x0303),
        key_shares=(0x001D, 0x0017)),
    ClientTemplate(
        "openssl", "curl / OpenSSL 3.0 (Linux)", 0x0303,
        (0x1302, 0x1303, 0x1301, 0xC02C, 0xC030, 0x009F, 0xCCA9, 0xCCA8,
         0xCCAA, 0xC02B, 0xC02F, 0x009E, 0xC024, 0xC028, 0x006B, 0xC023,
         0xC027, 0x0067, 0xC00A, 0xC014, 0x0039, 0xC009, 0xC013, 0x0033,
         0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0x00FF),
        ("server_name", "ec_point_formats", "supported_groups",
         "session_ticket", "alpn", "encrypt_then_mac",
         "extended_master_secret", "signature_algorithms",
         "supported_versions", "psk_key_exchange_modes", "key_share"),
        groups=(0x001D, 0x0017, 0x001E, 0x0019, 0x0018, 0x0100, 0x0101,
                0x0102, 0x0103, 0x0104),
        point_formats=(0, 1, 2),
        sigalgs=(0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080A,
                 0x080B, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                 0x0303, 0x0203, 0x0301, 0x0201, 0x0302, 0x0202, 0x0402,
                 0x0502, 0x0602),
        alpn=("h2", "http/1.1"), versions=(0x0304, 0x0303),
        key_shares=(0x001D,), upload=(150, 400), download=(300, 6000)),
    ClientTemplate(
        "schannel10", "Windows 10 / Server 2016-2019 SChannel", 0x0303,
        (0xC02C, 0xC02B, 0xC030, 0xC02F, 0xC024, 0xC023, 0xC028, 0xC027,
         0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x003D, 0x003C,
         0x0035, 0x002F, 0x000A),
        ("server_name", "status_request", "supported_groups",
         "ec_point_formats", "signature_algorithms", "session_ticket", "alpn",
         "extended_master_secret", "renegotiation_info"),
        record=0x0303, groups=(0x001D, 0x0017, 0x0018),
        sigalgs=_SIGALGS_SCHANNEL, alpn=("h2", "http/1.1")),
    ClientTemplate(
        "schannel7", "Windows 7 / Server 2008 R2 SChannel (TLS 1.2)", 0x0303,
        (0xC028, 0xC027, 0xC014, 0xC013, 0x009F, 0x009E, 0x0039, 0x0033,
         0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0xC02C, 0xC02B,
         0xC024, 0xC023, 0xC00A, 0xC009, 0x006A, 0x0040, 0x0038, 0x0032,
         0x000A, 0x0013),
        ("server_name", "status_request", "supported_groups",
         "ec_point_formats", "signature_algorithms",
         "extended_master_secret", "renegotiation_info"),
        groups=(0x0017, 0x0018),
        sigalgs=(0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202,
                 0x0601, 0x0603),
        sid_len=0),
    # XP SChannel: TLS 1.0, RC4/3DES/DES/export suites, no extensions (no SNI)
    ClientTemplate(
        "schannel-xp", "Windows XP SChannel (TLS 1.0)", 0x0301,
        (0x0004, 0x0005, 0x000A, 0x0009, 0x0064, 0x0062, 0x0003, 0x0006,
         0x0013, 0x0012, 0x0063),
        sid_len=0, upload=(250, 600)),
    # Windows 2000 SChannel / IE 5: SSL 3.0
    ClientTemplate(
        "schannel-2000", "Windows 2000 SChannel (SSL 3.0)", 0x0300,
        (0x0004, 0x0005, 0x000A, 0x0009, 0x0064, 0x0062, 0x0003, 0x0006,
         0x0013, 0x0012, 0x0063),
        record=0x0300, sid_len=0, upload=(250, 600)),
    # CrowdStrike Falcon sensor: its own TLS 1.2-only stack, no ALPN
    ClientTemplate(
        "falcon", "CrowdStrike Falcon sensor", 0x0303,
        (0xC02F, 0xC030, 0xC02B, 0xC02C, 0xC013, 0xC014, 0x009C, 0x009D,
         0x002F, 0x0035),
        ("server_name", "supported_groups", "ec_point_formats",
         "signature_algorithms", "extended_master_secret"),
        record=0x0303, groups=(0x0017, 0x0018),
        sigalgs=(0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804,
                 0x0805, 0x0806),
        sid_len=0, upload=(200, 1400), download=(60, 400)),
)}


# Which client stack a host's HTTPS uses: browsers on workstations, the OS
# library (SChannel / OpenSSL) on servers and unattended systems.
_OS_TLS = {"win2019": "schannel10", "win2012": "schannel10",
           "win10": "schannel10", "win7": "schannel7", "winxp": "schannel-xp",
           "win2000": "schannel-2000", "linux": "openssl"}
_BROWSER = {"win10": "chrome", "linux": "firefox"}
_BROWSER_ROLES = {"ws", "eng", "hmi", "scada"}


def client_for(os_key: str, role: str = "") -> str:
    """TLS client template key for a host (OS fingerprint key + role)."""
    if role in _BROWSER_ROLES and os_key in _BROWSER:
        return _BROWSER[os_key]
    return _OS_TLS.get(os_key, "openssl")


# ---------------------------------------------------------------------------
# Server behaviour
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ServerProfile:
    key: str
    min_version: int
    max_version: int
    prefs: Tuple[int, ...]             # TLS <= 1.2 suite preference
    prefs13: Tuple[int, ...] = ()
    tickets: bool = True


SERVERS: Dict[str, ServerProfile] = {s.key: s for s in (
    # nginx / Apache on OpenSSL 3 (3DES/RC4 compiled out). Every server has
    # an RSA certificate, so no ECDSA suites are ever selected.
    ServerProfile("openssl", 0x0301, 0x0304,
                  (0xC030, 0xC02F, 0xCCA8, 0x009F, 0x009E, 0xC028, 0xC027,
                   0xC014, 0xC013, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035,
                   0x002F),
                  (0x1302, 0x1303, 0x1301)),
    # IIS on Server 2012 R2 - 2019 SChannel: TLS 1.0-1.2, no 1.3
    ServerProfile("schannel", 0x0301, 0x0303,
                  (0xC030, 0xC02F, 0xC028, 0xC027, 0xC014, 0xC013, 0x009F,
                   0x009E, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F,
                   0x000A)),
    # IIS 5/6 on Windows 2000 / XP-era: SSL 3.0 / TLS 1.0, RC4 first
    ServerProfile("schannel-legacy", 0x0300, 0x0301,
                  (0x0004, 0x0005, 0x000A, 0x0009, 0x0003, 0x0006),
                  tickets=False),
    # Embedded web server (PLC / BMS supervisor): TLS 1.2, AES only
    ServerProfile("embedded", 0x0303, 0x0303,
                  (0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F,
                   0x0035), tickets=False),
)}

_OS_SERVER = {"win2019": "schannel", "win2012": "schannel", "win10": "schannel",
              "win7": "schannel", "winxp": "schannel-legacy",
              "win2000": "schannel-legacy", "linux": "openssl"}


def server_for(os_key: str, embedded: bool = False) -> str:
    if embedded:
        return "embedded"
    return _OS_SERVER.get(os_key, "openssl")


# ---------------------------------------------------------------------------
# ClientHello
# ---------------------------------------------------------------------------
def _grease(rnd: _Rand) -> List[int]:
    """GREASE values for this connection: [cipher, first extension, group /
    key share, supported_versions, last extension]; the two extension
    values differ so no extension type repeats."""
    idx = list(range(16))
    out = []
    for _ in range(5):
        out.append(0x0A0A + 0x1010 * idx.pop(rnd.int(0, len(idx) - 1)))
    return out


def client_hello(t: ClientTemplate, sni: str, rnd: _Rand
                 ) -> Tuple[bytes, dict]:
    """(ClientHello record, state) — state holds the random, session id and
    offers the server needs to answer consistently."""
    random = rnd.bytes(32)
    sid = rnd.bytes(t.sid_len)
    g = _grease(rnd) if t.grease else [0] * 5
    ciphers = ((g[0],) if t.grease else ()) + t.ciphers
    shares = {}
    for grp in t.key_shares:
        shares[grp] = rnd.bytes(32) if grp == 0x001D else \
            b"\x04" + rnd.bytes(64)
    build = {
        "server_name": lambda: _ext(0, _u16(b"\x00" + _u16(sni.encode()))),
        "extended_master_secret": lambda: _ext(23, b""),
        "renegotiation_info": lambda: _ext(0xFF01, b"\x00"),
        "supported_groups": lambda: _ext(10, _u16(_list16(
            ((g[2],) if t.grease else ()) + t.groups))),
        "ec_point_formats": lambda: _ext(11, _u8(bytes(t.point_formats))),
        "session_ticket": lambda: _ext(35, b""),
        "alpn": lambda: _ext(16, _u16(b"".join(_u8(p.encode())
                                               for p in t.alpn))),
        "status_request": lambda: _ext(5, b"\x01\x00\x00\x00\x00"),
        "signature_algorithms": lambda: _ext(13, _u16(_list16(t.sigalgs))),
        "signed_certificate_timestamp": lambda: _ext(18, b""),
        "key_share": lambda: _ext(51, _u16(
            ((struct.pack("!H", g[2]) + _u16(b"\x00")) if t.grease else b"")
            + b"".join(struct.pack("!H", k) + _u16(v)
                       for k, v in shares.items()))),
        "psk_key_exchange_modes": lambda: _ext(45, _u8(b"\x01")),
        "supported_versions": lambda: _ext(43, _u8(_list16(
            ((g[3],) if t.grease else ()) + t.versions))),
        "compress_certificate": lambda: _ext(27, _u8(b"\x00\x02")),
        "application_settings": lambda: _ext(17513, _u16(_u8(b"h2"))),
        "delegated_credentials": lambda: _ext(34, _u16(_list16(
            (0x0403, 0x0503, 0x0603, 0x0203)))),
        "record_size_limit": lambda: _ext(28, b"\x40\x01"),
        "encrypt_then_mac": lambda: _ext(22, b""),
        "grease": lambda: _ext(g[1], b""),
        "grease2": lambda: _ext(g[4], b"\x00"),
    }
    exts = b"".join(build[name]() for name in t.exts if name != "padding")
    head = (struct.pack("!H", t.version) + random + _u8(sid) +
            _u16(_list16(ciphers)) + b"\x01\x00")
    if "padding" in t.exts and t.pad_to:
        # BoringSSL: pad a hello of 256..511 bytes up to 512
        size = 4 + len(head) + 2 + len(exts)
        if 0xFF < size < t.pad_to:
            pad = t.pad_to - size
            pad = pad - 4 if pad >= 5 else 1
            exts += _ext(21, bytes(pad))
    body = head + (_u16(exts) if t.exts else b"")
    rec = _record(22, t.record, _hs(1, body))
    offers = {"random": random, "sid": sid, "ciphers": set(t.ciphers),
              "exts": set(t.exts), "groups": t.groups, "shares": shares,
              "versions": t.versions, "alpn": t.alpn}
    return rec, offers


# ---------------------------------------------------------------------------
# Full conversation
# ---------------------------------------------------------------------------
_DOWNGRADE = {0x0303: b"DOWNGRD\x01", 0x0302: b"DOWNGRD\x00",
              0x0301: b"DOWNGRD\x00", 0x0300: b"DOWNGRD\x00"}


def _alert(version: int, desc: int) -> bytes:
    return _record(21, version, bytes([2, desc]))


def _choose(t: ClientTemplate, o: dict, srv: ServerProfile):
    """(version, cipher) the server picks, or (version, None) to refuse."""
    if 0x0304 in o["versions"] and srv.max_version >= 0x0304:
        cs = next((c for c in srv.prefs13 if c in o["ciphers"]), None)
        if cs is not None:
            return 0x0304, cs
    legacy = max([v for v in o["versions"] if v < 0x0304] or [t.version])
    version = min(legacy, srv.max_version, 0x0303)
    if version < srv.min_version:
        return version, None
    cs = next((c for c in srv.prefs if c in o["ciphers"]
               and (version >= 0x0303 or not _tls12_only(c))
               and (c not in _ECDHE or o["groups"])), None)
    return version, cs


@dataclass
class Channel:
    """The negotiated session after a handshake: protocol version, cipher
    suite and the connection's byte stream, so callers can add encrypted
    records sized for their own plaintext (``None`` cipher = refused)."""
    version: int
    cs: Optional[int]
    rnd: _Rand

    @property
    def record_version(self) -> int:
        return 0x0303 if self.version == 0x0304 else self.version

    def sealed(self, n: int) -> bytes:
        """Ciphertext (record body) of an ``n``-byte plaintext."""
        return _sealed(self.cs, self.version, n, self.rnd)

    def record(self, n: int) -> bytes:
        """One application_data record carrying ``n`` plaintext bytes."""
        return _record(23, self.record_version, self.sealed(n))

    def close_notify(self) -> bytes:
        """An encrypted close_notify alert (TLS 1.3 hides it in an
        application_data record)."""
        if self.version == 0x0304:
            return _record(23, 0x0303, self.sealed(2))
        return _record(21, self.version, self.sealed(2))


def _cert_request(version: int, issuer: Tuple[Tuple[str, str], ...]) -> bytes:
    """CertificateRequest (TLS 1.0-1.2): RSA / ECDSA signing certificates,
    the accepted signature algorithms (1.2) and the issuing CA's name."""
    body = _u8(b"\x01\x40")
    if version >= 0x0303:
        body += _u16(_list16((0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603,
                              0x0804, 0x0805, 0x0806)))
    return _hs(13, body + _u16(_u16(_name(issuer))))


def handshake(t: ClientTemplate, srv: ServerProfile, sni: str, seed: tuple,
              cert_cn: str = "", server_cert: bytes = b"",
              client_cert: bytes = b""
              ) -> Tuple[List[Tuple[bytes, bytes]], Channel]:
    """The handshake of one TLS connection as (client payload, server
    payload) exchanges, and the :class:`Channel` it negotiates.

    ``server_cert`` replaces the certificate built for ``cert_cn`` / ``sni``;
    a ``client_cert`` makes it mutually authenticated — the server asks for a
    certificate (CertificateRequest) and the client answers with Certificate
    + CertificateVerify (in clear before TLS 1.3, encrypted in 1.3). A
    refused client gets a fatal alert (one exchange, ``Channel.cs`` None).
    TLS 1.3 takes two exchanges (ClientHello / server flight, client
    Finished / session tickets), earlier versions two as well (hello /
    certificate flight, key exchange + Finished both ways)."""
    rnd = _Rand("tls", *seed)
    hello, o = client_hello(t, sni if "server_name" in t.exts else "", rnd)
    version, cs = _choose(t, o, srv)
    if cs is None:                         # fatal alert, connection closes
        desc = 70 if version < srv.min_version else 40
        return [(hello, _alert(t.record if version < 0x0301 else version,
                               desc))], Channel(version, None, rnd)
    srand = rnd.bytes(32)
    if srv.max_version >= 0x0304 and version < 0x0304:
        srand = srand[:24] + _DOWNGRADE[version]
    cn = cert_cn or sni
    cert = server_cert or certificate(cn, _Rand("cert", cn))
    alpn = o["alpn"][0] if o["alpn"] and "alpn" in o["exts"] else ""
    exchanges: List[Tuple[bytes, bytes]] = []
    if version == 0x0304:
        group = next(gr for gr in (0x001D, 0x0017, 0x0018) if gr in o["shares"])
        share = rnd.bytes(32) if group == 0x001D else b"\x04" + rnd.bytes(64)
        sh = _hs(2, struct.pack("!H", 0x0303) + srand + _u8(o["sid"]) +
                 struct.pack("!HB", cs, 0) + _u16(
                     _ext(43, struct.pack("!H", 0x0304)) +
                     _ext(51, struct.pack("!H", group) + _u16(share))))
        hlen = _TLS13[cs]
        ee = 4 + 2 + (len(_ext(16, _u16(_u8(alpn.encode())))) if alpn else 0)
        inner = ee + (4 + 1 + 3 + 3 + len(cert) + 2) + (4 + 4 + 256) + 4 + hlen
        if client_cert:                    # CertificateRequest: sigalgs ext
            inner += 4 + 1 + 2 + 4 + 2 + 2 * 8
        ccs = _record(20, 0x0303, b"\x01") if o["sid"] else b""
        flight = (_record(22, 0x0303, sh) + ccs +
                  _record(23, 0x0303, _sealed(cs, version, inner, rnd)))
        exchanges.append((hello, flight))
        cfin = 4 + hlen
        if client_cert:                    # Certificate + CertificateVerify
            cfin += (4 + 1 + 3 + 3 + len(client_cert) + 2) + (4 + 4 + 256)
        fin = ccs + _record(23, 0x0303, _sealed(cs, version, cfin, rnd))
        tickets = b"".join(_record(23, 0x0303, _sealed(cs, version, 233, rnd))
                           for _ in range(2 if srv.tickets else 0))
        exchanges.append((fin, tickets))
        return exchanges, Channel(version, cs, rnd)
    rec_v = version
    sexts = b""
    if o["exts"]:
        if "renegotiation_info" in o["exts"] or 0x00FF in o["ciphers"]:
            sexts += _ext(0xFF01, b"\x00")
        if "extended_master_secret" in o["exts"]:
            sexts += _ext(23, b"")
        if cs in _ECDHE and "ec_point_formats" in o["exts"]:
            sexts += _ext(11, _u8(b"\x00"))
        if "session_ticket" in o["exts"] and srv.tickets:
            sexts += _ext(35, b"")
        if alpn:
            sexts += _ext(16, _u16(_u8(alpn.encode())))
    sh = _hs(2, struct.pack("!H", version) + srand + _u8(rnd.bytes(32)) +
             struct.pack("!HB", cs, 0) + (_u16(sexts) if o["exts"] else b""))
    certs = _hs(11, _u24(_u24(cert)))
    sig = (struct.pack("!H", 0x0401) if version >= 0x0303 else b"") + \
        _u16(rnd.bytes(256))
    if cs in _ECDHE:
        group = next((gr for gr in (0x001D, 0x0017, 0x0018)
                      if gr in o["groups"]), 0x0017)
        pub = rnd.bytes(32) if group == 0x001D else b"\x04" + rnd.bytes(64)
        ske = _hs(12, struct.pack("!BH", 3, group) + _u8(pub) + sig)
        cke = _hs(16, _u8(rnd.bytes(32) if group == 0x001D
                          else b"\x04" + rnd.bytes(64)))
    elif cs in _DHE:
        p = b"\xff" * 8 + rnd.bytes(240) + b"\xff" * 8
        ske = _hs(12, _u16(p) + _u16(b"\x02") + _u16(rnd.bytes(256)) + sig)
        cke = _hs(16, _u16(rnd.bytes(256)))
    else:                                   # RSA key transport
        ske = b""
        pms = rnd.bytes(256)
        cke = _hs(16, pms if version == 0x0300 else _u16(pms))
    creq = _cert_request(version, issuer_for(cn)) if client_cert else b""
    flight = b"".join(_record(22, rec_v, m)
                      for m in (sh, certs, ske, creq, _hs(14, b"")) if m)
    exchanges.append((hello, flight))
    fin_len = 4 + (36 if version == 0x0300 else 12)
    ccs = _record(20, rec_v, b"\x01")
    ccert = cverify = b""
    if client_cert:
        ccert = _record(22, rec_v, _hs(11, _u24(_u24(client_cert))))
        cverify = _record(22, rec_v, _hs(15, (struct.pack("!H", 0x0401)
                                              if version >= 0x0303 else b"") +
                                         _u16(rnd.bytes(256))))
    cfin = (ccert + _record(22, rec_v, cke) + cverify + ccs +
            _record(22, rec_v, _sealed(cs, version, fin_len, rnd)))
    nst = b""
    if "session_ticket" in o["exts"] and srv.tickets:
        nst = _record(22, rec_v, _hs(4, struct.pack("!I", 7200) +
                                     _u16(rnd.bytes(192))))
    sfin = nst + ccs + _record(22, rec_v, _sealed(cs, version, fin_len, rnd))
    exchanges.append((cfin, sfin))
    return exchanges, Channel(version, cs, rnd)


def session(t: ClientTemplate, srv: ServerProfile, sni: str, count: int,
            seed: tuple, cert_cn: str = "") -> Tuple[List[Tuple[bytes, bytes]], int]:
    """One TLS connection as (client payload, server payload) exchanges, plus
    how many leading exchanges are the handshake (sent back to back; the
    application exchanges after them are separated by idle time). TLS 1.3's
    client Finished and the session tickets ride with the first request and
    response."""
    exchanges, ch = handshake(t, srv, sni, seed, cert_cn)
    if ch.cs is None:
        return exchanges, 1
    first = (b"", b"")
    if ch.version == 0x0304:
        first = exchanges.pop()
    hs_count = len(exchanges)
    for i in range(count):
        req = ch.record(ch.rnd.int(*t.upload))
        rsp = ch.record(ch.rnd.int(*t.download))
        if i == 0:
            req, rsp = first[0] + req, first[1] + rsp
        exchanges.append((req, rsp))
    return exchanges, hs_count


# ---------------------------------------------------------------------------
# DTLS 1.2 (RFC 6347) — the same handshake over datagrams
# ---------------------------------------------------------------------------
DTLS12, DTLS10 = 0xFEFD, 0xFEFF

# An embedded / OpenSSL DTLS 1.2 client (CIP Security class-1 I/O
# originators): TLS 1.2 suites, no SNI / ALPN / TLS 1.3 extensions, the
# first records stamped DTLS 1.0 as OpenSSL does until the version is agreed.
DTLS_CLIENT = ClientTemplate(
    "openssl-dtls", "OpenSSL DTLS 1.2 client", DTLS12,
    (0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC023, 0xC027, 0xC009, 0xC013, 0xC00A,
     0xC014, 0x009C, 0x009D, 0x003C, 0x002F, 0x0035, 0x00FF),
    ("ec_point_formats", "supported_groups", "extended_master_secret",
     "signature_algorithms"),
    record=DTLS10, groups=(0x001D, 0x0017, 0x0018),
    sigalgs=(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
             0x0601),
    sid_len=0)


def _dtls_record(ctype: int, version: int, epoch: int, seq: int,
                 body: bytes) -> bytes:
    return struct.pack("!BHH", ctype, version, epoch) + \
        seq.to_bytes(6, "big") + _u16(body)


def _dtls_fragments(mtype: int, mseq: int, body: bytes,
                    room: int) -> List[bytes]:
    """A handshake message as DTLS fragments of at most ``room`` bytes
    (12-byte header: type, length, message_seq, fragment offset/length)."""
    out, off = [], 0
    while True:
        frag = body[off:off + room]
        out.append(struct.pack("!B", mtype) + len(body).to_bytes(3, "big") +
                   struct.pack("!H", mseq) + off.to_bytes(3, "big") +
                   len(frag).to_bytes(3, "big") + frag)
        off += len(frag)
        if off >= len(body):
            return out


class DtlsChannel:
    """Epoch-1 record protection after a DTLS handshake: each side's record
    sequence numbers continue from ``seq`` (callers building a long-lived
    association in chunks start each chunk further on)."""

    def __init__(self, cs: Optional[int], rnd: _Rand, seq: int = 1) -> None:
        self.cs, self.rnd = cs, rnd
        self.seq = {True: seq, False: seq}

    def record(self, n: int, from_client: bool) -> bytes:
        """One application_data record carrying ``n`` plaintext bytes."""
        s = self.seq[from_client]
        self.seq[from_client] = s + 1
        return _dtls_record(23, DTLS12, 1, s & 0xFFFFFFFFFFFF,
                            _sealed(self.cs, 0x0303, n, self.rnd))


def dtls_handshake(t: ClientTemplate, srv: ServerProfile, seed: tuple,
                   server_cert: bytes, client_cert: bytes = b"",
                   mtu: int = 1400, app_seq: int = 1
                   ) -> Tuple[List[Tuple[List[bytes], List[bytes]]],
                              DtlsChannel]:
    """A DTLS 1.2 handshake as (client datagrams, server datagrams)
    exchanges: ClientHello / HelloVerifyRequest (stateless cookie),
    ClientHello with the cookie / ServerHello + Certificate [+
    ServerKeyExchange] [+ CertificateRequest] + ServerHelloDone, then the
    client's [Certificate +] ClientKeyExchange [+ CertificateVerify] +
    ChangeCipherSpec + Finished and the server's ChangeCipherSpec +
    Finished. Records are packed into datagrams of at most ``mtu`` bytes and
    handshake messages fragmented to fit. The channel's application records
    start at sequence ``app_seq`` in epoch 1."""
    rnd = _Rand("dtls", *seed)
    rec, o = client_hello(t, "", rnd)
    body = struct.pack("!H", DTLS12) + rec[9 + 2:]
    cut = 2 + 32 + 1 + len(o["sid"])
    cookie = rnd.bytes(20)
    _, cs = _choose(t, o, srv)
    cs = cs if cs is not None else 0x002F
    seq = {True: 0, False: 0}
    room = mtu - 13 - 12

    def flight(side: bool, items) -> List[bytes]:
        """(ctype, epoch, payload) records -> datagrams."""
        grams: List[bytes] = []
        cur = b""
        for ctype, epoch, payload in items:
            s = seq[side] if epoch == 0 else 0
            if epoch == 0:
                seq[side] += 1
            hello = epoch == 0 and ctype == 22 and payload[:1] in (b"\x01",
                                                                   b"\x03")
            r = _dtls_record(ctype, DTLS10 if hello else DTLS12, epoch, s,
                             payload)
            if cur and len(cur) + len(r) > mtu:
                grams.append(cur)
                cur = b""
            cur += r
        return grams + ([cur] if cur else [])

    def hs(mtype: int, mseq: int, msg: bytes):
        return [(22, 0, f) for f in _dtls_fragments(mtype, mseq, msg, room)]

    ch1 = hs(1, 0, body[:cut] + _u8(b"") + body[cut:])
    hvr = hs(3, 0, struct.pack("!H", DTLS10) + _u8(cookie))
    ch2 = hs(1, 1, body[:cut] + _u8(cookie) + body[cut:])
    exchanges = [(flight(True, ch1), flight(False, hvr))]
    sexts = b""
    if 0x00FF in o["ciphers"]:
        sexts += _ext(0xFF01, b"\x00")
    if "extended_master_secret" in o["exts"]:
        sexts += _ext(23, b"")
    if cs in _ECDHE:
        sexts += _ext(11, _u8(b"\x00"))
    sh = struct.pack("!H", DTLS12) + rnd.bytes(32) + _u8(rnd.bytes(32)) + \
        struct.pack("!HB", cs, 0) + _u16(sexts)
    sig = struct.pack("!H", 0x0401) + _u16(rnd.bytes(256))
    msgs = [(2, sh), (11, _u24(_u24(server_cert)))]
    if cs in _ECDHE:
        group = next((gr for gr in (0x001D, 0x0017, 0x0018)
                      if gr in o["groups"]), 0x0017)
        pub = rnd.bytes(32) if group == 0x001D else b"\x04" + rnd.bytes(64)
        msgs.append((12, struct.pack("!BH", 3, group) + _u8(pub) + sig))
        cke = _u8(rnd.bytes(32) if group == 0x001D else
                  b"\x04" + rnd.bytes(64))
    else:                                   # RSA key transport
        cke = _u16(rnd.bytes(256))
    if client_cert:
        msgs.append((13, _cert_request(0x0303, ISSUERS["corp"])[4:]))
    msgs.append((14, b""))
    srecs = []
    for k, (mtype, msg) in enumerate(msgs):
        srecs += hs(mtype, 1 + k, msg)
    exchanges.append((flight(True, ch2), flight(False, srecs)))
    crecs, mseq = [], 2
    if client_cert:
        crecs += hs(11, mseq, _u24(_u24(client_cert)))
        mseq += 1
    crecs += hs(16, mseq, cke)
    mseq += 1
    if client_cert:
        crecs += hs(15, mseq, struct.pack("!H", 0x0401) + _u16(rnd.bytes(256)))
        mseq += 1
    # Finished: the first epoch-1 record (sequence 0), encrypted
    fin = 12 + 12                           # header + verify_data
    crecs += [(20, 0, b"\x01"), (22, 1, _sealed(cs, 0x0303, fin, rnd))]
    srecs = [(20, 0, b"\x01"), (22, 1, _sealed(cs, 0x0303, fin, rnd))]
    exchanges.append((flight(True, crecs), flight(False, srecs)))
    return exchanges, DtlsChannel(cs, rnd, app_seq)
