"""Remote-access, file-transfer and vendor engineering protocol builders.

Normal administrative and engineering traffic, not attacks:

* file transfer / remote access (issue #48): FTP (control + passive data),
  TFTP, an HTTP firmware upload, SSH, RDP (TLS/NLA), VNC (RFB) and Telnet —
  the cleartext credentials in FTP / Telnet / HTTP Basic are the realistic
  finding a monitor should raise, not something the builder fakes;
* vendor engineering / HMI protocols (issue #49): Siemens S7CommPlus,
  Omron FINS, Mitsubishi SLMP (MC protocol 3E frame), HART-IP and GE SRTP.

Imported from the bottom of :mod:`tgt.protocols`, which owns the registry; the
builders register themselves with ``_reg`` like every other profile.

Endpoint roles: the client is the administrator / engineering station / HMI
and the server is the device or host being managed — except TFTP, where the
device itself is the client fetching its image from (and backing its config
up to) a TFTP server, as switches, RTUs and PLC comm modules do.

Identity values come from ``ep.meta`` when present, protocol-specific keys
first (``fins_model``, ``slmp_model``, ``hart_*``, ``srtp_*``, ``s7_*``,
``ssh_banner`` ...), then the generic catalog keys ``model`` / ``firmware``,
then a representative default; :func:`tgt.devices.identity_meta` fills the
protocol keys for catalog devices.

Dissector coverage (stock Wireshark 4.6): ftp/ftp-data, tftp, http +
mime_multipart, ssh, rdp + tls, vnc, telnet, omron (FINS) and hart_ip decode
these frames. S7CommPlus (only an out-of-tree plugin exists; the payload is
COTP data in stock tshark), SLMP / MELSEC and GE SRTP have no stock dissector;
they are built to the published framing (S7CommPlus: the s7comm_plus plugin's
0x72 PDU layout; SLMP: Mitsubishi's SLMP reference manual 3E binary frame;
SRTP: the 56-byte header described by Denton et al., DFRWS 2017).
"""
from __future__ import annotations

import base64
import hashlib
import struct
import zlib
from typing import List

from . import packet as P
from .packet import Endpoints
from .protocols import (_COTP_DT, TcpSession, _der, _der_int, _der_seq, _reg,
                        _sport, _tpkt)

_MSS = 1448                 # payload per TCP segment (<= the 1460 MSS announced)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _prand(seed: str, n: int) -> bytes:
    """Deterministic pseudo-random bytes (ciphertext, keys, file content)."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}|{i}".encode()).digest()
        i += 1
    return out[:n]


def _seed(ep: Endpoints, tag: str) -> str:
    return f"{tag}|{ep.client_ip}|{ep.server_ip}"


class _Session(TcpSession):
    """:class:`~tgt.protocols.TcpSession` whose SYN / SYN-ACK announce an MSS
    of 1460 and SACK-permitted, so the full-size segments these bulk
    protocols send are within the negotiated MSS."""

    def handshake(self) -> None:
        for from_client, flags in ((True, P.SYN), (False, P.SYN | P.ACK)):
            src, dst = ((self.ep.client_ip, self.ep.server_ip) if from_client
                        else (self.ep.server_ip, self.ep.client_ip))
            sp, dp = ((self.sport, self.dport) if from_client
                      else (self.dport, self.sport))
            seq = self.c_seq if from_client else self.s_seq
            ack = 0 if from_client else self.c_seq
            seg = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 7 << 4, flags,
                              64240, 0, 0) + b"\x02\x04\x05\xb4\x01\x01\x04\x02"
            chk = P._l4_checksum(src, dst, P.IPPROTO_TCP, seg)
            seg = seg[:16] + struct.pack("!H", chk) + seg[18:]
            self.frames.append(P.ip_frame(self.ep, from_client, P.IPPROTO_TCP,
                                          seg))
            if from_client:
                self.c_seq = (self.c_seq + 1) & 0xFFFFFFFF
            else:
                self.s_seq = (self.s_seq + 1) & 0xFFFFFFFF
        self._emit(True, P.ACK)


def _flow(ep: Endpoints, sport: int, dport: int,
          exchanges: List[tuple[bytes, bytes]]) -> List[bytes]:
    """Request/response session like :func:`tgt.protocols._tcp_flow`."""
    steps: List[tuple[bool, bytes]] = []
    for req, rsp in exchanges:
        if req:
            steps.append((True, req))
        if rsp:
            steps.append((False, rsp))
    return _session(ep, sport, dport, steps).frames


def _send(s: TcpSession, from_client: bool, data: bytes) -> None:
    """Send ``data`` as MSS-sized segments (PSH on the last one), with the
    receiver ACKing every second full segment like a delayed-ACK stack."""
    chunks = [data[k:k + _MSS] for k in range(0, len(data), _MSS)] or [b""]
    for n, c in enumerate(chunks):
        last = n == len(chunks) - 1
        s._emit(from_client, (P.PSH | P.ACK) if last else P.ACK, c)
        if not last and n % 2 == 1:
            s._emit(not from_client, P.ACK)


def _session(ep: Endpoints, sport: int, dport: int,
             steps: List[tuple[bool, bytes]], teardown: bool = True,
             client_closes: bool = True) -> TcpSession:
    """One TCP session from (from_client, payload) steps, segmenting large
    payloads; returns the session so callers can splice in other frames."""
    s = _Session(ep, sport, dport)
    s.handshake()
    for from_client, data in steps:
        _send(s, from_client, data)
    if teardown:
        if client_closes:
            s.teardown()
        else:
            s._emit(False, P.FIN | P.ACK)
            s._emit(True, P.FIN | P.ACK)
            s._emit(False, P.ACK)
    return s


def _meta(ep: Endpoints, *keys: str, default=None):
    """First present ``ep.meta`` value among ``keys``."""
    for k in keys:
        v = ep.meta.get(k)
        if v not in (None, ""):
            return v
    return default


def _node(ip: str) -> int:
    return P.ip_to_bytes(ip)[3]


# ===========================================================================
# #48 — file transfer and remote access
# ===========================================================================
def _fw_name(ep: Endpoints) -> str:
    """A firmware-image file name for the managed device."""
    name = _meta(ep, "fw_file")
    if name:
        return str(name)
    model = str(_meta(ep, "model", "product", default="device"))
    model = "".join(c if c.isalnum() else "_" for c in model).strip("_")
    fw = str(_meta(ep, "firmware", default="4.2.1")).lstrip("Vv")
    fw = "".join(c if c.isalnum() or c == "." else "_" for c in fw)
    return f"{model[:24] or 'device'}_v{fw}.bin"


def _fw_image(ep: Endpoints, size: int) -> bytes:
    """A firmware-looking blob: vendor header magic + version + filler."""
    name = _fw_name(ep).encode()
    hdr = b"FWUP" + struct.pack(">II", 1, size) + name[:48].ljust(48, b"\x00")
    body = _prand(_seed(ep, "fw") + name.decode(), size - len(hdr) - 4)
    blob = hdr + body
    return blob + struct.pack(">I", zlib.crc32(blob))


def _config_text(ep: Endpoints) -> bytes:
    host = str(_meta(ep, "host", "nbname", default="sw-cell01"))
    return (f"!\n! Last configuration change at 12:00:00 UTC Mon Oct 6 2025\n!\n"
            f"version 15.2\nservice timestamps log datetime msec\n"
            f"hostname {host}\n!\nlogging host {ep.server_ip}\n"
            f"ntp server {ep.server_ip}\n!\ninterface Vlan10\n"
            f" ip address {ep.client_ip} 255.255.255.0\n!\n"
            f"snmp-server community public RO\n!\nend\n").encode()


# ---------------------------------------------------------------------------
# FTP (21 + passive data)
# ---------------------------------------------------------------------------
def ftp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """FTP (21): banner, USER/PASS in cleartext, SYST, TYPE I, then for each
    transfer PASV + RETR (config backup) or STOR (firmware image) over a
    passive data connection, 226, QUIT.

    Meta: ``ftp_banner``, ``ftp_user`` / ``ftp_password``, ``fw_file``."""
    banner = str(_meta(ep, "ftp_banner", default="220 (vsFTPd 3.0.5)"))
    if not banner[:3].isdigit():
        banner = "220 " + banner
    user = str(_meta(ep, "ftp_user", default="admin"))
    pw = str(_meta(ep, "ftp_password", default="Plant#2025"))
    ctl = _Session(ep, _sport(), 21)
    ctl.handshake()
    frames = ctl.frames
    seed = zlib.crc32(P.ip_to_bytes(ep.server_ip))

    def say(from_client: bool, line: str) -> None:
        ctl._emit(from_client, P.PSH | P.ACK, (line + "\r\n").encode())

    say(False, banner)
    for c, s in ((f"USER {user}", "331 Please specify the password."),
                 (f"PASS {pw}", "230 Login successful."),
                 ("SYST", "215 UNIX Type: L8"),
                 ("TYPE I", "200 Switching to Binary mode.")):
        say(True, c)
        say(False, s)
    a = ep.server_ip.replace(".", ",")
    for i in range(max(1, count)):
        dport = 50000 + (seed + 37 * i) % 10000
        say(True, "PASV")
        say(False, f"227 Entering Passive Mode ({a},{dport >> 8},{dport & 0xFF}).")
        if i % 2 == 0:
            name, data, up = "running-config.cfg", _config_text(ep), False
            say(True, f"RETR {name}")
        else:
            name, data, up = _fw_name(ep), _fw_image(ep, 3000), True
            say(True, f"STOR {name}")
        say(False, "150 Ok to send data." if up else
            f"150 Opening BINARY mode data connection for {name} "
            f"({len(data)} bytes).")
        # passive data connection: client -> server:dport; the sender closes
        d = _session(ep, _sport(), dport, [(up, data)], client_closes=up)
        frames.extend(d.frames)
        say(False, "226 Transfer complete.")
    say(True, "QUIT")
    say(False, "221 Goodbye.")
    ctl.teardown()
    return frames


# ---------------------------------------------------------------------------
# TFTP (69/udp + ephemeral transfer ports)
# ---------------------------------------------------------------------------
def tftp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """TFTP (69/UDP, RFC 1350 octet mode): the device (client) fetches its
    firmware image with RRQ — DATA/ACK in 512-byte blocks ending with a short
    block — and backs its configuration up with WRQ. The server answers from
    a fresh transfer port (TID), as RFC 1350 requires."""
    frames: List[bytes] = []
    ident = 0
    for i in range(max(1, count)):
        cport, sport = _sport(), _sport()  # server picks its own TID port
        read = i % 2 == 0
        if read:
            name, data = _fw_name(ep), _fw_image(ep, 1324)
        else:
            host = str(_meta(ep, "nbname", "host", default="device"))
            name, data = f"{host}-confg", _config_text(ep)
        op = 1 if read else 2
        req = struct.pack("!H", op) + name.encode() + b"\x00octet\x00"
        frames.append(P.udp_frame(ep, True, cport, 69, req, ident=ident))
        ident += 1
        blocks = [data[k:k + 512] for k in range(0, len(data) + 1, 512)]
        if not read:            # WRQ: server ACKs block 0 from its new TID
            frames.append(P.udp_frame(ep, False, sport, cport,
                                      struct.pack("!HH", 4, 0), ident=ident))
        for n, blk in enumerate(blocks, 1):
            dat = struct.pack("!HH", 3, n) + blk
            ack = struct.pack("!HH", 4, n)
            if read:
                frames.append(P.udp_frame(ep, False, sport, cport, dat,
                                          ident=ident))
                frames.append(P.udp_frame(ep, True, cport, sport, ack,
                                          ident=ident))
            else:
                frames.append(P.udp_frame(ep, True, cport, sport, dat,
                                          ident=ident))
                frames.append(P.udp_frame(ep, False, sport, cport, ack,
                                          ident=ident))
            ident += 1
    return frames


# ---------------------------------------------------------------------------
# HTTP firmware upload
# ---------------------------------------------------------------------------
def http_fw_flow(ep: Endpoints, count: int) -> List[bytes]:
    """HTTP (80) firmware upgrade of a device web server: a multipart
    ``POST`` of the image to the vendor upgrade CGI (odd cycles: a raw
    ``PUT`` to a REST endpoint), with HTTP Basic credentials in cleartext,
    answered by 200 OK. Meta: ``fw_url``, ``fw_put_url``, ``http_user`` /
    ``http_password``, ``server`` (banner), ``ua``."""
    host = str(_meta(ep, "host", default=ep.server_ip))
    ua = str(_meta(ep, "ua", default="Mozilla/5.0 (Windows NT 10.0; Win64; "
                   "x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/129.0.0.0 Safari/537.36"))
    server = str(_meta(ep, "server", default="GoAhead-Webs"))
    cred = base64.b64encode(
        f"{_meta(ep, 'http_user', default='admin')}:"
        f"{_meta(ep, 'http_password', default='admin123')}".encode()).decode()
    post_url = str(_meta(ep, "fw_url", default="/cgi-bin/firmware_upgrade.cgi"))
    put_url = str(_meta(ep, "fw_put_url", default="/api/v1/system/firmware"))
    name = _fw_name(ep)
    image = _fw_image(ep, 4096)
    steps: List[tuple[bool, bytes]] = []
    for i in range(max(1, count)):
        if i % 2 == 0:
            bnd = "----WebKitFormBoundary" + _prand(name + str(i), 8).hex()
            body = (f"--{bnd}\r\nContent-Disposition: form-data; "
                    f'name="action"\r\n\r\nupgrade\r\n'
                    f"--{bnd}\r\nContent-Disposition: form-data; "
                    f'name="firmware"; filename="{name}"\r\n'
                    f"Content-Type: application/octet-stream\r\n\r\n"
                    ).encode() + image + f"\r\n--{bnd}--\r\n".encode()
            head = (f"POST {post_url} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: {ua}\r\nAuthorization: Basic {cred}\r\n"
                    f"Content-Type: multipart/form-data; boundary={bnd}\r\n")
        else:
            body = image
            head = (f"PUT {put_url} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: {ua}\r\nAuthorization: Basic {cred}\r\n"
                    "Content-Type: application/octet-stream\r\n")
        req = (head + f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        ok = (f'{{"status":"ok","image":"{name}","size":{len(image)},'
              f'"action":"reboot-scheduled"}}').encode()
        rsp = (f"HTTP/1.1 200 OK\r\nServer: {server}\r\n"
               "Content-Type: application/json\r\n"
               f"Content-Length: {len(ok)}\r\n\r\n").encode() + ok
        steps += [(True, req), (False, rsp)]
    return _session(ep, _sport(), 80, steps).frames


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
_OSSH_MACS = ("umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
              "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
              "hmac-sha1-etm@openssh.com,umac-64@openssh.com,"
              "umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1")
_OSSH_CIPHERS = ("chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,"
                 "aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com")

# (banner, kex, host key, ciphers, MACs, compression) as each implementation
# offers them by default — the KEXINIT lists HASSH / HASSHServer hash.
_SSH_IMPL = {
    # clients
    "windows-client": (
        "SSH-2.0-OpenSSH_for_Windows_8.1",
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
        "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1,ext-info-c",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
        "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,"
        "rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
        "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        _OSSH_CIPHERS, _OSSH_MACS, "none,zlib@openssh.com,zlib"),
    "linux-client": (
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
        "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,"
        "ext-info-c",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,"
        "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,"
        "ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
        "ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,"
        "sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        _OSSH_CIPHERS, _OSSH_MACS, "none,zlib@openssh.com,zlib"),
    # servers
    "openssh": (
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
        "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "sntrup761x25519-sha512@openssh.com,"
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
        "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
        _OSSH_CIPHERS, _OSSH_MACS, "none,zlib@openssh.com"),
    "windows": (
        "SSH-2.0-OpenSSH_for_Windows_8.1",
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
        "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1",
        "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519",
        _OSSH_CIPHERS, _OSSH_MACS, "none"),
    "cisco": (
        "SSH-2.0-Cisco-1.25",
        "ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,"
        "diffie-hellman-group14-sha1",
        "ssh-rsa",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,"
        "aes256-cbc",
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96",
        "none"),
    "dropbear": (
        "SSH-2.0-dropbear_2020.81",
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,"
        "ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au",
        "ecdsa-sha2-nistp256,ssh-rsa,ssh-dss",
        "aes128-ctr,aes256-ctr",
        "hmac-sha1,hmac-sha2-256",
        "zlib@openssh.com,none"),
}

# key-exchange public value sizes: (client value, server value, is_mpint)
_SSH_KEX_SIZES = {
    "curve25519-sha256": (32, 32, False),
    "curve25519-sha256@libssh.org": (32, 32, False),
    "ecdh-sha2-nistp256": (65, 65, False),
    "ecdh-sha2-nistp384": (97, 97, False),
    "ecdh-sha2-nistp521": (133, 133, False),
    "diffie-hellman-group14-sha256": (256, 256, True),
    "diffie-hellman-group14-sha1": (256, 256, True),
    "diffie-hellman-group16-sha512": (512, 512, True),
}
_SSH_MAC_LEN = {"hmac-sha1": 20, "hmac-sha1-96": 12, "hmac-sha2-256": 32,
                "hmac-sha2-512": 64, "umac-64": 8, "umac-128": 16}


def _ssh_str(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def _ssh_mpint(b: bytes) -> bytes:
    b = b.lstrip(b"\x00")
    if b and b[0] & 0x80:
        b = b"\x00" + b
    return _ssh_str(b)


def _ssh_pkt(payload: bytes, seed: str) -> bytes:
    """Unencrypted SSH binary packet (block size 8, >= 4 bytes padding)."""
    pad = 8 - (5 + len(payload)) % 8
    if pad < 4:
        pad += 8
    return struct.pack("!IB", 1 + len(payload) + pad, pad) + payload + \
        _prand(seed, pad)


def _ssh_kexinit(algs: tuple, cookie: bytes) -> bytes:
    _, kex, hk, enc, mac, comp = algs
    lists = [kex, hk, enc, enc, mac, mac, comp, comp, "", ""]
    return b"\x14" + cookie + b"".join(_ssh_str(x.encode()) for x in lists) + \
        b"\x00" + struct.pack("!I", 0)


def _ssh_pick(client: str, server: str) -> str:
    """RFC 4253 7.1: the first client algorithm the server also supports."""
    offered = server.split(",")
    return next((a for a in client.split(",") if a in offered), "")


def _ssh_hostkey(alg: str, seed: str) -> tuple[bytes, bytes]:
    """(host key blob, signature blob) for the negotiated host-key alg."""
    if alg == "ssh-ed25519":
        return (_ssh_str(b"ssh-ed25519") + _ssh_str(_prand(seed + "hk", 32)),
                _ssh_str(b"ssh-ed25519") + _ssh_str(_prand(seed + "sig", 64)))
    if alg.startswith("ecdsa-sha2-"):
        curve = alg.rsplit("-", 1)[1].encode()
        sig = _ssh_mpint(b"\x7a" + _prand(seed + "r", 31)) + \
            _ssh_mpint(b"\x3b" + _prand(seed + "s", 31))
        return (_ssh_str(alg.encode()) + _ssh_str(curve) +
                _ssh_str(b"\x04" + _prand(seed + "hk", 64)),
                _ssh_str(alg.encode()) + _ssh_str(sig))
    n = b"\xc5" + _prand(seed + "n", 255)           # RSA-2048
    return (_ssh_str(b"ssh-rsa") + _ssh_mpint(b"\x01\x00\x01") + _ssh_mpint(n),
            _ssh_str(alg.encode()) + _ssh_str(_prand(seed + "sig", 256)))


def _ssh_server_impl(ep: Endpoints) -> str:
    impl = str(_meta(ep, "ssh_flavor", default="")).lower()
    if impl in _SSH_IMPL and not impl.endswith("-client"):
        return impl
    vendor = str(_meta(ep, "vendor", default="")).lower()
    if "cisco" in vendor:
        return "cisco"
    if str(_meta(ep, "server", default="")).startswith("Microsoft"):
        return "windows"
    if vendor and not any(v in vendor for v in ("canonical", "linux", "red hat",
                                                "microsoft", "vmware")):
        return "dropbear"                   # embedded device / appliance
    return "openssh"


def ssh_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SSH (22): version banners, KEXINIT both ways with each side's real
    default algorithm lists (so HASSH and HASSHServer differ), the key
    exchange the two lists actually negotiate (curve25519 / ECDH / DH group
    14 init + reply with host key and signature), NEWKEYS, then encrypted
    packets sized for the negotiated cipher + MAC: user auth, channel setup
    and interactive keystrokes / output.

    The server implementation follows ``ep.meta['ssh_flavor']`` (openssh |
    windows | cisco | dropbear), else is inferred from the ``vendor`` /
    ``server`` meta (Linux -> OpenSSH 8.9, Windows -> OpenSSH for Windows,
    Cisco -> Cisco-1.25, other embedded vendors -> Dropbear). The client is
    Windows' built-in OpenSSH (an engineering workstation) unless
    ``ssh_client`` is ``linux``; ``ssh_banner`` / ``ssh_client_banner``
    override the version strings."""
    srv = list(_SSH_IMPL[_ssh_server_impl(ep)])
    cli = list(_SSH_IMPL["linux-client" if str(_meta(ep, "ssh_client",
                                                     default="")) == "linux"
                         else "windows-client"])
    srv[0] = str(_meta(ep, "ssh_banner", default=srv[0]))
    cli[0] = str(_meta(ep, "ssh_client_banner", default=cli[0]))
    kex = _ssh_pick(cli[1], srv[1])
    hk_alg = _ssh_pick(cli[2], srv[2])
    cipher = _ssh_pick(cli[3], srv[3])
    mac = _ssh_pick(cli[4], srv[4])
    seed = _seed(ep, "ssh")
    s = _Session(ep, _sport(), 22)
    s.handshake()
    _send(s, False, (srv[0] + "\r\n").encode())
    _send(s, True, (cli[0] + "\r\n").encode())
    _send(s, True, _ssh_pkt(_ssh_kexinit(tuple(cli), _prand(seed + "cc", 16)),
                            seed + "p1"))
    _send(s, False, _ssh_pkt(_ssh_kexinit(tuple(srv), _prand(seed + "sc", 16)),
                             seed + "p2"))
    c_len, s_len, mp = _SSH_KEX_SIZES.get(kex, (32, 32, False))
    q_c, q_s = _prand(seed + "qc", c_len), _prand(seed + "qs", s_len)
    if kex.startswith("ecdh-sha2-"):
        q_c, q_s = b"\x04" + q_c[1:], b"\x04" + q_s[1:]
    enc_pub = _ssh_mpint if mp else _ssh_str
    hostkey, sig = _ssh_hostkey(hk_alg, seed)
    _send(s, True, _ssh_pkt(b"\x1e" + enc_pub(q_c), seed + "p3"))
    reply = b"\x1f" + _ssh_str(hostkey) + enc_pub(q_s) + _ssh_str(sig)
    _send(s, False, _ssh_pkt(reply, seed + "p4") +
          _ssh_pkt(b"\x15", seed + "p5"))
    _send(s, True, _ssh_pkt(b"\x15", seed + "p6"))
    # encrypted packets: AEAD ciphers carry a 16-byte tag; otherwise the MAC
    if cipher.startswith("chacha20") or "gcm" in cipher:
        tag = 16
    else:
        tag = _SSH_MAC_LEN.get(mac.replace("-etm@openssh.com", "")
                               .replace("@openssh.com", ""), 20)
    block = 8 if cipher.startswith("chacha20") or "3des" in cipher else 16
    k = 0

    def enc(from_client: bool, blocks: int) -> None:
        nonlocal k
        k += 1
        _send(s, from_client, _prand(f"{seed}|e{k}", 4 + 4 + block * blocks +
                                     tag))

    # service request/accept, ext-info, userauth request/success, channel
    # open/confirm, pty-req + shell
    for c, r in ((2, 2), (5, 3), (4, 2), (7, 3), (5, 2)):
        enc(True, c)
        enc(False, r)
    for i in range(max(1, count)):
        enc(True, 2)                    # keystroke / command line
        enc(False, 2 + (i % 5) * 3)     # echo + command output
    enc(True, 2)                        # channel EOF / close
    enc(False, 3)
    s.teardown()
    return s.frames


# ---------------------------------------------------------------------------
# TLS helpers (RDP)
# ---------------------------------------------------------------------------
def _tls_rec(ctype: int, body: bytes, ver: int = 0x0303) -> bytes:
    return struct.pack("!BHH", ctype, ver, len(body)) + body


def _tls_hs(htype: int, body: bytes) -> bytes:
    return struct.pack("!B", htype) + struct.pack("!I", len(body))[1:] + body


def _tls_ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!HH", etype, len(data)) + data


def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = b""
    for n in [40 * arcs[0] + arcs[1]] + arcs[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _x509_self_signed(cn: str, seed: str) -> bytes:
    """A self-signed RSA-2048 X.509 v3 certificate with subject = issuer =
    CN=<host> and the server-auth EKU — what an RDP listener presents."""
    sha256rsa = _der_seq(_oid("1.2.840.113549.1.1.11"), _der(0x05, b""))
    name = _der_seq(_der(0x31, _der_seq(_oid("2.5.4.3"),
                                        _der(0x0C, cn.encode()))))
    validity = _der_seq(_der(0x17, b"250901000000Z"), _der(0x17, b"260301000000Z"))
    modulus = int.from_bytes(b"\xc3" + _prand(seed + "mod", 255), "big")
    rsa_key = _der_seq(_der_int(modulus), _der_int(65537))
    spki = _der_seq(_der_seq(_oid("1.2.840.113549.1.1.1"), _der(0x05, b"")),
                    _der(0x03, b"\x00" + rsa_key))
    eku = _der_seq(_oid("2.5.29.37"),
                   _der(0x04, _der_seq(_oid("1.3.6.1.5.5.7.3.1"))))
    ku = _der_seq(_oid("2.5.29.15"), _der(0x04, _der(0x03, b"\x04\x30")))
    serial = int.from_bytes(b"\x1f" + _prand(seed + "ser", 15), "big")
    tbs = _der_seq(_der(0xA0, _der_int(2)), _der_int(serial), sha256rsa, name,
                   validity, name, spki, _der(0xA3, _der_seq(ku, eku)))
    return _der_seq(tbs, sha256rsa, _der(0x03, b"\x00" + _prand(seed + "sig", 256)))


# ---------------------------------------------------------------------------
# RDP
# ---------------------------------------------------------------------------
def rdp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """RDP (3389), a normal NLA logon: X.224 Connection Request with the
    ``mstshash`` cookie and RDP_NEG_REQ (PROTOCOL_SSL | PROTOCOL_HYBRID),
    Connection Confirm with RDP_NEG_RSP selecting HYBRID (CredSSP), then the
    TLS 1.2 handshake (mstsc-style ClientHello; ServerHello, the listener's
    self-signed CN=<host> certificate, ECDHE key exchange) and TLS
    application data carrying CredSSP, MCS and the session. Meta:
    ``rdp_user`` (cookie), ``host`` / ``sni`` (certificate CN)."""
    user = str(_meta(ep, "rdp_user", default="operator"))[:9]
    host = str(_meta(ep, "host", default="SCADA-SRV01"))
    fqdn = str(_meta(ep, "sni", default=host))
    seed = _seed(ep, "rdp")
    cookie = f"Cookie: mstshash={user}\r\n".encode()
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 8, 0x00000003)
    x224 = struct.pack("!BBHHB", 6 + len(cookie) + len(neg_req), 0xE0, 0, 0, 0)
    cr = _tpkt(x224 + cookie + neg_req)
    # flags: EXTENDED_CLIENT_DATA | DYNVC_GFX | RESTRICTED_ADMIN | REDIRECTED_AUTH
    neg_rsp = struct.pack("<BBHI", 0x02, 0x1F, 8, 0x00000002)
    cc = _tpkt(struct.pack("!BBHHB", 6 + len(neg_rsp), 0xD0, 0,
                           0x1234 + (zlib.crc32(seed.encode()) & 0xFFF), 0) +
               neg_rsp)
    # TLS 1.2 ClientHello as SChannel sends it (no SNI when dialled by IP)
    ciphers = (0xC02C, 0xC02B, 0xC030, 0xC02F, 0xC024, 0xC023, 0xC028, 0xC027,
               0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x003D, 0x003C,
               0x0035, 0x002F, 0x000A)
    exts = b""
    if fqdn and not fqdn.replace(".", "").isdigit():
        sn = fqdn.encode()
        exts += _tls_ext(0x0000, struct.pack("!HBH", len(sn) + 3, 0, len(sn)) + sn)
    exts += _tls_ext(0x0005, b"\x01\x00\x00\x00\x00")             # status_request
    exts += _tls_ext(0x000A, struct.pack("!HHHH", 6, 0x001D, 0x0017, 0x0018))
    exts += _tls_ext(0x000B, b"\x01\x00")                         # ec_point_formats
    sigalgs = (0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503,
               0x0203, 0x0202, 0x0601, 0x0603)
    exts += _tls_ext(0x000D, struct.pack("!H", 2 * len(sigalgs)) +
                     struct.pack(f"!{len(sigalgs)}H", *sigalgs))
    exts += _tls_ext(0x0017, b"")                                 # ext. master secret
    exts += _tls_ext(0xFF01, b"\x00")                             # renegotiation_info
    ch = struct.pack("!H", 0x0303) + _prand(seed + "cr", 32) + b"\x00" + \
        struct.pack("!H", 2 * len(ciphers)) + \
        struct.pack(f"!{len(ciphers)}H", *ciphers) + b"\x01\x00" + \
        struct.pack("!H", len(exts)) + exts
    client_hello = _tls_rec(0x16, _tls_hs(0x01, ch), 0x0301)
    sh_exts = _tls_ext(0x0017, b"") + _tls_ext(0xFF01, b"\x00")
    sh = struct.pack("!H", 0x0303) + _prand(seed + "sr", 32) + b"\x20" + \
        _prand(seed + "sid", 32) + struct.pack("!HB", 0xC030, 0) + \
        struct.pack("!H", len(sh_exts)) + sh_exts
    cert = _x509_self_signed(fqdn, seed)
    certs = struct.pack("!I", len(cert))[1:] + cert
    cert_msg = struct.pack("!I", len(certs))[1:] + certs
    point = b"\x04" + _prand(seed + "ecs", 64)
    ske = struct.pack("!BHB", 3, 0x0017, len(point)) + point + \
        struct.pack("!HH", 0x0804, 256) + _prand(seed + "skesig", 256)
    server_flight = _tls_rec(0x16, _tls_hs(0x02, sh) + _tls_hs(0x0B, cert_msg) +
                             _tls_hs(0x0C, ske) + _tls_hs(0x0E, b""))
    cpoint = b"\x04" + _prand(seed + "ecc", 64)
    client_fin = _tls_rec(0x16, _tls_hs(0x10, bytes([len(cpoint)]) + cpoint)) + \
        _tls_rec(0x14, b"\x01") + _tls_rec(0x16, _prand(seed + "cfin", 40))
    server_fin = _tls_rec(0x14, b"\x01") + _tls_rec(0x16, _prand(seed + "sfin", 40))
    steps: List[tuple[bool, bytes]] = [
        (True, cr), (False, cc), (True, client_hello), (False, server_flight),
        (True, client_fin), (False, server_fin)]
    k = 0

    def app(from_client: bool, n: int) -> None:
        nonlocal k
        k += 1
        steps.append((from_client, _tls_rec(0x17, _prand(f"{seed}|a{k}", n))))

    # CredSSP: NTLM negotiate / challenge / authenticate + pubKeyAuth, then
    # TSCredentials; then MCS Connect Initial / Response and the licensing /
    # capability exchange
    for c, r in ((93, 285), (657, 89), (377, 0), (476, 365), (310, 120),
                 (980, 1270)):
        app(True, c)
        if r:
            app(False, r)
    for i in range(max(1, count)):      # input PDUs + bitmap updates
        app(True, 37 + 8 * (i % 3))
        app(False, 420 + 260 * (i % 4))
    return _session(ep, _sport(), 3389, steps).frames


# ---------------------------------------------------------------------------
# VNC (RFB 3.8)
# ---------------------------------------------------------------------------
def vnc_flow(ep: Endpoints, count: int) -> List[bytes]:
    """VNC (5900, RFB 003.008): version exchange, security type 2 (VNC
    authentication) challenge/response, SecurityResult OK, ClientInit
    (shared), ServerInit with the desktop name, then SetPixelFormat /
    SetEncodings and framebuffer update request/response cycles.
    Meta: ``vnc_desktop`` (else ``host``); ``vnc_auth: "none"`` offers only
    security type 1 (None) — no challenge, an unauthenticated HMI."""
    desktop = str(_meta(ep, "vnc_desktop", "host", default="HMI-PANEL01")).encode()
    noauth = str(_meta(ep, "vnc_auth", default="")).lower() == "none"
    seed = _seed(ep, "vnc")
    w, h = 1280, 800
    # 32 bpp, depth 24, little-endian, true colour, 255/255/255, shifts 16/8/0
    pixfmt = struct.pack("!BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    server_init = struct.pack("!HH", w, h) + pixfmt + \
        struct.pack("!I", len(desktop)) + desktop
    encodings = (16, 5, 6, 1, 0, -239, -223, -308)    # ZRLE Hextile ... Raw
    set_enc = struct.pack("!BxH", 2, len(encodings)) + \
        struct.pack(f"!{len(encodings)}i", *encodings)
    auth = ([(False, b"\x01\x01"), (True, b"\x01")] if noauth else
            [(False, b"\x01\x02"), (True, b"\x02"),
             (False, _prand(seed + "chal", 16)),
             (True, _prand(seed + "resp", 16))])
    steps = [(False, b"RFB 003.008\n"), (True, b"RFB 003.008\n")] + auth + [
             (False, struct.pack("!I", 0)), (True, b"\x01"),
             (False, server_init),
             (True, struct.pack("!B3x", 0) + pixfmt), (True, set_enc)]
    for i in range(max(1, count)):
        x, y = 64 * (i % 8), 48 * (i % 6)
        steps.append((True, struct.pack("!BBHHHH", 3, 1 if i else 0, 0, 0,
                                        w, h)))
        rw, rh = 16, 8                                  # one Raw rectangle
        rect = struct.pack("!HHHHi", x, y, rw, rh, 0) + \
            _prand(f"{seed}|px{i}", rw * rh * 4)
        steps.append((False, struct.pack("!BxH", 0, 1) + rect))
    return _session(ep, _sport(), 5900, steps).frames


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------
_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = 255, 254, 253, 252, 251, 250, 240


def telnet_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Telnet (23): option negotiation (DO TTYPE / NAWS, WILL ECHO / SGA and
    the client's answers, TTYPE subnegotiation), a login prompt, cleartext
    username and password, a shell banner and a few read-only commands.
    Meta: ``telnet_user`` / ``telnet_password``, ``host``, ``telnet_banner``."""
    host = str(_meta(ep, "host", default="rtu01"))
    user = str(_meta(ep, "telnet_user", default="admin"))
    pw = str(_meta(ep, "telnet_password", default="admin"))
    banner = str(_meta(ep, "telnet_banner",
                       default="\r\nBusyBox v1.31.1 () built-in shell (ash)\r\n"))

    def iac(*cmds: tuple[int, int]) -> bytes:
        return b"".join(bytes([_IAC, c, o]) for c, o in cmds)

    ttype_send = bytes([_IAC, _SB, 24, 1, _IAC, _SE])
    ttype_is = bytes([_IAC, _SB, 24, 0]) + b"XTERM" + bytes([_IAC, _SE])
    naws = bytes([_IAC, _SB, 31, 0, 80, 0, 24, _IAC, _SE])
    prompt = f"{user}@{host}:~# "
    steps = [
        (False, iac((_DO, 24), (_DO, 31), (_DO, 32), (_DO, 39))),
        (True, iac((_WILL, 24), (_WILL, 31), (_WONT, 32), (_WONT, 39))),
        (True, naws),
        (False, ttype_send),
        (True, ttype_is),
        (False, iac((_WILL, 3), (_DO, 1), (_WILL, 1))),
        (True, iac((_DO, 3), (_WONT, 1), (_DO, 1))),
        (False, f"\r\n{host} login: ".encode()),
        (True, f"{user}\r\n".encode()),
        (False, f"{user}\r\nPassword: ".encode()),
        (True, f"{pw}\r\n".encode()),
        (False, f"\r\n{banner}\r\n{prompt}".encode()),
    ]
    cmds = [("uptime", " 12:00:41 up 41 days,  3:12,  load average: 0.08, "
             "0.05, 0.01"),
            ("cat /proc/version", "Linux version 4.14.98 (gcc version 8.3.0) "
             "#1 SMP PREEMPT"),
            ("ifconfig eth0 | head -2",
             f"eth0      Link encap:Ethernet  HWaddr {ep.server_mac.upper()}\r\n"
             f"          inet addr:{ep.server_ip}  Bcast:0.0.0.0  "
             "Mask:255.255.255.0"),
            ("df -h /", "Filesystem   Size  Used Avail Use% Mounted on\r\n"
             "/dev/root    122M   87M   35M  72% /")]
    for i in range(max(1, count)):
        c, out = cmds[i % len(cmds)]
        steps.append((True, f"{c}\r\n".encode()))
        steps.append((False, f"{c}\r\n{out}\r\n{prompt}".encode()))
    steps.append((True, b"exit\r\n"))
    steps.append((False, b"exit\r\n"))
    return _session(ep, _sport(), 23, steps, client_closes=False).frames


# ===========================================================================
# #49 — vendor engineering protocols
# ===========================================================================
# ---------------------------------------------------------------------------
# Siemens S7CommPlus (TIA Portal / HMI <-> S7-1200/1500)
# ---------------------------------------------------------------------------
def _vlq(n: int) -> bytes:
    """S7CommPlus unsigned variable-length quantity (7 bits per byte, MSB
    first, high bit = continuation)."""
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


def _s7p_wstr(s: str) -> bytes:                    # PValue WString
    b = s.encode()
    return b"\x00\x15" + _vlq(len(b)) + b


def _s7p_udint(v: int) -> bytes:                   # PValue UDInt
    return b"\x00\x04" + _vlq(v)


def _s7p_attr(attr_id: int, pvalue: bytes) -> bytes:
    return b"\xa3" + _vlq(attr_id) + pvalue


def _s7p_object(rel_id: int, class_id: int, attrs: bytes) -> bytes:
    return b"\xa1" + struct.pack("!I", rel_id) + _vlq(class_id) + _vlq(0) + \
        _vlq(0) + attrs + b"\xa2"


def _s7p(version: int, data: bytes, digest: bytes = b"") -> bytes:
    """One S7CommPlus PDU in TPKT/COTP DT: 0x72 header (protocol id, version,
    data length), V3 integrity part (digest length + 32-byte digest), data,
    and the 0x72 trailer."""
    if version == 3:
        data = bytes([len(digest)]) + digest + data
    return _tpkt(_COTP_DT + struct.pack("!BBH", 0x72, version, len(data)) +
                 data + struct.pack("!BBH", 0x72, version, 0))


def _s7p_req(func: int, seq: int, session: int, body: bytes,
             flags: int = 0x34) -> bytes:
    return struct.pack("!BHHHHIB", 0x31, 0, func, 0, seq, session, flags) + body


def _s7p_rsp(func: int, seq: int, body: bytes, flags: int = 0x00) -> bytes:
    return struct.pack("!BHHHHB", 0x32, 0, func, 0, seq, flags) + body


def s7plus_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7CommPlus (102): COTP connect to the ``SIMATIC-ROOT-HMI`` TSAP,
    CreateObject (V1, ServerSession) whose response carries the CPU's order
    number and firmware, SetMultiVariables echoing the session version, then
    integrity-protected (V3) GetMultiVariables polls of DB tags, and
    DeleteObject on close — an HMI / TIA Portal session to an S7-1500.
    Meta: ``s7_order`` / ``order``, ``s7_firmware`` (major, minor, patch),
    ``s7plus_tsap``."""
    order = str(_meta(ep, "s7_order", "order", default="6ES7 516-3AN01-0AB0"))
    if not order.startswith("6ES7"):
        order = "6ES7 516-3AN01-0AB0"
    fw = _meta(ep, "s7_firmware", default=(2, 8, 3))
    fw_s = f"V{fw[0]}.{fw[1]}" if isinstance(fw, (tuple, list)) else str(fw)
    tsap = str(_meta(ep, "s7plus_tsap", default="SIMATIC-ROOT-HMI")).encode()
    seed = _seed(ep, "s7p")
    params = b"\xc0\x01\x0a\xc1\x02\x06\x00\xc2" + bytes([len(tsap)]) + tsap
    cr = _tpkt(struct.pack("!BBHHB", 6 + len(params), 0xE0, 0, 0x0004, 0) + params)
    cc = _tpkt(struct.pack("!BBHHB", 6 + len(params), 0xD0, 0x0004, 0x0C1E, 0) +
               params)
    session = 0x70000000 | (zlib.crc32(seed.encode()) & 0xFFFF)
    client_info = "1:::6.0::TCP/IP -> Intel(R) Ethernet Connection I219-LM.TCPIP.1"
    create = _s7p(1, _s7p_req(0x04CA, 1, 0x00000120, struct.pack("!I", 0x11D) +
                              _s7p_udint(0) + struct.pack("!I", 0) +
                              _s7p_object(0xD3, 0x11F, _s7p_attr(
                                  233, _s7p_wstr("ServerSession_%08X" % session)) +
                                  _s7p_attr(289, _s7p_wstr(client_info))) +
                              struct.pack("!I", 0), flags=0x36))
    plc_info = f"1;{order} ;{fw_s}"
    version_struct = b"\x00\x17" + struct.pack("!I", 314) + \
        _vlq(319) + _s7p_wstr(plc_info) + _vlq(320) + _s7p_udint(3) + b"\x00"
    created = _s7p(1, _s7p_rsp(0x04CA, 1, _vlq(0) + _vlq(1) + _vlq(session) +
                               _s7p_object(session, 0x11F,
                                           _s7p_attr(306, version_struct)) +
                               struct.pack("!I", 0)))
    exchanges = [(cr, cc), (create, created)]
    seq = 2

    def v3(data: bytes, k: int) -> bytes:
        return _s7p(3, data, _prand(f"{seed}|d{k}", 32))

    # SetMultiVariables: echo the ServerSessionVersion into the session
    setv = _s7p_req(0x0542, seq, session, struct.pack("!I", session) +
                    _vlq(1) + _vlq(1) + _vlq(306) + _vlq(1) + version_struct +
                    b"\x00" + _vlq(seq) + struct.pack("!I", 0))
    setr = _s7p_rsp(0x0542, seq, _vlq(0) + b"\x00" + _vlq(seq) +
                    struct.pack("!I", 0))
    exchanges.append((v3(setv, 0), v3(setr, 1)))
    for i in range(max(1, count)):
        seq += 1
        nitems = 3
        items = b""
        for t in range(nitems):     # SymbolCrc, AccessArea DB1, LID count, ...
            items += b"\x00" + _vlq(0x8A0E0001) + _vlq(2) + _vlq(0x0A) + \
                _vlq(1 + t + 2 * (i % 4))
        req = _s7p_req(0x054C, seq, session, struct.pack("!I", 0) +
                       _vlq(nitems) + _vlq(nitems * 4) + items + _vlq(seq) +
                       struct.pack("!I", 0))
        vals = b""
        for t in range(nitems):     # item number + PValue (Real)
            vals += _vlq(t + 1) + b"\x00\x0e" + \
                struct.pack("!f", 20.0 + 1.5 * t + 0.1 * i)
        rsp = _s7p_rsp(0x054C, seq, _vlq(0) + vals + b"\x00" + b"\x00" +
                       _vlq(seq) + struct.pack("!I", 0))
        exchanges.append((v3(req, 2 * i + 2), v3(rsp, 2 * i + 3)))
    seq += 1
    delete = _s7p_req(0x04D4, seq, session, struct.pack("!I", session) +
                      struct.pack("!I", 0))
    deleted = _s7p_rsp(0x04D4, seq, _vlq(0) + _vlq(session) +
                       struct.pack("!I", 0))
    exchanges.append((v3(delete, 998), v3(deleted, 999)))
    return _flow(ep, _sport(), 102, exchanges)


# ---------------------------------------------------------------------------
# Omron FINS (UDP 9600)
# ---------------------------------------------------------------------------
def fins_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Omron FINS/UDP (9600): Controller Data Read (0501: CPU model and
    version, e.g. NJ501-1500), then Memory Area Read (0101) polls of DM words
    with an occasional Memory Area Write (0102) setpoint — Sysmac Studio /
    CX-Programmer or an HMI against an NJ/CJ controller. FINS node numbers
    follow the last IP octet, as Omron's automatic address conversion does.
    Meta: ``fins_model`` (else ``model``), ``fins_version`` (else
    ``firmware``)."""
    model = str(_meta(ep, "fins_model", "model", default="NJ501-1500"))[:20]
    version = str(_meta(ep, "fins_version", "firmware", default="01.48"))[:20]
    dna, da1, sna, sa1 = 0, _node(ep.server_ip), 0, _node(ep.client_ip)

    def hdr(resp: bool, sid: int) -> bytes:
        if resp:
            return bytes([0xC0, 0, 0x02, sna, sa1, 0, dna, da1, 0, sid])
        return bytes([0x80, 0, 0x02, dna, da1, 0, sna, sa1, 0, sid])

    msgs: List[tuple[bytes, bytes]] = []
    sid = 0
    ident = model.encode().ljust(20, b" ") + version.encode().ljust(20, b" ")
    # area data: program area (Kwords), IOM (KB), DM words, timers/counters,
    # EM banks, (steps) reserved, memory card type + size
    area = struct.pack(">HBHBBHBH", 20, 23, 32768, 8, 0, 0, 0, 0)
    msgs.append((hdr(False, sid) + b"\x05\x01\x00",
                 hdr(True, sid) + b"\x05\x01\x00\x00" + ident +
                 bytes(40) + area))
    for i in range(max(1, count)):
        sid = (sid + 1) & 0xFF
        if i % 6 == 5:          # write 2 DM words (setpoints) at D200
            vals = struct.pack(">HH", 0x0100 + i, 0x00C8)
            req = hdr(False, sid) + b"\x01\x02\x82" + struct.pack(">HBH", 200, 0, 2) + vals
            rsp = hdr(True, sid) + b"\x01\x02\x00\x00"
        else:                   # read 10 DM words at D100
            req = hdr(False, sid) + b"\x01\x01\x82" + struct.pack(">HBH", 100, 0, 10)
            data = b"".join(struct.pack(">H", (0x0200 + 7 * i + w) & 0xFFFF)
                            for w in range(10))
            rsp = hdr(True, sid) + b"\x01\x01\x00\x00" + data
        msgs.append((req, rsp))
    frames = []
    for n, (req, rsp) in enumerate(msgs):
        frames.append(P.udp_frame(ep, True, 9600, 9600, req, ident=n))
        frames.append(P.udp_frame(ep, False, 9600, 9600, rsp, ident=n))
    return frames


# ---------------------------------------------------------------------------
# Mitsubishi SLMP / MC protocol 3E binary frame (TCP 5007)
# ---------------------------------------------------------------------------
def _slmp_req(cmd: int, sub: int, data: bytes) -> bytes:
    # subheader 5000, network 0, PC 0xFF, dest module I/O 03FF (own CPU),
    # station 0, length (timer..data), monitoring timer 0x0010 (4 s)
    body = struct.pack("<HHH", 0x0010, cmd, sub) + data
    return b"\x50\x00\x00\xff" + struct.pack("<HBH", 0x03FF, 0, len(body)) + body


def _slmp_rsp(data: bytes, end: int = 0) -> bytes:
    body = struct.pack("<H", end) + data
    return b"\xd0\x00\x00\xff" + struct.pack("<HBH", 0x03FF, 0, len(body)) + body


def slmp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Mitsubishi SLMP (MC protocol 3E binary frame, TCP 5007): Read Type
    Name (0101: CPU model name + model code, e.g. R04CPU / 0x4800), then Batch
    Read (0401) of D registers with an occasional Batch Write (1401) — GX
    Works / an HMI against a MELSEC iQ-R or Q CPU. Meta: ``slmp_model``
    (else ``model``), ``slmp_model_code``, ``slmp_port``."""
    model = str(_meta(ep, "slmp_model", "model", default="R04CPU"))[:16]
    code = int(_meta(ep, "slmp_model_code", default=0x4800))
    port = int(_meta(ep, "slmp_port", default=5007))
    d_code = 0xA8                                   # device D (data register)
    exchanges = [(_slmp_req(0x0101, 0x0000, b""),
                  _slmp_rsp(model.encode().ljust(16, b" ") +
                            struct.pack("<H", code)))]
    for i in range(max(1, count)):
        if i % 6 == 5:          # Batch Write 2 words at D200
            vals = struct.pack("<HH", 0x0100 + i, 1500)
            req = _slmp_req(0x1401, 0x0000, (200).to_bytes(3, "little") +
                            bytes([d_code]) + struct.pack("<H", 2) + vals)
            rsp = _slmp_rsp(b"")
        else:                   # Batch Read 10 words at D100
            req = _slmp_req(0x0401, 0x0000, (100).to_bytes(3, "little") +
                            bytes([d_code]) + struct.pack("<H", 10))
            rsp = _slmp_rsp(b"".join(struct.pack("<H", (0x0300 + 5 * i + w)
                                                 & 0xFFFF) for w in range(10)))
        exchanges.append((req, rsp))
    return _flow(ep, _sport(), port, exchanges)


# ---------------------------------------------------------------------------
# HART-IP (TCP 5094)
# ---------------------------------------------------------------------------
def _hart_pdu(delim: int, addr: bytes, cmd: int, data: bytes,
              status: bytes = b"") -> bytes:
    body = bytes([delim]) + addr + bytes([cmd, len(status) + len(data)]) + \
        status + data
    chk = 0
    for b in body:
        chk ^= b
    return body + bytes([chk])


def _hartip(mtype: int, mid: int, seq: int, body: bytes, status: int = 0) -> bytes:
    return struct.pack("!BBBBHH", 1, mtype, mid, status, seq & 0xFFFF,
                       8 + len(body)) + body


def hart_ip_flow(ep: Endpoints, count: int) -> List[bytes]:
    """HART-IP (TCP 5094): Session Initiate (primary host), pass-through
    command 0 (Read Unique Identifier: manufacturer, expanded device type,
    revisions, device ID), command 20 (Read Long Tag) on the long-frame
    address it returned, command 3 (dynamic variables + loop current) polls
    and keep-alives, then Session Close — an asset-management host against a
    HART-IP gateway / field device. Meta: ``hart_manufacturer_id``,
    ``hart_device_type`` (expanded), ``hart_device_rev``, ``hart_sw_rev``,
    ``hart_hw_rev``, ``hart_device_id`` (24-bit), ``hart_tag``."""
    mfr = int(_meta(ep, "hart_manufacturer_id", default=0x0026))  # Rosemount
    dtype = int(_meta(ep, "hart_device_type", default=0x2606))
    dev_rev = int(_meta(ep, "hart_device_rev", default=10))
    sw_rev = int(_meta(ep, "hart_sw_rev", default=4))
    hw_rev = int(_meta(ep, "hart_hw_rev", default=5))
    dev_id = _meta(ep, "hart_device_id")
    if dev_id is None:
        dev_id = zlib.crc32(P.mac_to_bytes(ep.server_mac)) & 0xFFFFFF
    dev_id = int(dev_id) & 0xFFFFFF
    tag = str(_meta(ep, "hart_tag", "host", default="PT-101"))[:32]
    status = b"\x00\x00"                    # response code 0, device status 0
    short = b"\x80"                         # primary master, polling address 0
    long_addr = bytes([0x80 | ((dtype >> 8) & 0x3F), dtype & 0xFF]) + \
        dev_id.to_bytes(3, "big")
    seq = 1
    timer = struct.pack("!BI", 1, 600000)   # primary host, 10 min inactivity
    exchanges = [(_hartip(0, 0, seq, timer), _hartip(1, 0, seq, timer))]
    cmd0 = bytes([254]) + struct.pack("!H", dtype) + bytes([
        5, 7, dev_rev, sw_rev, (hw_rev << 3) | 0, 0x00]) + \
        dev_id.to_bytes(3, "big") + bytes([5, 4]) + struct.pack("!H", 3) + \
        bytes([0]) + struct.pack("!HH", mfr, mfr) + bytes([1])
    seq += 1
    exchanges.append((
        _hartip(0, 3, seq, _hart_pdu(0x02, short, 0, b"")),
        _hartip(1, 3, seq, _hart_pdu(0x06, short, 0, cmd0, status))))
    seq += 1
    exchanges.append((
        _hartip(0, 3, seq, _hart_pdu(0x82, long_addr, 20, b"")),
        _hartip(1, 3, seq, _hart_pdu(0x86, long_addr, 20,
                                     tag.encode("latin-1").ljust(32, b"\x00"),
                                     status))))
    for i in range(max(1, count)):
        seq += 1
        if i % 5 == 4:
            exchanges.append((_hartip(0, 2, seq, b""), _hartip(1, 2, seq, b"")))
            continue
        pv = 4.0 + 0.05 * (i % 20)          # loop current mA / PV in bar
        dyn = struct.pack("!f", 4.0 + 16.0 * (pv - 4.0) / 10.0) + \
            bytes([7]) + struct.pack("!f", pv) + \
            bytes([32]) + struct.pack("!f", 21.5 + 0.1 * (i % 7)) + \
            bytes([7]) + struct.pack("!f", pv) + \
            bytes([7]) + struct.pack("!f", pv)
        exchanges.append((
            _hartip(0, 3, seq, _hart_pdu(0x82, long_addr, 3, b"")),
            _hartip(1, 3, seq, _hart_pdu(0x86, long_addr, 3, dyn, status))))
    seq += 1
    exchanges.append((_hartip(0, 1, seq, b""), _hartip(1, 1, seq, b"")))
    return _flow(ep, _sport(), 5094, exchanges)


# ---------------------------------------------------------------------------
# GE SRTP (TCP 18245)
# ---------------------------------------------------------------------------
_SRTP_SEG = {"R": 0x08, "AI": 0x0A, "AQ": 0x0C, "I": 0x10, "Q": 0x12, "M": 0x16}


def _srtp(kind: int, seq: int, msg_type: int, mbox_src: bytes, mbox_dst: bytes,
          svc: bytes, text: bytes = b"") -> bytes:
    """One 56-byte SRTP header (+ optional text): type at 0, sequence at 2
    and 30, text length at 4, message type at 31, mailbox source/destination
    at 32/36, packet n of m at 40/41, service request / status + inline data
    at 42..55."""
    h = bytearray(56)
    h[0] = kind
    h[2] = seq & 0xFF
    h[4:6] = struct.pack("<H", len(text))
    h[9] = 0x01
    h[17] = 0x01
    h[30] = seq & 0xFF
    h[31] = msg_type
    h[32:36] = mbox_src
    h[36:40] = mbox_dst
    h[40], h[41] = 1, 1
    h[42:42 + len(svc)] = svc
    return bytes(h) + text


def srtp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """GE SRTP (TCP 18245): the 56-byte all-zero initialise message and its
    acknowledgement, then Read System Memory (service 0x04) requests for
    %R registers (and %AI words every third poll) answered with the data —
    Proficy / an HMI against a PACSystems RX3i / Series 90 PLC. Replies of up
    to 6 bytes ride inline in the header (message type 0x94); longer ones
    follow it as text (0xD4). Meta: ``srtp_r_start`` (0-based %R offset)."""
    start = int(_meta(ep, "srtp_r_start", default=0))
    host_box = b"\x00\x00\x00\x00"
    plc_box = b"\x10\x0e\x00\x00"
    init_ack = bytearray(56)
    init_ack[0] = 0x01
    init_ack[8] = 0x0F
    exchanges = [(bytes(56), bytes(init_ack))]
    for i in range(max(1, count)):
        seq = (i + 1) & 0xFF
        if i % 3 == 2:
            seg, off, n = _SRTP_SEG["AI"], 0, 2       # 2 %AI words, inline
        else:
            seg, off, n = _SRTP_SEG["R"], start + 10 * (i % 4), 8
        req = _srtp(0x02, seq, 0xC0, host_box, plc_box,
                    struct.pack("<BBHH", 0x04, seg, off, n))
        data = b"".join(struct.pack("<H", (0x0400 + 3 * i + w) & 0xFFFF)
                        for w in range(n))
        if len(data) <= 6:
            rsp = _srtp(0x03, seq, 0x94, plc_box, host_box,
                        b"\x00\x00" + data.ljust(6, b"\x00"))
        else:
            rsp = _srtp(0x03, seq, 0xD4, plc_box, host_box, b"\x00\x00", data)
        exchanges.append((req, rsp))
    return _flow(ep, _sport(), 18245, exchanges)


# ===========================================================================
# Registry
# ===========================================================================
_reg("ftp", "FTP", "IT", "21", "tcp", ftp_flow,
     "Cleartext login, PASV RETR config / STOR firmware over a data channel")
_reg("tftp", "TFTP", "IT", "69", "udp", tftp_flow,
     "Device RRQ of a firmware image + WRQ config backup, DATA/ACK blocks")
_reg("http-fw", "HTTP firmware upload", "IT", "80", "tcp", http_fw_flow,
     "Multipart POST / raw PUT of a firmware image with Basic auth")
_reg("ssh", "SSH", "IT", "22", "tcp", ssh_flow,
     "Banners, per-side KEXINIT (HASSH), ECDH kex, NEWKEYS, encrypted session")
_reg("rdp", "RDP", "IT", "3389", "tcp", rdp_flow,
     "X.224 CR (mstshash, SSL|HYBRID), NEG_RSP, TLS 1.2 handshake + NLA data")
_reg("vnc", "VNC (RFB)", "IT", "5900", "tcp", vnc_flow,
     "RFB 003.008, VNC auth challenge/response, ServerInit desktop name")
_reg("telnet", "Telnet", "IT", "23", "tcp", telnet_flow,
     "Option negotiation, cleartext login, shell commands")
_reg("s7plus", "S7CommPlus (S7-1500)", "OT", "102", "tcp", s7plus_flow,
     "CreateObject session (order no. + FW), V3 GetMultiVariables polls")
_reg("fins", "Omron FINS", "OT", "9600", "udp", fins_flow,
     "Controller Data Read (model/version), DM memory area read/write")
_reg("slmp", "Mitsubishi SLMP", "OT", "5007", "tcp", slmp_flow,
     "3E frame: Read Type Name (CPU model), D-register batch read/write")
_reg("hart-ip", "HART-IP", "OT", "5094", "tcp", hart_ip_flow,
     "Session initiate, cmd 0 unique ID, cmd 20 long tag, cmd 3 PV polls")
_reg("srtp", "GE SRTP", "OT", "18245", "tcp", srtp_flow,
     "Init + Read System Memory of %R / %AI registers (PACSystems RX3i)")
