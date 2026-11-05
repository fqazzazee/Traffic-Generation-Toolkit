"""Example TGT plugin: "Acme" smart sensors speaking CoAP.

Load it with::

    TGT_PLUGIN_PATH=examples/plugins tgt list            # shows what it adds
    TGT_PLUGIN_PATH=examples/plugins tgt run -p coap --pcap coap.pcap --once --rate 0
    TGT_PLUGIN_PATH=examples/plugins tgt run --env acme-plant --pcap acme.pcap --once --rate 0
    TGT_PLUGIN_PATH=examples/plugins tgt run --env acme-plant --sprinkle acme-valve-tamper ...

or copy this file (with ``acme-plant.json`` and ``acme-siem.json``) into
``~/.config/tgt/plugins/``. Self-test: ``python3 examples/plugins/acme_plant.py``
(builds every registration and, with tshark on PATH, checks the frames
decode as CoAP with no warnings).

It registers, through the :mod:`tgt.plugins` API:

* protocol ``coap`` — CoAP (RFC 7252) GET of sensor resources, 2.05 Content
  JSON replies (Wireshark layer ``coap``);
* scenario ``acme-iiot`` — CoAP sensors + MQTT telemetry;
* device model ``acme-sx1`` — the Acme SX-1 smart sensor;
* environment ``acme-plant`` — from ``acme-plant.json`` next to this file;
* attack ``coap-put`` (category ``ot-write``) and incident
  ``acme-valve-tamper`` that uses it;
* score map ``acme-siem`` — an alert map for ``tgt score --alert-map``.
"""
from __future__ import annotations

import os
import struct
import sys

if __name__ == "__main__":          # standalone self-test from a checkout
    sys.path.insert(0, os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..")))

from tgt import packet as P                     # noqa: E402
from tgt import plugins                         # noqa: E402
from tgt.devices import DeviceModel             # noqa: E402
from tgt.enterprise import Host                 # noqa: E402
from tgt.incidents import Incident              # noqa: E402
from tgt.protocols import _cycle_base, _sport   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
COAP_PORT = 5683


# --- CoAP wire format ------------------------------------------------------
def _option(prev: int, number: int, value: bytes) -> bytes:
    """One CoAP option (delta and length < 13 here: one header byte)."""
    delta = number - prev
    assert delta < 13 and len(value) < 13
    return bytes([(delta << 4) | len(value)]) + value


def coap_message(mtype: int, code: int, mid: int, token: bytes,
                 path: str = "", fmt=None, payload: bytes = b"") -> bytes:
    """mtype 0 CON / 2 ACK; code 0.01 GET = 0x01, 0.03 PUT = 0x03,
    2.04 Changed = 0x44, 2.05 Content = 0x45."""
    out = bytes([0x40 | (mtype << 4) | len(token), code]) + \
        struct.pack("!H", mid & 0xFFFF) + token
    prev = 0
    for seg in [s for s in path.split("/") if s]:
        out += _option(prev, 11, seg.encode())       # Uri-Path
        prev = 11
    if fmt is not None:
        out += _option(prev, 12, bytes([fmt]) if fmt else b"")  # Content-Format
    if payload:
        out += b"\xff" + payload
    return out


def coap_flow(ep: P.Endpoints, count: int):
    """Client GETs /sensors/<n>/value; the sensor answers 2.05 Content
    (application/json, piggybacked ACK)."""
    sport = _sport()
    cb = _cycle_base(count)
    frames = []
    for i in range(count):
        mid = (cb + i + 1) & 0xFFFF
        token = struct.pack("!H", (0xAC00 + cb + i) & 0xFFFF)
        path = f"sensors/{1 + i % 3}/value"
        req = coap_message(0, 0x01, mid, token, path)
        body = b'{"v":%d.%d,"u":"degC"}' % (20 + i % 5, (cb + i) % 10)
        resp = coap_message(2, 0x45, mid, token, fmt=50, payload=body)
        frames.append(P.udp_frame(ep, True, sport, COAP_PORT, req, ident=i))
        frames.append(P.udp_frame(ep, False, COAP_PORT, sport, resp, ident=i))
    return frames


def coap_put(ep: P.Endpoints, count: int):
    """Unauthorized actuator write: CoAP PUT /actuators/valve "OPEN"."""
    sport = _sport()
    frames = []
    for i in range(max(1, count)):
        mid, token = 0x7000 + i, b"\xde\xad"
        req = coap_message(0, 0x03, mid, token, "actuators/valve", fmt=0,
                           payload=b"OPEN")
        ack = coap_message(2, 0x44, mid, token)
        frames.append(P.udp_frame(ep, True, sport, COAP_PORT, req, ident=i))
        frames.append(P.udp_frame(ep, False, COAP_PORT, sport, ack, ident=i))
    return frames


# --- registrations -----------------------------------------------------------
plugins.register_protocol(
    "coap", "CoAP", "OT", str(COAP_PORT), "udp", coap_flow,
    "CoAP GET of sensor values, 2.05 Content JSON replies (Acme plugin)",
    dissector="coap")

plugins.register_scenario(
    "acme-iiot", "Acme IIoT Sensors", ["coap", "mqtt"],
    "Acme SX-1 smart sensors polled over CoAP plus MQTT telemetry to the "
    "edge broker (example plugin).")

plugins.register_device_model(DeviceModel(
    model_id="acme-sx1", vendor="Acme Instruments",
    product="SX-1 Smart Sensor", device_type="meter",
    ouis=("00:1b:c5",), purdue_level="1", os_family="Acme RTOS",
    firmware=("2.4.1", "2.5.0"), serial_format="SX1-######",
    banners={"http": "Acme-SX/{firmware}"}, aliases=("SX-1",)))

plugins.register_attack(
    "coap-put", coap_put, "Unauthorized CoAP PUT to an actuator",
    category="ot-write", protocol="coap", service="coap")

plugins.register_incident(Incident(
    "acme-valve-tamper", "Acme Valve Tamper", "OT", "2026",
    "Example plugin incident: a rogue laptop on the sensor network opens a "
    "valve with unauthenticated CoAP PUTs after a quick port sweep.",
    [Host("ROGUE-LAPTOP", "10.77.10.66", "3c:52:82:00:00:66", "ws", "win10"),
     Host("SX1-03", "10.77.10.23", "00:1b:c5:00:00:23", "meter", "linux",
          model="acme-sx1")],
    [("ROGUE-LAPTOP", "SX1-03", "port-scan", {"scan_ports": [5683, 80]}),
     ("ROGUE-LAPTOP", "SX1-03", "coap-put", {})]))

plugins.register_env_file(os.path.join(HERE, "acme-plant.json"))
plugins.register_scoremap("acme-siem", os.path.join(HERE, "acme-siem.json"))


# --- self-test ---------------------------------------------------------------
def selftest() -> int:
    import shutil
    import subprocess
    import tempfile
    from tgt import enterprise, incidents, protocols, score
    from tgt.pcap import PcapWriter
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    protocols.begin_build(1, 0)
    frames = protocols.get("coap").build(P.Endpoints(), 4)
    check(len(frames) == 8, "coap: 4 exchanges -> 8 frames")
    put = coap_put(P.Endpoints(), 1)
    env = enterprise.get("acme-plant")
    batch = env.build(2)
    check(any(k == "coap" for k, _ in batch), "acme-plant: no CoAP flows")
    inc = incidents.get("acme-valve-tamper")
    mapping = inc.map_onto(env)
    check(mapping.get("SX1-03") is not None and
          mapping["SX1-03"].model == "acme-sx1",
          "incident does not map onto an Acme sensor")
    check(score.load_json_spec("acme-siem")["format"] == "csv",
          "score map not found")
    tshark = shutil.which("tshark")
    if tshark:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "coap.pcap")
            with PcapWriter(path) as w:
                for f in frames + put + [f for _, f in batch]:
                    w.write(f)
            out = subprocess.run(
                [tshark, "-r", path, "-Y", "coap", "-T", "fields",
                 "-e", "coap.code", "-e", "coap.opt.uri_path"],
                capture_output=True, text=True).stdout.split("\n")
            check(sum(1 for ln in out if ln.startswith("1\t")) >= 4,
                  f"tshark: CoAP GETs not decoded: {out[:4]}")
            check(any(ln.startswith("3\t") for ln in out),
                  "tshark: CoAP PUT not decoded")
            expert = subprocess.run([tshark, "-r", path, "-q", "-z",
                                     "expert,note"],
                                    capture_output=True, text=True).stdout
            bad = [ln for ln in expert.splitlines() if "Malformed" in ln or
                   "Warning" in ln or "Error" in ln]
            check(not bad, f"tshark expert: {bad[:3]}")
    for f in fails:
        print(f"FAIL: {f}")
    print("acme_plant plugin self-test: " + ("FAILED" if fails else "ok")
          + ("" if tshark else " (tshark not found: dissection skipped)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(selftest())
