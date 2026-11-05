"""Local HTTP control API for a running ``tgt run`` (stdlib ``http.server``).

``tgt run ... --api 127.0.0.1:8787`` serves, in a background thread:

=======================  ====================================================
``GET  /status``         JSON: running/paused, packets/bytes/errors, pps,
                         uptime, cycles, seed, rate, per-profile and
                         per-interface counters, the run config, injections
``GET  /manifest``       the live run manifest (same JSON as ``--manifest``)
``GET  /injections``     the injection records only
``POST /stop``           stop the run (pcap/manifest are flushed as on Ctrl-C)
``POST /pause``          hold sending (``/resume`` continues)
``POST /resume``
``POST /rate?pps=N``     re-pace a rate-limited run
``POST /inject?incident=KEY[&duration=60][&ratio=0.05]``
                         sprinkle an existing incident for ``duration``
                         seconds (see :mod:`tgt.control`); recorded in the
                         manifest with its exact first/last frame times
=======================  ====================================================

Parameters may be query parameters or a JSON / form body. Replies are JSON
(``{"ok": true, ...}`` or ``{"ok": false, "error": "..."}``).

Security: the server binds loopback only unless ``--api-allow-remote`` (which
then requires ``--api-token``). With a token every request needs
``Authorization: Bearer <token>``. Requests carrying a browser ``Origin``
header, or a ``Host`` header that is not the loopback address the server is
bound to, are refused, so a web page cannot drive (or read) the API by
cross-site requests or DNS rebinding.

``tgt ctl status|stop|pause|resume|rate|inject|manifest`` is the matching
client (:func:`request`, urllib only).

Using it from the TUI later: the TUI already runs an :class:`~tgt.engine.Engine`
in-process, so it can call ``engine.control`` directly (``pause()``,
``inject(key, duration)``, ``status()``) for a key binding, and start a
:class:`ControlServer` on the same engine to let ``tgt ctl`` / scripts steer a
TUI-launched run; a TUI could also *attach* to a headless run (systemd
service, container) by polling ``GET /status`` with :func:`request` instead of
reading ``engine.stats``.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import socket
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

API_VERSION = 1
DEFAULT_BIND = "127.0.0.1:8787"


class ApiError(Exception):
    pass


def parse_bind(spec: str) -> Tuple[str, int]:
    """``"127.0.0.1:8787"``, ``"8787"``, ``":8787"``, ``"[::1]:8787"``,
    ``"localhost:9000"`` -> (host, port); host defaults to 127.0.0.1."""
    spec = (spec or "").strip()
    host, port = "127.0.0.1", spec
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        port = rest.lstrip(":")
    elif spec.count(":") == 1:
        host, port = spec.split(":")
        host = host or "127.0.0.1"
    elif spec.count(":") > 1:
        raise ApiError(f"bad address {spec!r}: write IPv6 as [addr]:port")
    try:
        p = int(port)
    except ValueError:
        raise ApiError(f"bad address {spec!r}: need [HOST:]PORT")
    if not 0 <= p <= 65535:
        raise ApiError(f"bad port {p}")
    return host, p


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _json_safe(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=str))


class ControlServer:
    """HTTP control endpoint for one :class:`~tgt.engine.Engine`."""

    def __init__(self, engine, host: str = "127.0.0.1", port: int = 8787,
                 token: Optional[str] = None, allow_remote: bool = False):
        if not is_loopback(host) and not allow_remote:
            raise ApiError(f"refusing to bind the control API to non-loopback "
                           f"{host!r}; add --api-allow-remote (and "
                           "--api-token) to expose it")
        if not is_loopback(host) and not token:
            raise ApiError("a non-loopback control API needs --api-token")
        self.engine, self.token = engine, token or None
        self.loopback = is_loopback(host)
        self.started = time.time()
        cls = _Server
        if ":" in host:
            cls = type("_Server6", (_Server,),
                       {"address_family": socket.AF_INET6})
        try:
            self.httpd = cls((host, port), self._handler())
        except OSError as e:
            raise ApiError(f"cannot bind control API on {host}:{port}: {e}")
        self.host = host
        self.port = self.httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{h}:{self.port}"

    def start(self) -> "ControlServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        name="tgt-api", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    # -- endpoint bodies ---------------------------------------------------
    def status(self) -> Dict:
        from . import __version__
        eng = self.engine
        s, cfg = eng.stats, eng.cfg
        return {
            "ok": True, "api": API_VERSION, "tool": f"tgt {__version__}",
            "running": s.running, "finished": s.finished,
            "paused": eng.control.paused,
            "uptime": round(s.elapsed, 3),
            "api_started": _iso(self.started),
            "seed": s.seed, "rate": cfg.rate,
            "packets": s.packets, "bytes": s.bytes, "errors": s.errors,
            "last_error": s.last_error,
            "pps": round(s.pps, 2), "mbps": round(s.mbps, 4),
            "cycles": s.cycles, "cycle_frames": s.cycle_frames,
            "per_profile": dict(s.per_profile),
            "interfaces": _json_safe(dict(s.per_iface)),
            "summary": cfg.summary(),
            "config": _json_safe(asdict(cfg)),
            "injections": eng.control.status(),
        }

    def manifest(self) -> Optional[Dict]:
        rec = getattr(self.engine, "recorder", None)
        if rec is None:
            return None
        for _ in range(20):         # the engine thread may be mid-update
            try:
                return rec.to_dict(self.engine.stats)
            except RuntimeError:
                time.sleep(0.01)
        raise ApiError("manifest busy, retry")

    # -- HTTP plumbing ---------------------------------------------------------
    def _handler(self):
        srv = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "tgt-api/1"
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):     # quiet: stdout is the UI
                pass

            def _send(self, code: int, doc: Dict) -> None:
                body = (json.dumps(doc, indent=1) + "\n").encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                if self.close_connection:
                    self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def _err(self, code: int, msg: str) -> None:
                # a rejected request's body may be unread: never parse it as
                # the next request on a keep-alive connection
                self.close_connection = True
                self._send(code, {"ok": False, "error": msg})

            def _allowed(self) -> bool:
                if self.headers.get("Origin"):
                    self._err(403, "browser cross-origin requests are not "
                              "accepted")
                    return False
                if srv.loopback:
                    host = (self.headers.get("Host") or "").strip()
                    name = host.rsplit(":", 1)[0] if not host.endswith("]") \
                        else host
                    name = name.strip("[]")
                    if host and not is_loopback(name):
                        self._err(403, f"bad Host header {host!r}")
                        return False
                if srv.token:
                    got = self.headers.get("Authorization") or ""
                    want = f"Bearer {srv.token}"
                    if not hmac.compare_digest(got.encode(), want.encode()):
                        self._err(401, "missing or bad bearer token")
                        return False
                return True

            def _params(self) -> Dict[str, str]:
                q = {k: v[-1] for k, v in
                     parse_qs(urlsplit(self.path).query).items()}
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    raise ApiError("bad Content-Length") from None
                if n < 0:
                    raise ApiError("bad Content-Length")
                if n > 65536:
                    raise ApiError("request body too large")
                raw = self.rfile.read(n) if n else b""
                if raw:
                    ctype = self.headers.get("Content-Type") or ""
                    if "json" in ctype:
                        doc = json.loads(raw.decode() or "{}")
                        if not isinstance(doc, dict):
                            raise ApiError("JSON body must be an object")
                        q.update({k: str(v) for k, v in doc.items()})
                    else:
                        q.update({k: v[-1] for k, v in
                                  parse_qs(raw.decode()).items()})
                return q

            def do_GET(self):
                if not self._allowed():
                    return
                path = urlsplit(self.path).path.rstrip("/") or "/"
                try:
                    if path in ("/", "/status"):
                        return self._send(200, srv.status())
                    if path == "/manifest":
                        doc = srv.manifest()
                        if doc is None:
                            return self._err(404, "no manifest recorder")
                        return self._send(200, doc)
                    if path == "/injections":
                        return self._send(200, {
                            "ok": True,
                            "injections": srv.engine.control.status()})
                except ApiError as e:
                    return self._err(503, str(e))
                if path in _POSTS:
                    return self._err(405, f"use POST {path}")
                return self._err(404, f"no such endpoint {path}")

            def do_POST(self):
                if not self._allowed():
                    return
                path = urlsplit(self.path).path.rstrip("/")
                try:
                    p = self._params()
                except (ApiError, ValueError) as e:
                    return self._err(400, str(e))
                eng, ctl = srv.engine, srv.engine.control
                if path == "/stop":
                    eng.stop()
                    return self._send(200, {"ok": True, "stopping": True})
                if path == "/pause":
                    ctl.pause()
                    return self._send(200, {"ok": True, "paused": True})
                if path == "/resume":
                    ctl.resume()
                    return self._send(200, {"ok": True, "paused": False})
                if path == "/rate":
                    try:
                        pps = float(p["pps"])
                    except (KeyError, ValueError):
                        return self._err(400, "need pps=N (packets/s)")
                    try:
                        ctl.set_rate(pps)
                    except ValueError as e:
                        return self._err(400 if pps < 0 else 409, str(e))
                    return self._send(200, {"ok": True, "rate": pps})
                if path == "/inject":
                    key = p.get("incident") or p.get("key") or ""
                    try:
                        dur = float(p.get("duration", 60))
                        ratio = (float(p["ratio"]) if p.get("ratio")
                                 else None)
                    except ValueError:
                        return self._err(400, "duration/ratio must be "
                                         "numbers")
                    if not eng.is_alive():
                        return self._err(409, "the run has finished")
                    try:
                        inj = ctl.inject(key, dur, ratio, via="api")
                    except KeyError:
                        return self._err(404, f"unknown incident {key!r} "
                                         "(see 'tgt list')")
                    except ValueError as e:
                        return self._err(409 if "already" in str(e) else 400,
                                         str(e))
                    return self._send(202, {"ok": True,
                                            "injection": inj.to_dict()})
                return self._err(404, f"no such endpoint {path}")

        return Handler


_POSTS = ("/stop", "/pause", "/resume", "/rate", "/inject")


def _iso(ts: float) -> str:
    from .manifest import iso
    return iso(ts)


# ---------------------------------------------------------------------------
# client (tgt ctl)
# ---------------------------------------------------------------------------
def request(api: str, method: str, path: str,
            params: Optional[Dict[str, Any]] = None,
            token: Optional[str] = None,
            timeout: float = 10.0) -> Tuple[int, Dict]:
    """Call the control API at ``api`` ([HOST:]PORT or a URL); returns
    (HTTP status, JSON reply). Raises ApiError when it cannot connect."""
    import urllib.error
    import urllib.request
    from urllib.parse import urlencode
    if api.startswith(("http://", "https://")):
        base = api.rstrip("/")
    else:
        host, port = parse_bind(api)
        h = f"[{host}]" if ":" in host else host
        base = f"http://{h}:{port}"
    url = base + path
    data = None
    if params:
        q = urlencode({k: v for k, v in params.items() if v is not None})
        if method == "GET":
            url += "?" + q
        else:
            data = q.encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    elif method == "POST":
        req.data = b""
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            doc = json.loads(e.read().decode() or "{}")
        except ValueError:
            doc = {"ok": False, "error": str(e)}
        return e.code, doc
    except (urllib.error.URLError, OSError) as e:
        raise ApiError(f"cannot reach the control API at {base}: "
                       f"{getattr(e, 'reason', e)}")
