#!/usr/bin/env python3
"""Run the unmodified mozvpn builtin SOCKS5 engine for the panel.

MOZVPS_DATA defaults to ~/.mozvps-data.  core.json is the upstream
account store.  ports.json is {"CC|CITY|INDEX": {"port": int, "enabled": bool}}.
Missing locations use upstream's deterministic port and default to enabled;
all configured ports, even for disabled or currently unknown locations, are
reserved before any defaults are assigned.  Duplicate/invalid configuration
is rejected rather than silently exposing a proxy on the wrong port.
locations.json is an atomic snapshot [{"id", "label", "port", "enabled"}]
of the entries returned by upstream's builtin engine build, including disabled
entries.  Restart the worker after editing ports.json; changes are loaded on
an upstream engine rebuild, not hot-applied to existing listeners.

MOZVPS_PROXY_BIND defaults to 127.0.0.1.  SOCKS5 has NO local authentication;
non-loopback binding is dangerous without a firewall or authenticated gateway.
Upstream output is suppressed because it includes raw tokens and TOTP codes.
The upstream first-run migration is disabled for this panel-owned store: it
otherwise imports and deletes legacy files outside MOZVPS_DATA.
"""

import contextlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import shutil
import tempfile
import threading

import mozvpn


_DIAGNOSTICS = sys.stderr
_ORIGINAL_PORT_FOR_LOCATION = mozvpn.port_for_location
_ORIGINAL_BUILD_PROXIES = mozvpn.BuiltinProxyEngine.build_proxies
_ORIGINAL_START_ALL = mozvpn.BuiltinProxyEngine.start_all
_ORIGINAL_STOP_ALL = mozvpn.BuiltinProxyEngine.stop_all
_ORIGINAL_CHECK_RUNNING = mozvpn.BuiltinProxyEngine.check_running
_ORIGINAL_CONNECT_RESOLVED = mozvpn._connect_resolved_ips
_BUILD_CONTEXT = threading.local()
_BUILD_LOCK = threading.Lock()
_DATA_HTTP_PROXY = None


def data_directory():
    return Path(os.environ.get("MOZVPS_DATA") or Path.home() / ".mozvps-data").expanduser().resolve()


def _diagnostic(message):
    # Only call with fixed, non-sensitive strings; upstream output is unsafe.
    try:
        print("mozvps worker: " + message, file=_DIAGNOSTICS, flush=True)
    except (OSError, ValueError):
        pass


def _connect_data_via_http_proxy(ips, host, port, timeout):
    """Create the Mozilla egress TCP socket through an optional HTTP proxy.

    TLS and the Mozilla CONNECT/Bearer exchange still happen in the unchanged
    core after this raw CONNECT tunnel is returned. With no data proxy set,
    the original direct path is used byte-for-byte.
    """
    if _DATA_HTTP_PROXY is None:
        return _ORIGINAL_CONNECT_RESOLVED(ips, host, port, timeout)
    proxy_host, proxy_port = _DATA_HTTP_PROXY
    raw = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        raw.settimeout(timeout)
        target = f"[{host}]" if ':' in str(host) and not str(host).startswith('[') else str(host)
        raw.sendall((f"CONNECT {target}:{int(port)} HTTP/1.1\r\n"
                     f"Host: {target}:{int(port)}\r\n"
                     "Proxy-Connection: keep-alive\r\n\r\n").encode('ascii'))
        response = b''
        while b'\r\n\r\n' not in response and len(response) <= 65536:
            chunk = raw.recv(4096)
            if not chunk:
                break
            response += chunk
        line = response.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
        parts = line.split()
        if len(parts) < 2 or parts[1] != '200':
            raise OSError('HTTP data proxy CONNECT failed')
        return raw
    except Exception:
        raw.close()
        raise


def _atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, ensure_ascii=False, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_ports(path):
    try:
        with path.open("r", encoding="utf-8") as source:
            config = json.load(source, object_pairs_hook=_unique_object)
    except FileNotFoundError:
        return {}
    if not isinstance(config, dict):
        raise ValueError("ports.json must be an object")
    used_ports = set()
    for key, entry in config.items():
        if not isinstance(key, str) or len(key.split("|")) != 3:
            raise ValueError("invalid location key")
        if not isinstance(entry, dict):
            raise ValueError("invalid location settings")
        port, enabled = entry.get("port"), entry.get("enabled")
        if type(port) is not int or not 1 <= port <= 65535 or type(enabled) is not bool:
            raise ValueError("invalid port or enabled value")
        if port in used_ports:
            raise ValueError("duplicate custom port")
        used_ports.add(port)
    return config


def _location_key(server):
    return (f"{server['countryCode']}|{server.get('cityCode') or ''}"
            f"|{server.get('serverIndex') or 0}")


def _panel_port_for_location(key, used):
    context = getattr(_BUILD_CONTEXT, "value", None)
    if context is None:
        return _ORIGINAL_PORT_FOR_LOCATION(key, used)
    config, reserved = context
    entry = config.get(key)
    if entry is not None:
        port = entry["port"]
        if port in used:
            raise ValueError("custom port already allocated")
        used.add(port)
        return port
    # Original receives a separate set, so the entire reserved set does not
    # prevent a later explicitly assigned port from being claimed by its key.
    blocked = used | reserved
    base, size = mozvpn.LOCAL_PORT_BASE, mozvpn.LOCAL_PORT_RANGE
    if len(blocked) >= size and sum(base <= p < base + size for p in blocked) >= size:
        raise ValueError("upstream default port range exhausted")
    port = _ORIGINAL_PORT_FOR_LOCATION(key, blocked)
    used.add(port)
    return port


def _panel_build_proxies(self, locations, verified):
    # Use the upstream builder unchanged for keys, labels, upstream metadata,
    # DNS allocation, max-proxies behavior, and proxy descriptors.  Allocate
    # disabled entries too, then filter them only from the returned proxies.
    with _BUILD_LOCK:
        try:
            directory = data_directory()
            config = _load_ports(directory / "ports.json")
            servers = list(verified)
            keys = [_location_key(server) for server in servers]
            if len(keys) != len(set(keys)):
                raise ValueError("duplicate upstream location key")
            reserved = {entry["port"] for entry in config.values()}
            try:
                with (directory / "preferences.json").open("r", encoding="utf-8") as source:
                    panel_port = json.load(source).get("panel_port", 1234)
            except FileNotFoundError:
                panel_port = 1234
            if type(panel_port) is not int or not 1024 <= panel_port <= 65535:
                raise ValueError("invalid panel port")
            if panel_port in reserved:
                raise ValueError("a location port collides with the panel port")
            reserved.add(panel_port)
            _BUILD_CONTEXT.value = (config, reserved)
            try:
                proxies = _ORIGINAL_BUILD_PROXIES(self, locations, servers)
            finally:
                del _BUILD_CONTEXT.value
            if len(proxies) > len(keys):
                raise ValueError("upstream proxy list is inconsistent")
            inventory = []
            enabled_proxies = []
            for key, proxy in zip(keys, proxies):
                enabled = config.get(key, {}).get("enabled", True)
                inventory.append({"id": key, "label": proxy["label"],
                                  "port": proxy["port"], "enabled": enabled,
                                  "active": False})
                if enabled:
                    enabled_proxies.append(proxy)
            _atomic_json(directory / "locations.json", inventory)
            return enabled_proxies
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            # Never fall back to unfiltered proxies when the panel data is bad.
            _diagnostic("could not build proxy inventory; check ports.json for invalid or duplicate ports.")
            raise


def _publish_bound_listeners(engine):
    """Report listener bind status, not a guarantee of upstream connectivity."""
    try:
        path = data_directory() / "locations.json"
        with path.open("r", encoding="utf-8") as source:
            inventory = json.load(source)
        bound = set()
        for sock in list(engine._sockets):
            try:
                bound.add(sock.getsockname()[1])
            except OSError:
                pass
        for item in inventory:
            item["active"] = bool(item.get("enabled") and item.get("port") in bound)
        _atomic_json(path, inventory)
    except (OSError, ValueError, TypeError):
        _diagnostic("could not publish listener status.")


def _panel_start_all(engine):
    try:
        return _ORIGINAL_START_ALL(engine)
    finally:
        _publish_bound_listeners(engine)


def _panel_check_running(engine):
    try:
        return _ORIGINAL_CHECK_RUNNING(engine)
    finally:
        _publish_bound_listeners(engine)


def _panel_stop_all(engine):
    try:
        return _ORIGINAL_STOP_ALL(engine)
    finally:
        _publish_bound_listeners(engine)


def _is_loopback(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _prepare_core(path):
    # On a new panel store, never let upstream migrate/delete unrelated legacy
    # files from ~/.config or the script directory. Preserve all existing data.
    if path.exists():
        with path.open("r", encoding="utf-8") as source:
            config = json.load(source)
        if not isinstance(config, dict):
            raise ValueError("invalid core config")
        if config.get("first_run", True):
            config["first_run"] = False
            _atomic_json(path, config)
    else:
        config = mozvpn.cfg_default()
        config["first_run"] = False
        _atomic_json(path, config)


def main():
    global _DATA_HTTP_PROXY
    directory = data_directory()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _prepare_core(directory / "core.json")
    except (OSError, ValueError, TypeError):
        _diagnostic("cannot prepare the data directory or core.json.")
        return 1

    bind = (os.environ.get("MOZVPS_PROXY_BIND") or "127.0.0.1").strip() or "127.0.0.1"
    if not _is_loopback(bind):
        _diagnostic("WARNING: non-loopback SOCKS5 listeners are unauthenticated; protect them with a firewall.")

    # Inherited credentials must not override the panel's current account.
    for name in ("MOZVPN_EMAIL", "MOZVPN_PASSWORD", "MOZVPN_SESSION_TOKEN",
                 "MOZVPN_TOTP", "MOZVPN_TOTP_SECRET"):
        os.environ.pop(name, None)
    proxy_url = ''
    data_proxy = None
    try:
        with (directory / "preferences.json").open("r", encoding="utf-8") as source:
            preferences = json.load(source)
        if preferences.get('mozilla_proxy_enabled'):
            host = str(preferences.get('mozilla_proxy_host') or '').strip()
            port = preferences.get('mozilla_proxy_port')
            if host and type(port) is int and 1 <= port <= 65535 and not any(ch in host for ch in '\r\n\x00 /'):
                proxy_url = f'http://{host}:{port}'
        if preferences.get('mozilla_data_proxy_enabled'):
            host = str(preferences.get('mozilla_proxy_host') or '').strip()
            port = preferences.get('mozilla_proxy_port')
            if host and type(port) is int and 1 <= port <= 65535 and not any(ch in host for ch in '\r\n\x00 /'):
                data_proxy = (host, port)
    except (OSError, ValueError, TypeError, AttributeError):
        _diagnostic("could not read Mozilla proxy settings.")
    _DATA_HTTP_PROXY = data_proxy
    mozvpn.port_for_location = _panel_port_for_location
    mozvpn._connect_resolved_ips = _connect_data_via_http_proxy
    mozvpn.BuiltinProxyEngine.build_proxies = _panel_build_proxies
    mozvpn.BuiltinProxyEngine.start_all = _panel_start_all
    mozvpn.BuiltinProxyEngine.check_running = _panel_check_running
    mozvpn.BuiltinProxyEngine.stop_all = _panel_stop_all
    # Prefer the external sing-box transport when the installer provided it.
    # It gives the data plane HTTP/2/HTTP/3 support; builtin remains a safe
    # fallback for upgrades where the binary is temporarily unavailable.
    engine = "singbox" if shutil.which("sing-box") else "builtin"
    sys.argv = [str(Path(__file__).resolve()), "--config", str(directory / "core.json"),
                "--proxy-type", "socks5", "--auto-rotate", "--local-proxy",
                "--local-proxy-engine", engine, "--listen", bind,
                "--no-dns-relay", "--no-input", "--no-save"]
    if proxy_url:
        sys.argv.extend(["--api-proxy", proxy_url])
    # Upstream prints proxyPass/JWT and generated TOTP; suppress ALL of its
    # output instead of trying to recognize secrets in arbitrary log lines.
    # Non-tty stdin is also needed because upstream may prompt on a real tty
    # despite interactive=False. Panel controls the worker lifecycle.
    try:
        with open(os.devnull, "r", encoding="utf-8") as input_null, \
                open(os.devnull, "w", encoding="utf-8") as output_null, \
                contextlib.redirect_stdout(output_null), contextlib.redirect_stderr(output_null):
            sys.stdin = input_null
            mozvpn.main()
    except KeyboardInterrupt:
        return 0
    except SystemExit as exc:
        return exc.code if type(exc.code) is int else 1
    except Exception:
        _diagnostic("upstream worker exited unexpectedly.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
