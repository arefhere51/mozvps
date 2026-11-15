#!/usr/bin/env python3
"""Isolated, non-interactive upstream authentication helper.

Protocol: send ONE UTF-8 JSON line on stdin, never command-line arguments:
    {"email":"...", "password":"...", "totp":"...", "config_path":"..."}
``totp`` is optional/empty, a six-digit one-time code, or a base32 secret.
``config_path`` must designate a unique, isolated temporary regular file,
not MOZVPS_DATA/core.json. It may be absent, empty, or an empty JSON config.
The caller owns its lifecycle and must restrict access and delete it after use.

Writes exactly one JSON line to stdout: on success
    {"ok":true, "config_path":"/absolute/path", "account":"email"}
and on failure {"ok":false, "error":"safe description", "code":"..."}.
Exit status is 0 on success and 1 on failure. No password, TOTP or token is
returned or logged. The caller enforces a timeout. On success the temporary
config contains the upstream accounts[account] record, including plaintext
credentials/session; the parent must merge that record into the stopped
worker's core.json, preserving the existing current_account, and resume it.
This helper never merges or touches the managed core config.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace


class SafeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _validate_request(request):
    if not isinstance(request, dict):
        raise SafeError("invalid_request", "Expected a JSON object.")
    email = request.get("email")
    password = request.get("password")
    totp = request.get("totp")
    path = request.get("config_path")
    if not isinstance(email, str) or not email.strip():
        raise SafeError("invalid_request", "An account email is required.")
    if not isinstance(password, str) or not password:
        raise SafeError("invalid_request", "An account password is required.")
    if totp is None:
        totp = ""
    if not isinstance(totp, str):
        raise SafeError("invalid_request", "TOTP must be a six-digit code or base32 secret.")
    if not isinstance(path, str) or not path.strip():
        raise SafeError("invalid_request", "A unique temporary config path is required.")
    return email.strip().lower(), password, totp.strip(), Path(path).expanduser().absolute()


def _prepare_temporary_config(path):
    data = Path(os.environ.get("MOZVPS_DATA") or Path.home() / ".mozvps-data").expanduser()
    if os.path.realpath(path) == os.path.realpath(data / "core.json"):
        raise SafeError("invalid_config", "Authentication requires an isolated temporary config, not core.json.")
    try:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 1024 * 1024:
                raise SafeError("invalid_config", "The temporary config must be an isolated regular file.")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "r", encoding="utf-8") as source:
                fd = -1
                text = source.read()
            if text.strip():
                value = json.loads(text)
                if (not isinstance(value, dict) or value.get("accounts") not in (None, {})
                        or value.get("current_account")):
                    raise SafeError("invalid_config", "The temporary config must not contain an existing account.")
        finally:
            if fd >= 0:
                os.close(fd)
    except SafeError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise SafeError("invalid_config", "Cannot access the isolated temporary config.") from None


def _safe_upstream_error(mozvpn, exc):
    # Compare complete known upstream messages; never relay exception text or
    # server data, which can contain a password, a session, or a TOTP code.
    message = str(exc)
    known = {
        "email_unverified": ("email_verification_required", "Verify the account email using Mozilla's email, then try again."),
        "email_confirm_required": ("email_verification_required", "Mozilla requires email sign-in confirmation; complete it with Mozilla, then try again."),
        "totp_missing": ("totp_required", "Mozilla requires a TOTP code or base32 secret."),
        "totp_rejected_final": ("totp_rejected", "Mozilla rejected the TOTP code; check the code or secret and try again."),
        "totp_need_pyotp": ("totp_dependency_missing", "The pyotp dependency is required to generate TOTP codes from a secret."),
        "wrong_password": ("invalid_credentials", "Mozilla rejected the account credentials."),
        "account_not_found": ("invalid_credentials", "Mozilla could not find the account."),
        "waf_406": ("security_check", "Mozilla's security check could not be completed; try again later."),
    }
    for key, (code, description) in known.items():
        if message == mozvpn.tr(key):
            return SafeError(code, description)
    if getattr(exc, "code", "") in ("blocked", "blocked_login"):
        return SafeError("security_check", "Mozilla blocked or rate-limited sign-in; check email and try again later.")
    return SafeError("authentication_failed", "Authentication failed; check the credentials and Mozilla sign-in requirements.")


def authenticate(request):
    email, password, totp, config_path = _validate_request(request)
    _prepare_temporary_config(config_path)
    # Import and invoke upstream entirely under output redirection in main().
    # This is a separate process, so the upstream global config is isolated.
    import mozvpn

    proxy = os.environ.get('MOZVPN_API_PROXY', '').strip()
    if proxy:
        if not (proxy.startswith('http://') or proxy.startswith('https://')):
            raise SafeError('invalid_proxy', 'The configured Mozilla proxy must use http:// or https://.')
        mozvpn.set_api_proxy(proxy)
    else:
        mozvpn.set_api_proxy('')

    fixed_code = None
    secret = None
    if totp:
        compact = re.sub(r"[\s-]+", "", totp)
        if re.fullmatch(r"[0-9]{6}", compact):
            fixed_code = compact
        else:
            try:
                secret = mozvpn.validate_totp_secret(totp)
            except (mozvpn.MozVpnError, ValueError, TypeError):
                raise SafeError("invalid_totp", "TOTP must be a six-digit code or valid base32 secret.") from None

    args = SimpleNamespace(email=email, password=password, session_token=None,
                           relogin=True, totp=fixed_code, totp_secret=secret, qr=None)
    creds = {"email": email, "password": password, "totp_secret": secret}
    try:
        mozvpn.apply_config_path(str(config_path))
        provider = mozvpn.make_totp_provider(args, creds)
        # force_relogin prevents a previously cached session from passing as a
        # successful verification of new credentials. Upstream's anti-bot,
        # fxa_login and verification flow are not modified or bypassed.
        session = mozvpn.ensure_session(args, creds, provider, interactive=False,
                                        force_relogin=True)
        if not isinstance(session, str) or not session:
            raise SafeError("authentication_failed", "Mozilla did not return a valid session.")
        mozvpn.cache_account(args, creds, session_token=session)
        # Upstream's cfg_save() deliberately swallows OSError; confirm that the
        # complete successful record really exists before reporting success.
        with config_path.open("r", encoding="utf-8") as source:
            written = json.load(source)
        record = written.get("accounts", {}).get(email, {})
        if (not isinstance(record, dict) or record.get("session_token") != session
                or record.get("password") != password
                or (secret is not None and record.get("totp_secret") != secret)):
            raise SafeError("config_write_failed", "The successful account could not be saved to the temporary config.")
    except mozvpn.MozVpnError as exc:
        raise _safe_upstream_error(mozvpn, exc) from None
    except SafeError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        raise SafeError("authentication_failed", "Authentication or temporary config storage failed.") from None
    return {"ok": True, "config_path": str(config_path), "account": email}


def main():
    original_stdout = sys.stdout
    try:
        # An accidental upstream prompt must not consume more caller input;
        # _can_prompt() must also see a non-tty. A fresh StringIO buffers all
        # upstream output, including generated codes, and is never displayed.
        line = sys.stdin.readline(1024 * 1024 + 1)
        if len(line) > 1024 * 1024:
            raise SafeError("invalid_request", "The JSON request is too large.")
        try:
            request = json.loads(line)
        except (ValueError, TypeError):
            raise SafeError("invalid_request", "Expected one valid JSON request line.") from None
        sys.stdin = io.StringIO("")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = authenticate(request)
        status = 0
    except SafeError as exc:
        result = {"ok": False, "error": exc.message, "code": exc.code}
        status = 1
    except BaseException:
        # No repr, traceback, server text, or captured output may escape.
        result = {"ok": False, "error": "Authentication helper failed.", "code": "helper_failed"}
        status = 1
    original_stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
    original_stdout.flush()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
