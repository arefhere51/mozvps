#!/usr/bin/env python3
"""MozVPS self-hosted management server. Mozilla's core is left unmodified."""
from __future__ import annotations

import hashlib
import getpass
import hmac
import http.cookies
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('MOZVPS_DATA', str(Path.home() / '.mozvps-data'))).resolve()
DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(DATA, 0o700)
os.umask(0o077)
CORE = DATA / 'core.json'
PORTS = DATA / 'ports.json'
LOCATIONS = DATA / 'locations.json'
PREFS = DATA / 'preferences.json'
AUTH = DATA / 'panel-auth.json'
EVENTS = DATA / 'events.log'
HOST = os.environ.get('MOZVPS_PANEL_HOST', '0.0.0.0')
SESSION_SECONDS = 12 * 60 * 60


def read_json(path, default):
    try:
        with path.open(encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return default


def write_json(path, data):
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def event(message):
    # Never write upstream output, credentials, OTPs or access tokens here.
    try:
        with EVENTS.open('a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S ') + message + '\n')
        if EVENTS.stat().st_size > 512_000:
            lines = EVENTS.read_text(encoding='utf-8').splitlines()[-500:]
            EVENTS.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    except OSError:
        pass


def password_record(password):
    salt = secrets.token_bytes(16)
    rounds = 310_000
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, rounds)
    return {'salt': salt.hex(), 'digest': digest.hex(), 'rounds': rounds,
            'default_password': password == 'admin'}


def check_password(record, candidate):
    try:
        if not isinstance(candidate, str) or len(candidate) > 256:
            return False
        digest = hashlib.pbkdf2_hmac('sha256', candidate.encode('utf-8'),
                                     bytes.fromhex(record['salt']), int(record['rounds']))
        return hmac.compare_digest(digest.hex(), record['digest'])
    except (ValueError, KeyError, TypeError):
        return False


class Controller:
    def __init__(self):
        self.lock = threading.RLock()
        self.sessions = {}
        self.attempts = {}
        self.worker = None
        self.worker_started = 0
        self.detail = 'هیچ حساب تأییدشده‌ای ثبت نشده است.'
        self.preferences = read_json(PREFS, {})
        if not isinstance(self.preferences, dict):
            self.preferences = {}
        self.preferences.setdefault('panel_port', 1234)
        self.preferences.setdefault('desired', True)
        self.preferences.setdefault('mozilla_proxy_enabled', False)
        self.preferences.setdefault('mozilla_data_proxy_enabled', False)
        self.preferences.setdefault('mozilla_proxy_host', '127.0.0.1')
        self.preferences.setdefault('mozilla_proxy_port', 8080)
        # An existing damaged auth file must not silently reset to admin.
        if not AUTH.exists():
            write_json(AUTH, password_record('admin'))
            event('رمز اولیهٔ پنل admin است؛ فوراً آن را تغییر دهید.')
        self.auth = read_json(AUTH, None)
        if not isinstance(self.auth, dict) or not {'salt', 'digest', 'rounds'} <= self.auth.keys():
            raise RuntimeError('Invalid panel auth file; refusing to reset the password.')

    def prefs_save(self):
        write_json(PREFS, self.preferences)

    def mozilla_proxy_url(self):
        if not self.preferences.get('mozilla_proxy_enabled'):
            return ''
        host = str(self.preferences.get('mozilla_proxy_host') or '').strip()
        port = self.preferences.get('mozilla_proxy_port')
        if not host or type(port) is not int or not 1 <= port <= 65535:
            return ''
        return f'http://{host}:{port}'

    def accounts(self):
        data = read_json(CORE, {})
        if not isinstance(data, dict):
            return []
        current = data.get('current_account')
        accounts = data.get('accounts', {})
        if not isinstance(accounts, dict):
            return []
        return [{'email': em, 'current': em == current,
                 'quota_remaining': a.get('quota_remaining'), 'quota_limit': a.get('quota_limit'),
                 'quota_reset': a.get('quota_reset'), 'quota_unlimited': bool(a.get('quota_unlimited')),
                 'authenticated': bool(a.get('session_token'))}
                for em, a in accounts.items() if isinstance(a, dict)]

    def start(self):
        with self.lock:
            self.preferences['desired'] = True
            self.prefs_save()
            if self.worker is not None and self.worker.poll() is None:
                return
            if not any(a['authenticated'] for a in self.accounts()):
                self.detail = 'ابتدا یک حساب موزیلا را با موفقیت اضافه کنید.'
                event('اجرای پراکسی در انتظار ثبت حساب است.')
                return
            # Upstream prints JWTs and TOTP values: do not persist or expose its console output.
            self.worker = subprocess.Popen([sys.executable, str(ROOT / 'worker.py')],
                                           cwd=str(ROOT), stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           env=os.environ.copy())
            self.worker_started = time.time()
            self.detail = 'هسته در حال راه‌اندازی است؛ اتصال و لوکیشن‌ها را بررسی کنید.'
            event('هستهٔ پراکسی راه‌اندازی شد.')

    def stop(self, permanent=True):
        with self.lock:
            if permanent:
                self.preferences['desired'] = False
                self.prefs_save()
            p = self.worker
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
                event('هستهٔ پراکسی متوقف شد.')
            self.worker = None
            self.detail = 'پراکسی متوقف است؛ پنل همچنان در دسترس است.'

    def restart(self):
        with self.lock:
            self.stop(permanent=False)
            self.start()

    def state(self):
        with self.lock:
            p = self.worker
            if not p:
                return 'stopped'
            if p.poll() is not None:
                self.detail = 'هسته متوقف شده است؛ تنظیمات حساب یا دسترسی شبکه را بررسی کنید.'
                return 'error'
            try:
                has_live_inventory = LOCATIONS.exists() and LOCATIONS.stat().st_mtime >= self.worker_started
            except OSError:
                has_live_inventory = False
            if has_live_inventory:
                inventory = read_json(LOCATIONS, [])
                if any(isinstance(item, dict) and item.get('active') for item in inventory):
                    self.detail = 'شنوندهٔ SOCKS5 باز است؛ دسترسی مقصد و سهمیه به موزیلا وابسته‌اند.'
                    return 'running'
                if inventory and not any(isinstance(item, dict) and item.get('enabled') for item in inventory):
                    self.detail = 'همهٔ لوکیشن‌ها غیرفعال‌اند؛ حداقل یکی را فعال کنید.'
                else:
                    self.detail = 'هیچ شنونده‌ای فعال نیست؛ پورت‌ها یا وضعیت اتصال را بررسی کنید.'
            return 'starting'

    def status(self):
        loc = read_json(LOCATIONS, [])
        service = self.state()
        if not isinstance(loc, list):
            loc = []
        if service in ('stopped', 'error'):
            loc = [dict(item, active=False) for item in loc if isinstance(item, dict)]
        bind = os.environ.get('MOZVPS_PROXY_BIND', '127.0.0.1')
        detail = self.detail
        if bind not in ('127.0.0.1', 'localhost', '::1'):
            detail += ' هشدار: پراکسی شبکه‌ای بدون رمز است؛ دسترسی آن را با فایروال محدود کنید.'
        return {'service': service, 'detail': detail, 'accounts': self.accounts(),
                'locations': loc,
                'panel_port': self.preferences['panel_port'],
                'mozilla_proxy': {'enabled': bool(self.preferences.get('mozilla_proxy_enabled')),
                                  'data_enabled': bool(self.preferences.get('mozilla_data_proxy_enabled')),
                                  'host': self.preferences.get('mozilla_proxy_host', '127.0.0.1'),
                                  'port': self.preferences.get('mozilla_proxy_port', 8080)}}

    def save_mozilla_proxy(self, enabled, host, port, data_enabled=False):
        if not isinstance(enabled, bool):
            raise ValueError('Proxy enabled state is invalid.')
        host = str(host or '').strip()
        if not host or any(ch in host for ch in '\r\n\x00 /'):
            raise ValueError('Proxy host is invalid.')
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError('Proxy port is invalid.')
        if not 1 <= port <= 65535:
            raise ValueError('Proxy port must be between 1 and 65535.')
        with self.lock:
            self.preferences.update({'mozilla_proxy_enabled': enabled,
                                     'mozilla_data_proxy_enabled': bool(data_enabled),
                                     'mozilla_proxy_host': host,
                                     'mozilla_proxy_port': port})
            self.prefs_save()
            event('Mozilla HTTP proxy settings updated.')
            if self.worker is not None and self.worker.poll() is None:
                self.restart()

    def add_account(self, email, password, totp):
        email = str(email or '').strip().lower()
        password = str(password or '')
        totp = str(totp or '').strip()
        if len(email) > 254 or '@' not in email or any(x in email for x in '\r\n\x00'):
            raise ValueError('ایمیل حساب موزیلا معتبر نیست.')
        if not password or len(password) > 1024 or len(totp) > 256:
            raise ValueError('گذرواژه یا کد دومرحله‌ای معتبر نیست.')
        with self.lock:
            desired = bool(self.preferences.get('desired', True))
            self.stop(permanent=False)
            # Isolated auth avoids simultaneous writes to the live core store.
            with tempfile.TemporaryDirectory(prefix='account-', dir=DATA) as d:
                temp_config = str(Path(d) / 'config.json')
                request = json.dumps({'email': email, 'password': password, 'totp': totp,
                                      'config_path': temp_config}, ensure_ascii=False)
                try:
                    child_env = os.environ.copy()
                    proxy = self.mozilla_proxy_url()
                    if proxy:
                        child_env['MOZVPN_API_PROXY'] = proxy
                    else:
                        child_env.pop('MOZVPN_API_PROXY', None)
                    proc = subprocess.run([sys.executable, str(ROOT / 'auth_helper.py')],
                                          input=request + '\n', text=True, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, timeout=180, cwd=str(ROOT), env=child_env)
                    result = json.loads(proc.stdout)
                except subprocess.TimeoutExpired:
                    result = {'ok': False, 'error': 'زمان ورود تمام شد؛ محدودیت شبکه یا تأیید موزیلا را بررسی کنید.'}
                except (ValueError, OSError):
                    result = {'ok': False, 'error': 'ورود انجام نشد؛ دسترسی شبکه و اطلاعات حساب را بررسی کنید.'}
                if result.get('ok'):
                    temp = read_json(Path(temp_config), {})
                    incoming = temp.get('accounts', {}).get(email) if isinstance(temp, dict) else None
                    if not isinstance(incoming, dict) or not incoming.get('session_token'):
                        result = {'ok': False, 'error': 'موزیلا نشست معتبر برنگرداند.'}
                    else:
                        core = read_json(CORE, {})
                        if not isinstance(core, dict):
                            core = {}
                        if not isinstance(core.get('accounts'), dict):
                            core['accounts'] = {}
                        core.setdefault('version', 2)
                        core.setdefault('first_run', False)
                        core.setdefault('migrated_at', None)
                        core.setdefault('profile_defaults', {})
                        core['accounts'][email] = incoming
                        if not core.get('current_account') or core['current_account'] not in core['accounts']:
                            core['current_account'] = email
                        write_json(CORE, core)
                        event('حساب موزیلا ثبت و تأیید شد.')
            if desired:
                self.start()
            if not result.get('ok'):
                errors = {
                    'email_verification_required': 'موزیلا تأیید ایمیل می‌خواهد؛ ایمیل را تأیید و دوباره تلاش کنید.',
                    'totp_required': 'موزیلا به کد یا کلید تأیید دومرحله‌ای نیاز دارد.',
                    'totp_rejected': 'کد دومرحله‌ای پذیرفته نشد؛ کد یا کلید را بررسی کنید.',
                    'totp_dependency_missing': 'وابستگی تولید کد دومرحله‌ای نصب نشده است.',
                    'invalid_credentials': 'موزیلا اطلاعات حساب را نپذیرفت.',
                    'security_check': 'بررسی امنیتی موزیلا تکمیل نشد؛ بعداً دوباره تلاش کنید.',
                    'invalid_totp': 'کد یا کلید تأیید دومرحله‌ای معتبر نیست.',
                    'config_write_failed': 'ذخیرهٔ نشست تأییدشده انجام نشد.',
                }
                raise ValueError(errors.get(result.get('code'), 'ورود به موزیلا انجام نشد؛ اطلاعات حساب، تأیید حساب و دسترسی شبکه را بررسی کنید.'))
            return 'حساب تأیید شد. گردش خودکار به نشست‌های تأییدشده وابسته است.'

    def delete_account(self, email):
        with self.lock:
            desired = bool(self.preferences.get('desired', True))
            self.stop(permanent=False)
            core = read_json(CORE, {})
            if not isinstance(core, dict) or email not in core.get('accounts', {}):
                if desired:
                    self.start()
                raise ValueError('حساب پیدا نشد.')
            del core['accounts'][email]
            if core.get('current_account') == email:
                core['current_account'] = next(iter(core['accounts']), None)
            write_json(CORE, core)
            event('یک حساب موزیلا حذف شد.')
            if desired:
                self.start()

    def save_locations(self, items):
        if not isinstance(items, list) or len(items) > 5000:
            raise ValueError('فهرست لوکیشن معتبر نیست.')
        inventory = read_json(LOCATIONS, [])
        allowed = {x.get('id') for x in inventory if isinstance(x, dict) and isinstance(x.get('id'), str)}
        mapping, used = {}, set()
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('اطلاعات لوکیشن معتبر نیست.')
            key = item.get('id')
            if key not in allowed or key in mapping:
                raise ValueError('شناسهٔ لوکیشن ناشناخته یا تکراری است.')
            try:
                port = int(item['port'])
            except (KeyError, TypeError, ValueError):
                raise ValueError('شمارهٔ پورت معتبر نیست.')
            if not 1024 <= port <= 65535 or port == int(self.preferences['panel_port']):
                raise ValueError('پورت باید بین ۱۰۲۴ تا ۶۵۵۳۵ و متفاوت با پورت پنل باشد.')
            if port in used:
                raise ValueError('پورت تکراری مجاز نیست.')
            used.add(port)
            enabled = item.get('enabled', True)
            if not isinstance(enabled, bool):
                raise ValueError('وضعیت لوکیشن معتبر نیست.')
            mapping[key] = {'port': port, 'enabled': enabled}
        with self.lock:
            old = read_json(PORTS, {})
            if isinstance(old, dict):
                old.update(mapping)
            else:
                old = mapping
            # Include previously unseen/offline entries in collision checks too.
            all_ports = [v.get('port') for v in old.values() if isinstance(v, dict) and v.get('port')]
            if len(all_ports) != len(set(all_ports)):
                raise ValueError('پورت با یک لوکیشن ذخیره‌شدهٔ دیگر تداخل دارد.')
            write_json(PORTS, old)
            event('تنظیم پورت لوکیشن‌ها ذخیره شد.')
            if self.worker and self.worker.poll() is None:
                self.restart()


CTRL = Controller()
STOP = threading.Event()
SERVERS = []
SERVER_LOCK = threading.Lock()
TLS_CERT = os.environ.get('MOZVPS_PANEL_TLS_CERT')
TLS_KEY = os.environ.get('MOZVPS_PANEL_TLS_KEY')
if bool(TLS_CERT) != bool(TLS_KEY):
    raise RuntimeError('Both MOZVPS_PANEL_TLS_CERT and MOZVPS_PANEL_TLS_KEY are required.')


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = 'MozVPS'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        # Query strings and credentials are never written to access logs.
        return

    def reply(self, status, payload, content_type='application/json; charset=utf-8', headers=()):
        body = json.dumps(payload, ensure_ascii=False).encode() if content_type.startswith('application/json') else payload
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def body(self):
        if self.headers.get_content_type() != 'application/json':
            raise ValueError('درخواست باید JSON باشد.')
        try:
            n = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            n = -1
        if n < 0 or n > 1_000_000:
            raise ValueError('اندازهٔ درخواست معتبر نیست.')
        try:
            data = json.loads(self.rfile.read(n) or b'{}')
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError('درخواست معتبر نیست.')
        if not isinstance(data, dict):
            raise ValueError('درخواست معتبر نیست.')
        return data

    def session(self):
        try:
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            token = cookie['mozvps_session'].value if 'mozvps_session' in cookie else ''
        except http.cookies.CookieError:
            return None
        with CTRL.lock:
            item = CTRL.sessions.get(token)
            if not item or item['expires'] < time.time():
                CTRL.sessions.pop(token, None)
                return None
            return item

    def csrf_check(self, session):
        token = self.headers.get('X-CSRF-Token', '')
        return bool(session and hmac.compare_digest(token, session['csrf']))

    def secure_request(self):
        if TLS_CERT:
            return True
        # Honor reverse-proxy protocol headers only from the local machine.
        return self.client_address[0] in ('127.0.0.1', '::1') and self.headers.get('X-Forwarded-Proto', '').lower() == 'https'

    def do_GET(self):
        path = urlsplit(self.path).path
        static = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'application/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in static:
            filename, ctype = static[path]
            try:
                return self.reply(200, (ROOT / 'ui' / filename).read_bytes(), ctype)
            except OSError:
                return self.reply(404, {'error': 'فایل یافت نشد.'})
        session = self.session()
        if path == '/api/session':
            return self.reply(200, {'authenticated': bool(session), 'csrf': session['csrf'] if session else None,
                                    'default_password': bool(CTRL.auth.get('default_password'))})
        if not session:
            return self.reply(401, {'error': 'ابتدا وارد پنل شوید.'})
        if path == '/api/status':
            return self.reply(200, CTRL.status())
        if path == '/api/logs':
            try:
                lines = EVENTS.read_text(encoding='utf-8').splitlines()[-100:]
            except OSError:
                lines = []
            return self.reply(200, {'lines': lines})
        return self.reply(404, {'error': 'مسیر پیدا نشد.'})

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            data = self.body()
            if path == '/api/login':
                return self.login(data)
            session = self.session()
            if not session:
                return self.reply(401, {'error': 'ابتدا وارد پنل شوید.'})
            if not self.csrf_check(session):
                return self.reply(403, {'error': 'نشست نامعتبر است؛ صفحه را تازه کنید.'})
            if path == '/api/logout':
                with CTRL.lock:
                    CTRL.sessions.clear()
                return self.reply(200, {'ok': True}, headers=[('Set-Cookie', 'mozvps_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')])
            if path == '/api/password':
                old = data.get('current_password')
                new = data.get('new_password')
                if not check_password(CTRL.auth, old):
                    raise ValueError('گذرواژهٔ فعلی صحیح نیست.')
                if not isinstance(new, str) or not 8 <= len(new) <= 256:
                    raise ValueError('گذرواژهٔ جدید باید ۸ تا ۲۵۶ نویسه باشد.')
                with CTRL.lock:
                    CTRL.auth = password_record(new)
                    write_json(AUTH, CTRL.auth)
                    CTRL.sessions.clear()
                event('گذرواژهٔ پنل تغییر کرد.')
                return self.reply(200, {'ok': True, 'message': 'گذرواژه تغییر کرد؛ دوباره وارد شوید.'}, headers=[('Set-Cookie', 'mozvps_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')])
            if path == '/api/service':
                action = data.get('action')
                if action == 'start': CTRL.start()
                elif action == 'stop': CTRL.stop()
                elif action == 'restart': CTRL.restart()
                else: raise ValueError('دستور نامعتبر است.')
                return self.reply(200, {'ok': True, 'message': 'دستور اجرا شد.'})
            if path == '/api/accounts':
                if not self.secure_request() and self.client_address[0] not in ('127.0.0.1', '::1'):
                    return self.reply(403, {'error': 'برای ارسال اطلاعات موزیلا از HTTPS یا تونل محلی استفاده کنید.'})
                msg = CTRL.add_account(data.get('email'), data.get('password'), data.get('totp'))
                return self.reply(200, {'ok': True, 'message': msg})
            if path == '/api/locations':
                CTRL.save_locations(data.get('locations'))
                return self.reply(200, {'ok': True, 'message': 'پورت‌ها ذخیره شدند و هسته در صورت نیاز دوباره اجرا شد.'})
            if path == '/api/panel-port':
                try:
                    port = int(data.get('port'))
                except (TypeError, ValueError):
                    raise ValueError('شمارهٔ پورت معتبر نیست.')
                if not 1024 <= port <= 65535:
                    raise ValueError('پورت باید بین ۱۰۲۴ و ۶۵۵۳۵ باشد.')
                change_panel_port(port)
                return self.reply(200, {'ok': True, 'message': 'پورت پنل تغییر کرد؛ از نشانی جدید استفاده کنید.'})
            if path == '/api/mozilla-proxy':
                CTRL.save_mozilla_proxy(data.get('enabled'), data.get('host'), data.get('port'),
                                        data.get('data_enabled', False))
                return self.reply(200, {'ok': True, 'message': 'تنظیم پروکسی Mozilla ذخیره شد.'})
            return self.reply(404, {'error': 'مسیر پیدا نشد.'})
        except ValueError as e:
            return self.reply(400, {'error': str(e)})
        except OSError:
            return self.reply(400, {'error': 'عملیات انجام نشد؛ پورت یا دسترسی فایل را بررسی کنید.'})
        except Exception:
            event('خطای داخلی در اجرای درخواست پنل.')
            return self.reply(500, {'error': 'خطای داخلی؛ لطفاً دوباره تلاش کنید.'})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        session = self.session()
        if not session:
            return self.reply(401, {'error': 'ابتدا وارد پنل شوید.'})
        if not self.csrf_check(session):
            return self.reply(403, {'error': 'نشست نامعتبر است.'})
        if not path.startswith('/api/accounts/'):
            return self.reply(404, {'error': 'مسیر پیدا نشد.'})
        try:
            CTRL.delete_account(unquote(path[len('/api/accounts/'):]))
            return self.reply(200, {'ok': True, 'message': 'حساب حذف شد.'})
        except ValueError as e:
            return self.reply(400, {'error': str(e)})
        except Exception:
            return self.reply(500, {'error': 'حذف حساب انجام نشد.'})

    def login(self, data):
        ip = self.client_address[0]
        with CTRL.lock:
            now = time.time()
            # Limit memory as well as attempts, including when there are many IPs.
            CTRL.attempts = {k: [t for t in v if now - t < 600] for k, v in CTRL.attempts.items()
                             if any(now - t < 600 for t in v)}
            attempts = CTRL.attempts.setdefault(ip, [])
            if len(attempts) >= 8 or sum(map(len, CTRL.attempts.values())) >= 120:
                return self.reply(429, {'error': 'تلاش بیش از حد؛ ۱۰ دقیقه بعد دوباره امتحان کنید.'})
            if not check_password(CTRL.auth, data.get('password')):
                attempts.append(now)
                return self.reply(401, {'error': 'گذرواژهٔ پنل اشتباه است.'})
            CTRL.attempts.pop(ip, None)
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            CTRL.sessions = {k: v for k, v in CTRL.sessions.items() if v['expires'] > now}
            CTRL.sessions[token] = {'csrf': csrf, 'expires': now + SESSION_SECONDS}
        secure = '; Secure' if self.secure_request() else ''
        cookie = f'mozvps_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}{secure}'
        return self.reply(200, {'authenticated': True, 'csrf': csrf,
                                'default_password': bool(CTRL.auth.get('default_password'))}, headers=[('Set-Cookie', cookie)])


def create_server(port):
    server = Server((HOST, port), Handler)
    if TLS_CERT:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def change_panel_port(port):
    with SERVER_LOCK:
        if port == int(CTRL.preferences['panel_port']):
            return
        mapping = read_json(PORTS, {})
        if isinstance(mapping, dict) and any(isinstance(v, dict) and v.get('port') == port for v in mapping.values()):
            raise ValueError('این پورت به یک لوکیشن اختصاص یافته است.')
        inventory = read_json(LOCATIONS, [])
        if isinstance(inventory, list) and any(isinstance(item, dict) and item.get('port') == port for item in inventory):
            raise ValueError('این پورت به یک لوکیشن اختصاص یافته است.')
        # Bind the replacement before touching the previous server or preferences.
        new = create_server(port)
        CTRL.preferences['panel_port'] = port
        try:
            CTRL.prefs_save()
        except Exception:
            new.server_close()
            raise
        previous = list(SERVERS)
        SERVERS[:] = [new]
        threading.Thread(target=new.serve_forever, daemon=True).start()
        def shutdown_old():
            time.sleep(1)
            for s in previous:
                s.shutdown()
                s.server_close()
        threading.Thread(target=shutdown_old, daemon=True).start()
        event('پورت پنل تغییر کرد.')


def cli_add_account():
    """Interactive terminal account setup; secrets are never echoed or logged."""
    print('Add Firefox / Mozilla account')
    email = input('Email: ').strip()
    password = getpass.getpass('Password: ')
    totp = getpass.getpass('TOTP code or secret (optional): ')
    try:
        CTRL.add_account(email, password, totp)
        print('Account authenticated and saved. The panel will show it after refresh.')
        return 0
    except (EOFError, KeyboardInterrupt):
        print('\nCancelled.')
        return 130
    except ValueError as exc:
        print(f'Account authentication failed: {exc}', file=sys.stderr)
        return 1


def cli_list_accounts():
    print('Configured accounts:')
    accounts = CTRL.accounts()
    if not accounts:
        print('  No accounts configured.')
    for account in accounts:
        state = 'authenticated' if account['authenticated'] else 'not authenticated'
        current = ', current' if account['current'] else ''
        print(f"  {account['email']} ({state}{current})")
    return 0


def main():
    if '--add-account' in sys.argv[1:]:
        return cli_add_account()
    if '--list-accounts' in sys.argv[1:]:
        return cli_list_accounts()
    port = int(CTRL.preferences['panel_port'])
    server = create_server(port)
    SERVERS.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f'MozVPS panel: {"https" if TLS_CERT else "http"}://{HOST}:{port}', flush=True)
    if not TLS_CERT:
        print('WARNING: public HTTP and the default admin password are insecure; use HTTPS and change the password.', flush=True)
    if CTRL.preferences.get('desired', True):
        CTRL.start()
    def terminate(*_):
        STOP.set()
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    STOP.wait()
    CTRL.stop(permanent=False)
    with SERVER_LOCK:
        for s in SERVERS:
            s.shutdown()
            s.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
