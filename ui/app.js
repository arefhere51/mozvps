'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    authenticated: false,
    csrf: null,
    defaultPassword: false,
    locationsDirty: false,
    panelPortDirty: false,
    loadingStatus: false,
    loadingLogs: false,
    statusRefreshRequested: false,
    logsRefreshRequested: false,
    generation: 0,
    status: null,
    noticeTimer: null
  };

  // HTTP on any non-loopback address is treated conservatively as potentially public.
  const hostname = window.location.hostname.toLowerCase();
  const isLoopback = hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
  const insecureRemote = window.location.protocol !== 'https:' && !isLoopback;
  const numberFormat = new Intl.NumberFormat('fa-IR');
  const format = (value, fallback = 'نامشخص') => {
    if (value === null || value === undefined || value === '') return fallback;
    return typeof value === 'number' && Number.isFinite(value) ? numberFormat.format(value) : String(value);
  };
  const count = (value) => numberFormat.format(value);
  const bytes = (value) => {
    if (value === null || value === undefined || value === '') return '—';
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return format(value, '—');
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let scaled = number;
    let index = 0;
    while (scaled >= 1024 && index < units.length - 1) { scaled /= 1024; index += 1; }
    return new Intl.NumberFormat('fa-IR', {maximumFractionDigits: 2}).format(scaled) + ' ' + units[index];
  };

  function showNotice(message, isError = false) {
    const notice = $('notice');
    notice.textContent = message;
    notice.classList.toggle('error', isError);
    notice.hidden = false;
    clearTimeout(state.noticeTimer);
    state.noticeTimer = setTimeout(() => { notice.hidden = true; }, 6000);
  }

  function setError(id, message) {
    const node = $(id);
    node.textContent = message || '';
    node.hidden = !message;
  }

  function setBanner(id, message) {
    const node = $(id);
    node.querySelector('p').textContent = message || '';
    node.hidden = !message;
  }

  function updateSecurity() {
    const messages = [];
    if (state.defaultPassword) messages.push('رمز عبور پیش‌فرض پنل هنوز تغییر نکرده است؛ آن را فوراً به یک رمز قوی و یکتا تغییر دهید.');
    if (insecureRemote) messages.push('این اتصال HTTP در دسترسی غیرمحلی رمزگذاری نشده و خطرناک است؛ رمز پنل نیز در معرض شنود است. پیش از ارسال اطلاعات حساب موزیلا حتماً HTTPS را فعال کنید.');
    if (state.defaultPassword && insecureRemote) messages.push('ترکیب رمز پیش‌فرض ضعیف و HTTP روی شبکه عمومی بسیار خطرناک است.');
    const message = messages.join(' ');
    setBanner('login-security-warning', message);
    setBanner('security-warning', message);
    $('account-transport-hint').hidden = !insecureRemote;
    const accountButton = $('account-form').querySelector('button[type="submit"]');
    accountButton.disabled = insecureRemote || accountButton.getAttribute('aria-busy') === 'true';
  }

  async function api(path, options = {}) {
    const method = options.method || 'GET';
    const headers = { Accept: 'application/json' };
    if (method !== 'GET' && options.auth !== false) {
      if (!state.authenticated || !state.csrf) throw new Error('نشست امنیتی معتبر نیست. دوباره وارد پنل شوید.');
      headers['X-CSRF-Token'] = state.csrf;
    }
    let body;
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(options.body);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), path === '/api/accounts' ? 200000 : 45000);
    let response;
    try {
      response = await fetch(path, { method, headers, body, signal: controller.signal, credentials: 'same-origin', cache: 'no-store' });
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('پاسخی از سرور دریافت نشد؛ وضعیت عملیات را بررسی کنید.');
      throw new Error('ارتباط با سرور برقرار نشد. اتصال و اجرای پنل را بررسی کنید.');
    } finally {
      clearTimeout(timer);
    }
    if (response.status === 401 && options.auth !== false) {
      showLogin();
      setError('login-error', 'نشست شما پایان یافته است. دوباره وارد شوید.');
      throw new Error('نشست شما پایان یافته است.');
    }
    let data = {};
    try {
      const text = await response.text();
      if (text) data = JSON.parse(text);
    } catch (_) {
      if (!response.ok) throw new Error('درخواست با خطای سرور مواجه شد (' + count(response.status) + ').');
      throw new Error('پاسخ سرور قابل خواندن نیست.');
    }
    if (!response.ok || (data && typeof data.error === 'string' && data.error)) {
      throw new Error(data && typeof data.error === 'string' ? data.error : 'درخواست با خطا مواجه شد (' + count(response.status) + ').');
    }
    if (data && data.ok === false) throw new Error(typeof data.message === 'string' ? data.message : 'عملیات انجام نشد.');
    return data || {};
  }

  function applySession(session) {
    state.authenticated = session.authenticated === true;
    state.csrf = typeof session.csrf === 'string' && session.csrf ? session.csrf : null;
    state.defaultPassword = session.default_password === true;
    updateSecurity();
  }

  function showLogin() {
    state.generation += 1;
    state.authenticated = false;
    state.csrf = null;
    state.status = null;
    state.locationsDirty = false;
    state.panelPortDirty = false;
    $('boot-view').hidden = true;
    $('app-view').hidden = true;
    $('login-view').hidden = false;
    $('login-password').value = '';
    $('account-form').reset();
    $('password-form').reset();
    $('accounts-list').replaceChildren();
    $('locations-list').replaceChildren();
    $('logs-output').textContent = 'در حال دریافت گزارش‌ها...';
    updateSecurity();
  }

  function showApp() {
    $('boot-view').hidden = true;
    $('login-view').hidden = true;
    $('app-view').hidden = false;
    setError('login-error', '');
    updateSecurity();
    refreshStatus();
    refreshLogs();
  }

  async function withButton(button, task) {
    const oldText = button.textContent;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try { await task(); }
    catch (error) { showNotice(error.message || 'خطایی رخ داد.', true); }
    finally {
      button.disabled = false;
      if (button.id === 'save-locations' && !$('locations-list').querySelector('.location-row')) button.disabled = true;
      button.removeAttribute('aria-busy');
      // The button content remains intact; oldText is only used as an accessible fallback.
      if (!button.textContent.trim()) button.textContent = oldText;
      updateSecurity();
    }
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function icon(id) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'icon');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#' + id);
    svg.appendChild(use);
    return svg;
  }

  function badge(text, kind) {
    const node = element('span', 'badge ' + kind);
    node.append(element('span', 'badge-dot'), document.createTextNode(' ' + text));
    return node;
  }

  function renderStatus(data) {
    state.status = data;
    const states = {
      running: ['در حال اجرا', 'سرویس فعال است', 'good'],
      stopped: ['متوقف', 'سرویس متوقف است', 'neutral'],
      starting: ['در حال راه‌اندازی', 'در حال راه‌اندازی', 'warn'],
      error: ['خطا', 'سرویس با خطا مواجه است', 'bad']
    };
    const info = states[data.service] || ['نامشخص', 'وضعیت نامشخص', 'neutral'];
    const badgeNode = $('service-badge');
    badgeNode.className = 'badge ' + info[2];
    badgeNode.replaceChildren(element('span', 'badge-dot'), document.createTextNode(' ' + info[0]));
    $('service-title').textContent = info[1];
    $('service-detail').textContent = format(data.detail, 'جزئیاتی موجود نیست.');
    const accounts = Array.isArray(data.accounts) ? data.accounts : [];
    const locations = Array.isArray(data.locations) ? data.locations : [];
    $('account-count').textContent = count(accounts.length);
    $('accounts-counter').textContent = count(accounts.length) + ' حساب';
    const current = accounts.find((account) => account && account.current);
    $('current-account-summary').textContent = current ? 'حساب فعال: ' + format(current.email) : 'حساب فعال مشخص نشده است.';
    $('location-count').textContent = count(locations.filter((location) => location && location.active).length);
    renderAccounts(accounts);
    if (!state.locationsDirty) renderLocations(locations);
    if (!state.panelPortDirty && document.activeElement !== $('panel-port')) $('panel-port').value = data.panel_port == null ? '' : String(data.panel_port);
    const proxy = data.mozilla_proxy && typeof data.mozilla_proxy === 'object' ? data.mozilla_proxy : {};
    if (document.activeElement !== $('mozilla-proxy-host')) $('mozilla-proxy-host').value = proxy.host || '127.0.0.1';
    if (document.activeElement !== $('mozilla-proxy-port')) $('mozilla-proxy-port').value = proxy.port == null ? '8080' : String(proxy.port);
    $('mozilla-proxy-enabled').checked = proxy.enabled === true;
  }

  function renderAccounts(accounts) {
    const list = $('accounts-list');
    list.replaceChildren();
    if (!accounts.length) {
      list.appendChild(element('p', 'empty-state', 'هنوز حسابی اضافه نشده است. برای شروع، یک حساب موزیلا اضافه کنید.'));
      return;
    }
    for (const account of accounts) {
      if (!account || typeof account !== 'object') continue;
      const row = element('div', 'account-row');
      const identity = element('div', 'account-identity');
      const email = format(account.email, 'ایمیل نامشخص');
      const avatar = element('div', 'account-avatar', email.charAt(0).toUpperCase());
      avatar.setAttribute('aria-hidden', 'true');
      const identityText = element('div');
      identityText.appendChild(element('div', 'account-name', email));
      const meta = element('div', 'account-meta');
      if (account.current) meta.appendChild(badge('حساب فعال', 'good'));
      meta.appendChild(badge(account.authenticated ? 'احراز هویت شده' : 'نیازمند احراز هویت', account.authenticated ? 'neutral' : 'warn'));
      const remaining = Number(account.quota_remaining);
      const limit = Number(account.quota_limit);
      if (account.quota_remaining !== '' && account.quota_remaining != null && account.quota_limit !== '' && account.quota_limit != null && Number.isFinite(remaining) && Number.isFinite(limit) && limit > 0 && remaining / limit <= 0.2) {
        meta.appendChild(badge('سهمیه کم', 'warn'));
      }
      identityText.appendChild(meta);
      identity.append(avatar, identityText);
      const quota = element('div', 'account-quota');
      const top = element('div', 'quota-top');
      const quotaText = account.quota_unlimited ? 'نامحدود' : bytes(account.quota_remaining) + ' / ' + bytes(account.quota_limit);
      top.append(element('span', '', 'سهمیه باقی‌مانده'), element('strong', '', quotaText));
      quota.appendChild(top);
      if (account.quota_remaining !== '' && account.quota_remaining != null && account.quota_limit !== '' && account.quota_limit != null && Number.isFinite(remaining) && Number.isFinite(limit) && limit > 0) {
        const track = element('div', 'quota-track');
        const bar = element('div', 'quota-bar');
        const percent = Math.max(0, Math.min(100, remaining / limit * 100));
        bar.style.width = percent + '%';
        track.setAttribute('role', 'progressbar');
        track.setAttribute('aria-label', 'سهمیه باقی‌مانده');
        track.setAttribute('aria-valuemin', '0');
        track.setAttribute('aria-valuemax', '100');
        track.setAttribute('aria-valuenow', String(Math.round(percent)));
        track.appendChild(bar);
        quota.appendChild(track);
      }
      const bottom = element('div', 'quota-bottom');
      bottom.append(element('span', '', 'زمان بازنشانی'), element('span', '', format(account.quota_reset, 'نامشخص')));
      quota.appendChild(bottom);
      const deleteCell = element('div', 'account-delete');
      const remove = element('button', 'delete-button');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'حذف حساب ' + email);
      remove.title = 'حذف حساب';
      remove.appendChild(icon('i-trash'));
      remove.addEventListener('click', () => {
        if (!window.confirm('حساب «' + email + '» حذف شود؟')) return;
        withButton(remove, async () => {
          await api('/api/accounts/' + encodeURIComponent(String(account.email)), { method: 'DELETE' });
          showNotice('حساب حذف شد.');
          await refreshStatus();
        });
      });
      deleteCell.appendChild(remove);
      row.append(identity, quota, deleteCell);
      list.appendChild(row);
    }
    if (!list.childElementCount) list.appendChild(element('p', 'empty-state', 'حساب قابل نمایشی وجود ندارد.'));
  }

  function renderLocations(locations) {
    const list = $('locations-list');
    list.replaceChildren();
    if (!locations.length) {
      list.appendChild(element('p', 'empty-state', 'موقعیتی برای نمایش وجود ندارد.'));
      $('save-locations').disabled = true;
      return;
    }
    $('save-locations').disabled = false;
    for (const location of locations) {
      if (!location || typeof location !== 'object') continue;
      const row = element('div', 'location-row');
      row.locationId = location.id;
      const name = element('div', 'location-name');
      const glyph = element('span', 'location-dot');
      glyph.appendChild(icon('i-globe'));
      name.append(glyph, element('span', '', format(location.label, format(location.id))));
      const port = element('input', 'location-port');
      port.type = 'number';
      port.min = '1';
      port.max = '65535';
      port.required = true;
      port.inputMode = 'numeric';
      port.dir = 'ltr';
      port.value = location.port == null ? '' : String(location.port);
      port.setAttribute('aria-label', 'پورت ' + format(location.label, format(location.id)));
      const switchWrap = element('div', 'switch-wrap');
      const label = element('label', 'switch');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = Boolean(location.enabled);
      input.setAttribute('aria-label', 'فعال‌سازی ' + format(location.label, format(location.id)));
      label.append(input, element('span', 'switch-track'));
      switchWrap.appendChild(label);
      const markDirty = () => { state.locationsDirty = true; $('locations-hint').textContent = 'تغییرات ذخیره نشده‌اند.'; };
      port.addEventListener('input', markDirty);
      input.addEventListener('change', markDirty);
      row.append(name, port, switchWrap);
      list.appendChild(row);
    }
    $('save-locations').disabled = !list.querySelector('.location-row');
    $('locations-hint').textContent = 'تغییرات پس از ذخیره اعمال می‌شوند.';
  }

  async function refreshStatus() {
    if (!state.authenticated) return;
    if (state.loadingStatus) { state.statusRefreshRequested = true; return; }
    state.loadingStatus = true;
    const generation = state.generation;
    try {
      const data = await api('/api/status');
      if (!state.authenticated || generation !== state.generation) return;
      renderStatus(data);
      setBanner('status-error', '');
    } catch (error) {
      if (state.authenticated && generation === state.generation) setBanner('status-error', 'دریافت وضعیت ناموفق بود: ' + error.message);
    } finally {
      state.loadingStatus = false;
      if (state.statusRefreshRequested) {
        state.statusRefreshRequested = false;
        if (state.authenticated) refreshStatus();
      }
    }
  }

  async function refreshLogs() {
    if (!state.authenticated) return;
    if (state.loadingLogs) { state.logsRefreshRequested = true; return; }
    state.loadingLogs = true;
    const generation = state.generation;
    try {
      const data = await api('/api/logs');
      if (!state.authenticated || generation !== state.generation) return;
      const lines = Array.isArray(data.lines) ? data.lines : [];
      $('logs-output').textContent = lines.length ? lines.map((line) => String(line)).join('\n') : 'هنوز گزارشی وجود ندارد.';
    } catch (error) {
      if (state.authenticated && generation === state.generation) $('logs-output').textContent = 'دریافت گزارش‌ها ناموفق بود: ' + error.message;
    } finally {
      state.loadingLogs = false;
      if (state.logsRefreshRequested) {
        state.logsRefreshRequested = false;
        if (state.authenticated) refreshLogs();
      }
    }
  }

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    setError('login-error', '');
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try {
      const session = await api('/api/login', { method: 'POST', auth: false, body: { password: $('login-password').value } });
      applySession(session);
      if (!state.authenticated) throw new Error('ورود انجام نشد. رمز عبور را بررسی کنید.');
      $('login-password').value = '';
      showApp();
      if (!state.csrf) showNotice('نشست فاقد توکن امنیتی است؛ برای انجام تغییرات دوباره وارد شوید.', true);
    } catch (error) { setError('login-error', error.message); }
    finally { button.disabled = false; button.removeAttribute('aria-busy'); }
  });

  document.querySelectorAll('[data-reveal]').forEach((button) => button.addEventListener('click', () => {
    const input = $(button.dataset.reveal);
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    button.setAttribute('aria-label', showing ? 'نمایش رمز عبور' : 'پنهان کردن رمز عبور');
  }));

  $('logout-button').addEventListener('click', (event) => withButton(event.currentTarget, async () => {
    await api('/api/logout', { method: 'POST', body: {} });
    showLogin();
    showNotice('از پنل خارج شدید.');
  }));

  $('refresh-button').addEventListener('click', (event) => withButton(event.currentTarget, async () => {
    await Promise.all([refreshStatus(), refreshLogs()]);
  }));
  $('refresh-logs').addEventListener('click', (event) => withButton(event.currentTarget, refreshLogs));

  document.querySelectorAll('.service-action').forEach((button) => button.addEventListener('click', () => withButton(button, async () => {
    document.querySelectorAll('.service-action').forEach((item) => { item.disabled = true; });
    try {
      await api('/api/service', { method: 'POST', body: { action: button.dataset.action } });
      showNotice('درخواست مدیریت سرویس ثبت شد.');
      await refreshStatus();
      await refreshLogs();
    } finally { document.querySelectorAll('.service-action').forEach((item) => { item.disabled = false; }); }
  })));

  $('account-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (insecureRemote) { showNotice('برای ارسال اطلاعات حساب موزیلا از HTTPS استفاده کنید.', true); return; }
    const button = event.currentTarget.querySelector('button[type="submit"]');
    withButton(button, async () => {
      const result = await api('/api/accounts', { method: 'POST', body: { email: $('account-email').value.trim(), password: $('account-password').value, totp: $('account-totp').value.trim() } });
      $('account-form').reset();
      $('add-account-details').open = false;
      showNotice(typeof result.message === 'string' && result.message ? result.message : 'حساب اضافه شد.');
      await refreshStatus();
    });
  });

  $('locations-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const button = $('save-locations');
    const locations = Array.from($('locations-list').querySelectorAll('.location-row'), (row) => ({ id: row.locationId, port: Number(row.querySelector('.location-port').value), enabled: row.querySelector('input[type="checkbox"]').checked }));
    if (!locations.length) return;
    withButton(button, async () => {
      await api('/api/locations', { method: 'POST', body: { locations } });
      state.locationsDirty = false;
      showNotice('موقعیت‌ها ذخیره شدند.');
      await refreshStatus();
    });
  });

  $('panel-port').addEventListener('input', () => { state.panelPortDirty = true; });
  $('panel-port-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    withButton(button, async () => {
      await api('/api/panel-port', { method: 'POST', body: { port: Number($('panel-port').value) } });
      state.panelPortDirty = false;
      showNotice('پورت پنل ذخیره شد؛ در صورت نیاز با پورت جدید متصل شوید.');
      await refreshStatus();
    });
  });

  $('password-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    withButton(button, async () => {
      await api('/api/password', { method: 'POST', body: { current_password: $('current-password').value, new_password: $('new-password').value } });
      $('password-form').reset();
      showNotice('رمز عبور مدیریت تغییر کرد.');
      try {
        const session = await api('/api/session');
        applySession(session);
        if (!state.authenticated) showLogin();
      } catch (error) { showNotice('رمز تغییر کرد، اما دریافت وضعیت نشست ناموفق بود: ' + error.message, true); }
    });
  });

  $('mozilla-proxy-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    withButton(button, async () => {
      await api('/api/mozilla-proxy', { method: 'POST', body: {
        enabled: $('mozilla-proxy-enabled').checked,
        host: $('mozilla-proxy-host').value.trim(),
        port: Number($('mozilla-proxy-port').value)
      }});
      showNotice('تنظیم پروکسی Mozilla ذخیره شد.');
      await refreshStatus();
    });
  });

  document.querySelectorAll('.nav-link').forEach((link) => link.addEventListener('click', () => {
    document.querySelectorAll('.nav-link').forEach((item) => item.classList.remove('active'));
    link.classList.add('active');
  }));

  updateSecurity();
  api('/api/session', { auth: false }).then((session) => {
    applySession(session);
    if (state.authenticated) showApp();
    else showLogin();
  }).catch((error) => {
    showLogin();
    setError('login-error', error.message);
  });
  setInterval(() => { if (state.authenticated && !document.hidden) refreshStatus(); }, 15000);
})();
