'use strict';

(() => {
  const $ = (id) => document.getElementById(id);

  const views = { login: $('view-login'), otp: $('view-otp'), done: $('view-done') };

  const loginForm = $('login-form');
  const emailInput = $('email');
  const passwordInput = $('password');
  const loginSubmit = $('login-submit');
  const loginError = $('login-error');
  const loginNotice = $('login-notice');

  const otpForm = $('otp-form');
  const otpBoxes = $('otp-boxes');
  const digits = Array.from(document.querySelectorAll('.otp-digit'));
  const otpSubmit = $('otp-submit');
  const otpError = $('otp-error');
  const otpExpiry = $('otp-expiry');
  const resendBtn = $('otp-resend');

  let expiryTimer = null;
  let resendTimer = null;

  // ------------------------------------------------------------- helpers

  async function api(path, body) {
    const init = { method: body ? 'POST' : 'GET', credentials: 'same-origin', headers: {} };
    if (body) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    try {
      const res = await fetch(path, init);
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: { error: 'Can’t reach the server. Check your connection.' } };
    }
  }

  function show(name) {
    for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
    stopTimers();
    if (name === 'login') (emailInput.value ? passwordInput : emailInput).focus();
    if (name === 'otp') digits[0].focus();
  }

  function setBusy(button, busy) {
    button.setAttribute('aria-busy', String(busy));
    button.disabled = busy;
  }

  function setMessage(el, text) {
    el.textContent = text || '';
    el.hidden = !text;
  }

  function formatClock(seconds) {
    const m = Math.floor(seconds / 60);
    const s = String(seconds % 60).padStart(2, '0');
    return `${m}:${s}`;
  }

  function stopTimers() {
    clearInterval(expiryTimer);
    clearInterval(resendTimer);
  }

  // Timers run against a fixed deadline rather than counting ticks, so a
  // backgrounded tab still shows the right time when it comes back.
  function countdown(seconds, onTick, onDone) {
    const deadline = Date.now() + seconds * 1000;
    const tick = () => {
      const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      if (left > 0) return onTick(left);
      clearInterval(id);
      onDone();
    };
    const id = setInterval(tick, 1000);
    tick();
    return id;
  }

  // ---------------------------------------------------------- step 1

  $('reveal').addEventListener('click', (event) => {
    const button = event.currentTarget;
    const reveal = passwordInput.type === 'password';
    passwordInput.type = reveal ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(reveal));
    button.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
    passwordInput.focus();
  });

  for (const input of [emailInput, passwordInput]) {
    input.addEventListener('input', () => {
      input.removeAttribute('aria-invalid');
      setMessage(loginError, '');
    });
  }

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setMessage(loginError, '');
    setMessage(loginNotice, '');

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      emailInput.setAttribute('aria-invalid', 'true');
      setMessage(loginError, 'Enter a valid email address.');
      return emailInput.focus();
    }
    if (!password) {
      passwordInput.setAttribute('aria-invalid', 'true');
      setMessage(loginError, 'Enter your password.');
      return passwordInput.focus();
    }

    setBusy(loginSubmit, true);
    const { ok, data } = await api('/api/auth/login', { email, password });
    setBusy(loginSubmit, false);

    if (!ok) {
      setMessage(loginError, data.error || 'Sign-in failed. Please try again.');
      passwordInput.select();
      return;
    }

    passwordInput.value = '';
    enterOtp(data.pending);
  });

  // ---------------------------------------------------------- step 2

  function enterOtp(pending) {
    $('otp-email').textContent = pending.email;
    $('otp-delivery').hidden = pending.delivery !== 'log';
    setMessage(otpError, '');
    clearDigits();
    show('otp');
    startExpiry(pending.expiresIn);
    startResendCooldown(pending.resendIn);
  }

  function startExpiry(seconds) {
    clearInterval(expiryTimer);
    otpExpiry.classList.remove('expired');
    expiryTimer = countdown(
      seconds,
      (left) => { otpExpiry.textContent = `Code expires in ${formatClock(left)}`; },
      () => {
        otpExpiry.textContent = 'This code has expired. Send a new one.';
        otpExpiry.classList.add('expired');
      }
    );
  }

  function startResendCooldown(seconds) {
    clearInterval(resendTimer);
    if (!seconds) {
      resendBtn.disabled = false;
      resendBtn.textContent = 'Resend code';
      return;
    }
    resendBtn.disabled = true;
    resendTimer = countdown(
      seconds,
      (left) => { resendBtn.textContent = `Resend in ${formatClock(left)}`; },
      () => {
        resendBtn.disabled = false;
        resendBtn.textContent = 'Resend code';
      }
    );
  }

  function code() {
    return digits.map((d) => d.value).join('');
  }

  function paint() {
    for (const d of digits) d.classList.toggle('filled', d.value !== '');
    otpBoxes.classList.remove('invalid');
    setMessage(otpError, '');
  }

  function clearDigits() {
    for (const d of digits) d.value = '';
    paint();
  }

  function fillFrom(index, text) {
    const chars = text.replace(/\D/g, '').slice(0, digits.length - index).split('');
    chars.forEach((c, i) => { digits[index + i].value = c; });
    paint();
    const next = Math.min(index + chars.length, digits.length - 1);
    digits[next].focus();
    if (code().length === digits.length) otpForm.requestSubmit();
  }

  digits.forEach((input, index) => {
    input.addEventListener('input', () => {
      const value = input.value.replace(/\D/g, '');
      input.value = '';
      if (!value) return paint();
      fillFrom(index, value);
    });

    input.addEventListener('keydown', (event) => {
      if (event.key === 'Backspace' && !input.value && index > 0) {
        event.preventDefault();
        digits[index - 1].value = '';
        digits[index - 1].focus();
        paint();
      } else if (event.key === 'ArrowLeft' && index > 0) {
        event.preventDefault();
        digits[index - 1].focus();
      } else if (event.key === 'ArrowRight' && index < digits.length - 1) {
        event.preventDefault();
        digits[index + 1].focus();
      }
    });

    input.addEventListener('paste', (event) => {
      event.preventDefault();
      fillFrom(index, event.clipboardData.getData('text'));
    });

    // Deferred so the mouseup that follows a click doesn't undo the
    // selection — typing into a filled box then replaces its digit.
    input.addEventListener('focus', () => requestAnimationFrame(() => input.select()));
  });

  function rejectCode(message) {
    setMessage(otpError, message);
    otpBoxes.classList.add('invalid', 'shake');
    otpBoxes.addEventListener('animationend', () => otpBoxes.classList.remove('shake'), { once: true });
    for (const d of digits) d.value = '';
    for (const d of digits) d.classList.remove('filled');
    digits[0].focus();
  }

  function restart(message) {
    setMessage(loginNotice, message);
    show('login');
  }

  otpForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (otpSubmit.getAttribute('aria-busy') === 'true') return;

    const value = code();
    if (value.length !== digits.length) {
      setMessage(otpError, 'Enter all 6 digits.');
      return digits[value.length].focus();
    }

    setBusy(otpSubmit, true);
    const { ok, data } = await api('/api/auth/verify', { code: value });
    setBusy(otpSubmit, false);

    if (ok) return enterDone(data.user);
    if (data.restart) return restart(data.error);
    rejectCode(data.error || 'That code didn’t work.');
  });

  resendBtn.addEventListener('click', async () => {
    resendBtn.disabled = true;
    resendBtn.textContent = 'Sending…';
    const { ok, data } = await api('/api/auth/resend', {});

    if (ok) {
      clearDigits();
      digits[0].focus();
      $('otp-delivery').hidden = data.pending.delivery !== 'log';
      startExpiry(data.pending.expiresIn);
      startResendCooldown(data.pending.resendIn);
      setMessage(otpError, '');
      otpExpiry.textContent = 'A new code is on its way.';
      return;
    }
    if (data.restart) return restart(data.error);
    setMessage(otpError, data.error || 'Couldn’t send a new code.');
    startResendCooldown(data.retryAfter || 0);
  });

  $('otp-back').addEventListener('click', () => {
    setMessage(loginNotice, '');
    show('login');
  });

  // ---------------------------------------------------------- signed in

  function enterDone(user) {
    $('done-email').textContent = user.email;
    show('done');
    $('logout').focus();
  }

  $('logout').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true);
    await api('/api/auth/logout', {});
    setBusy(button, false);
    emailInput.value = '';
    setMessage(loginNotice, 'You’ve been signed out.');
    show('login');
  });

  // ---------------------------------------------------------- boot

  api('/api/auth/session').then(({ ok, data }) => {
    if (ok && data.authenticated) return enterDone(data.user);
    if (ok && data.pending) return enterOtp(data.pending);
    show('login');
  });
})();
