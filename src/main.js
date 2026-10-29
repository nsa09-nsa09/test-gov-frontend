import Keycloak from 'keycloak-js';

const KEYCLOAK_CONFIG = {
  url: 'http://localhost:8180',
  realm: 'GovApps',
  clientId: 'test-app',
};

// Alem Spring Boot BFF Gateway URL
const ALEM_API_BASE = 'http://localhost:8080/api/auth';
const SECOND_API_BASE = 'http://localhost:8081/api';

const keycloak = new Keycloak(KEYCLOAK_CONFIG);

// DOM Elements: Views
const loadingView = document.getElementById('loading-view');
const unauthView = document.getElementById('unauth-view');
const authView = document.getElementById('auth-view');

// DOM Elements: Header / Profile Actions
const btnLogin = document.getElementById('btn-login');
const btnLogout = document.getElementById('btn-logout');
const btnRefresh = document.getElementById('btn-refresh');
const btnCopyToken = document.getElementById('btn-copy-token');
const btnJwtIo = document.getElementById('btn-jwt-io');

const userName = document.getElementById('user-name');
const userUsername = document.getElementById('user-username');
const userEmail = document.getElementById('user-email');
const userAvatar = document.getElementById('user-avatar');
const badgeVerified = document.getElementById('badge-verified');
const expiryTimer = document.getElementById('expiry-timer');

const claimAud = document.getElementById('claim-aud');
const claimSub = document.getElementById('claim-sub');
const claimRoles = document.getElementById('claim-roles');
const claimIss = document.getElementById('claim-iss');

const jsonAccess = document.getElementById('json-access');
const jsonId = document.getElementById('json-id');
const rawAccess = document.getElementById('raw-access');
const rawRefresh = document.getElementById('raw-refresh');
const rawId = document.getElementById('raw-id');

// JWKS ID Token Verification Elements
const btnVerifyId = document.getElementById('btn-verify-id');
const btnVerifyRawId = document.getElementById('btn-verify-raw-id');
const verifyStatusPill = document.getElementById('verify-status-pill');
const verifyDetailsBox = document.getElementById('verify-details-box');
const verifyAlg = document.getElementById('verify-alg');
const verifyKid = document.getElementById('verify-kid');
const verifyIss = document.getElementById('verify-iss');
const verifySub = document.getElementById('verify-sub');
const verifyMsg = document.getElementById('verify-msg');

// Tabs for Alem Gateway (Login vs Register)
const tabBtnLogin = document.getElementById('tab-btn-login');
const tabBtnRegister = document.getElementById('tab-btn-register');
const paneLogin = document.getElementById('auth-pane-login');
const paneRegister = document.getElementById('auth-pane-register');

// Direct Login Form Elements
const directForm = document.getElementById('direct-auth-form');
const inputUsername = document.getElementById('direct-username');
const inputPassword = document.getElementById('direct-password');
const user2faStatus = document.getElementById('user-2fa-status');
const totpGroup = document.getElementById('direct-totp-group');
const inputTotp = document.getElementById('direct-totp');
const otpUserDisplay = document.getElementById('otp-user-display');
const directError = document.getElementById('direct-error');
const directSetupGroup = document.getElementById('direct-setup-group');
const btnSetup2fa = document.getElementById('btn-setup-2fa');
const directQrContainer = document.getElementById('direct-qr-container');
const directQrImg = document.getElementById('direct-qr-img');
const directSecretKey = document.getElementById('direct-secret-key');
const linkDirectQr = document.getElementById('link-direct-qr');
const btnCopyDirectUrl = document.getElementById('btn-copy-direct-url');
const directConfirmCode = document.getElementById('direct-confirm-code');
const btnConfirmTotp = document.getElementById('btn-confirm-totp');
const directConfirmMsg = document.getElementById('direct-confirm-msg');
const directResult = document.getElementById('direct-login-result');
const directJson = document.getElementById('direct-json');
const resultStatusBadge = document.getElementById('result-status-badge');
const btnDirectSubmit = document.getElementById('btn-direct-submit');

// Registration Form Elements
const registerForm = document.getElementById('register-form');
const regUsername = document.getElementById('reg-username');
const regEmail = document.getElementById('reg-email');
const regFirstname = document.getElementById('reg-firstname');
const regLastname = document.getElementById('reg-lastname');
const regPassword = document.getElementById('reg-password');
const regError = document.getElementById('reg-error');
const regSuccess = document.getElementById('reg-success');
const btnRegisterSubmit = document.getElementById('btn-register-submit');

let expiryInterval = null;
let currentSession = null; // { type: 'keycloak' | 'alem', accessToken, refreshToken, idToken, tokenParsed }
let current2FAState = { checked: false, has2fa: false, username: '' };
let checkDebounceTimer = null;
let activeTotpSetupId = null;

// Parse JWT without external libraries
function parseJwt(token) {
  if (!token) return {};
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return {};
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error('Failed to parse JWT:', e);
    return {};
  }
}

// Initialize Keycloak (Check SSO for standard redirect flow)
async function init() {
  try {
    const authenticated = await keycloak.init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      checkLoginIframe: false,
    });

    loadingView.classList.add('hidden');

    if (authenticated) {
      currentSession = {
        type: 'keycloak',
        accessToken: keycloak.token,
        refreshToken: keycloak.refreshToken,
        idToken: keycloak.idToken,
        tokenParsed: keycloak.tokenParsed,
      };
      renderAuthenticated();
    } else {
      renderUnauthenticated();
    }
  } catch (error) {
    console.warn('Keycloak OIDC check-sso error (will fallback to direct UI):', error);
    loadingView.classList.add('hidden');
    renderUnauthenticated();
  }
}

function renderUnauthenticated() {
  authView.classList.add('hidden');
  unauthView.classList.remove('hidden');
  if (expiryInterval) clearInterval(expiryInterval);
  verifyStatusPill?.classList.add('hidden');
  verifyDetailsBox?.classList.add('hidden');
  resetTokenExchangeUI();
}

function renderAuthenticated() {
  resetTokenExchangeUI();
  unauthView.classList.add('hidden');
  authView.classList.remove('hidden');
  verifyStatusPill?.classList.add('hidden');
  verifyDetailsBox?.classList.add('hidden');

  let tokenParsed = {};
  let idTokenParsed = {};
  let accessTokenStr = '';
  let refreshTokenStr = '';
  let idTokenStr = '';

  if (currentSession && currentSession.type === 'alem') {
    tokenParsed = currentSession.tokenParsed || {};
    accessTokenStr = currentSession.accessToken || '';
    refreshTokenStr = currentSession.refreshToken || '';
    idTokenStr = currentSession.idToken || '';
    idTokenParsed = idTokenStr ? parseJwt(idTokenStr) : { note: 'Direct grant token issued via Alem Gateway' };
  } else {
    tokenParsed = keycloak.tokenParsed || {};
    idTokenParsed = keycloak.idTokenParsed || {};
    accessTokenStr = keycloak.token || '';
    refreshTokenStr = keycloak.refreshToken || '';
    idTokenStr = keycloak.idToken || '';
  }

  // User Profile
  const name =
    tokenParsed.name ||
    `${tokenParsed.given_name || ''} ${tokenParsed.family_name || ''}`.trim() ||
    tokenParsed.preferred_username ||
    'Unknown User';

  userName.textContent = name;
  userUsername.textContent = `@${tokenParsed.preferred_username || '—'}`;
  userEmail.textContent = tokenParsed.email || 'No email';

  // Initials for Avatar
  const initials = (name || 'U')
    .split(' ')
    .map((n) => n[0])
    .join('')
    .substring(0, 2)
    .toUpperCase();
  userAvatar.textContent = initials;

  if (tokenParsed.email_verified) {
    badgeVerified.classList.remove('hidden');
  } else {
    badgeVerified.classList.add('hidden');
  }

  // Highlight Claims
  const audience = Array.isArray(tokenParsed.aud)
    ? tokenParsed.aud.join(', ')
    : tokenParsed.aud || '—';
  claimAud.textContent = audience;
  claimSub.textContent = tokenParsed.sub || '—';
  claimIss.textContent = tokenParsed.iss || '—';

  const roles = tokenParsed.realm_access?.roles || [];
  claimRoles.textContent = roles.length > 0 ? roles.join(', ') : 'None';

  // Formatted JSON Inspector
  jsonAccess.textContent = JSON.stringify(tokenParsed, null, 2);
  jsonId.textContent = JSON.stringify(idTokenParsed, null, 2);

  // Raw Tokens
  rawAccess.value = accessTokenStr;
  rawRefresh.value = refreshTokenStr;
  rawId.value = idTokenStr;

  startExpiryTimer(tokenParsed.exp);
}

function startExpiryTimer(expTimestamp) {
  if (expiryInterval) clearInterval(expiryInterval);

  function update() {
    const exp = expTimestamp || currentSession?.tokenParsed?.exp || keycloak.tokenParsed?.exp;
    if (!exp) {
      expiryTimer.textContent = '—';
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const remaining = exp - now;

    if (remaining <= 0) {
      expiryTimer.textContent = 'Expired';
      expiryTimer.style.color = '#ef4444';
    } else {
      const minutes = Math.floor(remaining / 60);
      const seconds = remaining % 60;
      expiryTimer.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
      expiryTimer.style.color = remaining < 60 ? '#f59e0b' : '#38bdf8';
    }
  }

  update();
  expiryInterval = setInterval(update, 1000);
}

// Browser Redirect Login
btnLogin.addEventListener('click', () => {
  keycloak.login();
});

// Logout handler (supports both Alem and Keycloak sessions)
btnLogout.addEventListener('click', async () => {
  if (currentSession && currentSession.type === 'alem') {
    try {
      if (currentSession.refreshToken) {
        await fetch(`${ALEM_API_BASE}/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken: currentSession.refreshToken }),
        });
      }
    } catch (e) {
      console.warn('Alem logout request failed:', e);
    }
    currentSession = null;
    renderUnauthenticated();
  } else {
    keycloak.logout();
  }
});

// Refresh token handler (supports both Alem and Keycloak sessions)
btnRefresh.addEventListener('click', async () => {
  if (currentSession && currentSession.type === 'alem') {
    if (!currentSession.refreshToken) {
      alert('No refresh token available to refresh');
      return;
    }
    try {
      const resp = await fetch(`${ALEM_API_BASE}/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: currentSession.refreshToken }),
      });
      const data = await resp.json();
      if (resp.ok && data.access_token) {
        currentSession.accessToken = data.access_token;
        if (data.refresh_token) currentSession.refreshToken = data.refresh_token;
        currentSession.tokenParsed = parseJwt(data.access_token);
        renderAuthenticated();
        alert('Token successfully refreshed via Alem Gateway!');
      } else {
        alert(data.message || 'Failed to refresh token via Alem');
      }
    } catch (e) {
      alert('Error refreshing token: ' + e.message);
    }
  } else {
    try {
      const refreshed = await keycloak.updateToken(-1);
      if (refreshed) {
        renderAuthenticated();
        alert('Token refreshed successfully via Keycloak!');
      } else {
        alert('Token is still valid');
      }
    } catch (error) {
      console.error('Failed to refresh token:', error);
      alert('Failed to refresh token. Session may have expired.');
    }
  }
});

btnCopyToken.addEventListener('click', async () => {
  const token = rawAccess.value;
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
    alert('Access token copied to clipboard!');
  } catch {
    alert('Could not copy to clipboard');
  }
});

btnJwtIo.addEventListener('click', () => {
  const token = rawAccess.value;
  if (!token) return;
  window.open(`https://jwt.io/#id_token=${token}`, '_blank');
});

// --- JWKS ID Token Signature Verification ---
async function verifyIdTokenWithAlem() {
  const token = rawId.value || currentSession?.idToken || keycloak.idToken;
  if (!token) {
    alert('No ID token available to verify. Please log in first.');
    return;
  }

  verifyStatusPill.className = 'verify-pill loading';
  verifyStatusPill.classList.remove('hidden');
  verifyStatusPill.innerHTML = '<span class="status-icon">🔄</span><span>Verifying with JWKS...</span>';
  btnVerifyId.disabled = true;
  if (btnVerifyRawId) btnVerifyRawId.disabled = true;

  try {
    const response = await fetch(`${ALEM_API_BASE}/verify-id-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id_token: token }),
    });

    const data = await response.json();

    verifyDetailsBox.classList.remove('hidden');
    verifyAlg.textContent = data.algorithm || 'RS256';
    verifyKid.textContent = data.key_id || '—';
    verifyIss.textContent = data.issuer || '—';
    verifySub.textContent = data.subject || '—';
    verifyMsg.textContent = data.message || (data.valid ? 'Signature is valid' : 'Verification failed');

    if (data.valid) {
      verifyStatusPill.className = 'verify-pill valid';
      verifyStatusPill.innerHTML = '<span class="status-icon">✅</span><span>Signature Valid (JWKS)</span>';
    } else {
      verifyStatusPill.className = 'verify-pill invalid';
      verifyStatusPill.innerHTML = '<span class="status-icon">❌</span><span>Invalid Signature</span>';
    }
  } catch (err) {
    verifyStatusPill.className = 'verify-pill invalid';
    verifyStatusPill.innerHTML = `<span class="status-icon">❌</span><span>Error: ${err.message}</span>`;
  } finally {
    btnVerifyId.disabled = false;
    if (btnVerifyRawId) btnVerifyRawId.disabled = false;
  }
}

btnVerifyId?.addEventListener('click', () => verifyIdTokenWithAlem());
btnVerifyRawId?.addEventListener('click', () => {
  document.querySelector('.tab-btn[data-tab="tab-id"]')?.click();
  verifyIdTokenWithAlem();
});

// Inspector Tabs
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach((p) => p.classList.remove('active'));

    btn.classList.add('active');
    const targetId = btn.getAttribute('data-tab');
    document.getElementById(targetId)?.classList.add('active');
  });
});

// --- Auth Tabs: Switch between Login and Register ---
tabBtnLogin.addEventListener('click', () => {
  tabBtnLogin.classList.add('active');
  tabBtnRegister.classList.remove('active');
  paneLogin.classList.remove('hidden');
  paneRegister.classList.add('hidden');
  regError.classList.add('hidden');
  regSuccess.classList.add('hidden');
});

tabBtnRegister.addEventListener('click', () => {
  tabBtnRegister.classList.add('active');
  tabBtnLogin.classList.remove('active');
  paneRegister.classList.remove('hidden');
  paneLogin.classList.add('hidden');
  directError.classList.add('hidden');
});

// --- Alem Gateway: Smart 2FA Precheck ---
async function checkUser2FA(username) {
  if (!username) {
    user2faStatus.className = 'user-status-pill status-loading';
    user2faStatus.innerHTML = '<span class="status-icon">ℹ️</span><span class="status-msg">Enter a username</span>';
    totpGroup.classList.add('hidden');
    directSetupGroup.classList.add('hidden');
    current2FAState = { checked: false, has2fa: false, needsSetup: false, username: '' };
    return;
  }

  user2faStatus.className = 'user-status-pill status-loading';
  user2faStatus.innerHTML = '<span class="status-icon">🔄</span><span class="status-msg">Checking 2FA via Alem...</span>';

  try {
    const res = await fetch(`${ALEM_API_BASE}/check-2fa?username=${encodeURIComponent(username)}`);
    const data = await res.json();

    if (!data.exists) {
      current2FAState = { checked: true, has2fa: false, needsSetup: false, username };
      user2faStatus.className = 'user-status-pill status-unknown';
      user2faStatus.innerHTML = `<span class="status-icon">⚠️</span><span class="status-msg">User <b>${username}</b> not found in GovApps</span>`;
      totpGroup.classList.add('hidden');
      directSetupGroup.classList.add('hidden');
      return;
    }

    if (data.needs_2fa_setup) {
      current2FAState = { checked: true, has2fa: false, needsSetup: true, username: data.username, setupUrl: data.setup_url };
      user2faStatus.className = 'user-status-pill status-setup-needed';
      user2faStatus.innerHTML = `<span class="status-icon">⚠️</span><span class="status-msg"><b>2FA Setup Needed:</b> QR code setup required for first login</span>`;
      directSetupGroup.classList.remove('hidden');
      totpGroup.classList.add('hidden');
    } else if (data.has2fa) {
      current2FAState = { checked: true, has2fa: true, needsSetup: false, username: data.username };
      user2faStatus.className = 'user-status-pill status-2fa';
      user2faStatus.innerHTML = `<span class="status-icon">🛡️</span><span class="status-msg"><b>2FA Enabled:</b> Google Authenticator required</span>`;
      otpUserDisplay.textContent = `GovApps (${data.username})`;
      totpGroup.classList.remove('hidden');
      directSetupGroup.classList.add('hidden');
    } else {
      current2FAState = { checked: true, has2fa: false, needsSetup: false, username: data.username };
      user2faStatus.className = 'user-status-pill status-no-2fa';
      user2faStatus.innerHTML = `<span class="status-icon">🔓</span><span class="status-msg"><b>Standard Login:</b> Password only (no 2FA)</span>`;
      totpGroup.classList.add('hidden');
      directSetupGroup.classList.add('hidden');
    }
  } catch (err) {
    console.error('Failed to precheck 2FA via Alem:', err);
    user2faStatus.className = 'user-status-pill status-unknown';
    user2faStatus.innerHTML = `<span class="status-icon">⚠️</span><span class="status-msg">Could not reach Alem backend: ${err.message}</span>`;
  }
}

// Quick Fill Chips
document.querySelectorAll('.btn-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    const user = chip.getAttribute('data-user');
    inputUsername.value = user;
    inputPassword.value = (user === 'alemtest1') ? 'password123' : 'password';
    inputTotp.value = '';
    directError.classList.add('hidden');
    directResult.classList.add('hidden');
    checkUser2FA(user);
  });
});

// Live debounce check as user types username
inputUsername.addEventListener('input', () => {
  clearTimeout(checkDebounceTimer);
  directError.classList.add('hidden');
  checkDebounceTimer = setTimeout(() => {
    checkUser2FA(inputUsername.value.trim());
  }, 350);
});

// Setup 2FA Popup Handler (for first login onboarding)
let setupPopup = null;

window.addEventListener('message', (event) => {
  if (event.data?.type === '2FA_SETUP_SUCCESS') {
    console.log('[Alem] Received 2FA_SETUP_SUCCESS event from callback window');
    if (setupPopup && !setupPopup.closed) {
      setupPopup.close();
    }
    const user = inputUsername.value.trim();
    if (user) {
      checkUser2FA(user);
    }
  }
});

function renderDirectTotpData(data) {
  if (!data) return;

  activeTotpSetupId = data.setup_id || null;

  if (data.qr_code_base64 && directQrImg) {
    directQrImg.src = data.qr_code_base64;
  }
  if (data.totp_secret && directSecretKey) {
    directSecretKey.textContent = data.totp_secret;
  }
  const targetUrl = data.bridge_url || data.direct_qr_url;
  if (targetUrl && linkDirectQr) {
    linkDirectQr.href = targetUrl;
  }

  directQrContainer?.classList.remove('hidden');
  totpGroup?.classList.remove('hidden');

  if (directConfirmMsg) {
    directConfirmMsg.className = 'hidden';
    directConfirmMsg.textContent = '';
  }
  if (directConfirmCode) {
    directConfirmCode.value = '';
    directConfirmCode.focus();
  }

  btnCopyDirectUrl?.addEventListener('click', async () => {
    const rawDirectUrl = data.direct_qr_url || targetUrl;
    if (!rawDirectUrl) return;
    try {
      await navigator.clipboard.writeText(rawDirectUrl);
      alert('Прямая ссылка на QR-код скопирована в буфер обмена!\n\n' + rawDirectUrl);
    } catch {
      prompt('Скопируйте ссылку вручную:', rawDirectUrl);
    }
  });
}

btnSetup2fa?.addEventListener('click', async () => {
  const username = inputUsername.value.trim();
  const password = inputPassword.value;
  if (!username || !password) {
    alert('Пожалуйста, введите логин и пароль в форме входа.');
    inputPassword.focus();
    return;
  }

  btnSetup2fa.disabled = true;
  btnSetup2fa.textContent = 'Генерация QR-кода через Keycloak SPI...';
  directError.classList.add('hidden');

  try {
    const res = await fetch(`${ALEM_API_BASE}/2fa/totp/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();
    if (res.ok && data.success) {
      renderDirectTotpData(data);
      console.log('[Alem] Direct Keycloak SPI QR code received. Setup ID:', data.setup_id);
    } else {
      directError.textContent = data.message || 'Не удалось получить QR-код через Keycloak SPI';
      directError.classList.remove('hidden');
    }
  } catch (err) {
    directError.textContent = `Ошибка связи с Alem: ${err.message}`;
    directError.classList.remove('hidden');
  } finally {
    btnSetup2fa.disabled = false;
    btnSetup2fa.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="3" width="7" height="7"/>
        <rect x="14" y="3" width="7" height="7"/>
        <rect x="14" y="14" width="7" height="7"/>
        <rect x="3" y="14" width="7" height="7"/>
      </svg>
      Получить QR-код напрямую (Native Keycloak TOTP API)
    `;
  }
});

btnConfirmTotp?.addEventListener('click', async () => {
  const username = inputUsername.value.trim();
  const code = (directConfirmCode?.value?.trim().replace(/\D/g, '')) || (inputTotp?.value?.trim().replace(/\D/g, ''));
  if (!code || code.length !== 6) {
    if (directConfirmMsg) {
      directConfirmMsg.className = '';
      directConfirmMsg.style.background = '#7f1d1d';
      directConfirmMsg.style.color = '#fecaca';
      directConfirmMsg.textContent = 'Пожалуйста, введите 6 цифр из приложения Authenticator.';
      directConfirmMsg.classList.remove('hidden');
    }
    directConfirmCode?.focus();
    return;
  }

  btnConfirmTotp.disabled = true;
  btnConfirmTotp.textContent = 'Проверка...';

  try {
    const res = await fetch(`${ALEM_API_BASE}/2fa/totp/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        setup_id: activeTotpSetupId,
        username,
        code,
        device_name: 'Google Authenticator'
      }),
    });

    const data = await res.json();
    if (res.ok && data.success) {
      if (directConfirmMsg) {
        directConfirmMsg.className = '';
        directConfirmMsg.style.background = '#064e3b';
        directConfirmMsg.style.color = '#a7f3d0';
        directConfirmMsg.textContent = '✅ 2FA успешно активирована в Keycloak! Теперь вы можете войти.';
        directConfirmMsg.classList.remove('hidden');
      }
      if (inputTotp) {
        inputTotp.value = code;
      }
      await checkUser2FA(username);
    } else {
      if (directConfirmMsg) {
        directConfirmMsg.className = '';
        directConfirmMsg.style.background = '#7f1d1d';
        directConfirmMsg.style.color = '#fecaca';
        directConfirmMsg.textContent = '❌ ' + (data.message || 'Неверный код подтверждения');
        directConfirmMsg.classList.remove('hidden');
      }
    }
  } catch (err) {
    if (directConfirmMsg) {
      directConfirmMsg.className = '';
      directConfirmMsg.style.background = '#7f1d1d';
      directConfirmMsg.style.color = '#fecaca';
      directConfirmMsg.textContent = '❌ Ошибка сети: ' + err.message;
      directConfirmMsg.classList.remove('hidden');
    }
  } finally {
    btnConfirmTotp.disabled = false;
    btnConfirmTotp.textContent = 'Активировать 2FA';
  }
});

directConfirmCode?.addEventListener('keyup', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    btnConfirmTotp?.click();
  }
});

// --- Alem Gateway: Direct Login Submit ---
directForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  directError.classList.add('hidden');
  directResult.classList.add('hidden');

  const username = inputUsername.value.trim();
  const password = inputPassword.value;

  if (!current2FAState.checked || current2FAState.username !== username) {
    btnDirectSubmit.disabled = true;
    btnDirectSubmit.textContent = 'Checking user...';
    await checkUser2FA(username);
    btnDirectSubmit.disabled = false;
    btnDirectSubmit.textContent = 'Sign in via Alem (POST /login)';
  }

  const payload = {
    username,
    password,
  };

  const totpVal = (inputTotp.value.trim().replace(/\D/g, '')) || (directConfirmCode?.value?.trim().replace(/\D/g, ''));

  if (current2FAState.needsSetup) {
    if (totpVal.length !== 6) {
      btnSetup2fa?.click();
      directError.innerHTML = `
        <strong>First-time 2FA Setup Required:</strong>
        <p style="margin-top: 4px;">Сгенерирован QR-код. Отсканируйте его в приложении, введите 6-значный код и нажмите "Активировать 2FA" или Sign in.</p>
      `;
      directError.classList.remove('hidden');
      (directConfirmCode || inputTotp).focus();
      return;
    }

    if (activeTotpSetupId) {
      try {
        btnDirectSubmit.disabled = true;
        btnDirectSubmit.textContent = 'Activating 2FA in Keycloak...';
        const confirmRes = await fetch(`${ALEM_API_BASE}/2fa/totp/confirm`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            setup_id: activeTotpSetupId,
            username,
            code: totpVal,
            device_name: 'Google Authenticator'
          }),
        });
        const confirmData = await confirmRes.json();
        if (!confirmRes.ok || !confirmData.success) {
          directError.textContent = 'Ошибка активации 2FA: ' + (confirmData.message || 'Неверный код');
          directError.classList.remove('hidden');
          btnDirectSubmit.disabled = false;
          btnDirectSubmit.textContent = 'Sign in via Alem (POST /login)';
          return;
        }
      } catch (err) {
        console.warn('Auto-confirm failed:', err);
      }
    }
    payload.otp = totpVal;
  } else if (current2FAState.has2fa) {
    if (totpVal.length !== 6) {
      directError.textContent = 'Please enter the 6-digit code from Google Authenticator';
      directError.classList.remove('hidden');
      inputTotp.focus();
      return;
    }
    payload.otp = totpVal;
  }

  btnDirectSubmit.disabled = true;
  btnDirectSubmit.textContent = current2FAState.has2fa ? 'Verifying 2FA via Alem...' : 'Signing in via Alem...';

  try {
    console.log(`[Alem Gateway] POST ${ALEM_API_BASE}/login for user:`, username);
    const response = await fetch(`${ALEM_API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (response.ok && data.access_token) {
      resultStatusBadge.textContent = current2FAState.has2fa ? 'Success (2FA Verified)' : 'Success (No 2FA)';
      resultStatusBadge.className = 'badge badge-success';
      directResult.classList.remove('hidden');
      directJson.textContent = JSON.stringify(data, null, 2);
      inputTotp.value = '';

      // Set active session from Alem Gateway
      currentSession = {
        type: 'alem',
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        idToken: data.id_token || '',
        tokenParsed: parseJwt(data.access_token),
      };

      // Switch to Authenticated Token Inspector View
      renderAuthenticated();
    } else {
      console.warn('[Alem Gateway] Login failed:', data);

      // Если в ответе вернулись данные для настройки 2FA (QR-код и прямая ссылка)
      if (data.data && data.data.qr_code_base64) {
        renderDirectTotpData(data.data);
        directError.innerHTML = `
          <strong>${data.message || 'Требуется настройка 2FA'}</strong>
          <p style="margin-top: 4px; font-size: 11px;">Сгенерирован QR-код и прямая ссылка. Отсканируйте QR-код в Google Authenticator, введите 6-значный код в поле выше и нажмите Sign in снова.</p>
        `;
        directError.classList.remove('hidden');
        inputTotp.focus();
        return;
      }

      const errorMsg = data.message || 'Invalid username or password';
      const isGenericCredError = errorMsg.includes('Неверный') || errorMsg.toLowerCase().includes('credential') || errorMsg.toLowerCase().includes('password');
      if (current2FAState.has2fa && isGenericCredError) {
        directError.innerHTML = `
          <strong>Authentication Failed: ${errorMsg}</strong>
          <ul style="margin: 6px 0 0 16px; padding: 0; font-size: 11px; line-height: 1.5;">
            <li>Check if password is correct.</li>
            <li>Check Google Authenticator for a valid 6-digit code.</li>
          </ul>
        `;
      } else {
        directError.innerHTML = `<strong>Authentication Failed:</strong> ${errorMsg}`;
      }
      directError.classList.remove('hidden');
    }
  } catch (err) {
    directError.textContent = `Network error connecting to Alem (${ALEM_API_BASE}): ${err.message}`;
    directError.classList.remove('hidden');
  } finally {
    btnDirectSubmit.disabled = false;
    btnDirectSubmit.textContent = 'Sign in via Alem (POST /login)';
  }
});

// --- Alem Gateway: Register Submit ---
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  regError.classList.add('hidden');
  regSuccess.classList.add('hidden');

  const payload = {
    username: regUsername.value.trim(),
    email: regEmail.value.trim(),
    firstName: regFirstname.value.trim(),
    lastName: regLastname.value.trim(),
    password: regPassword.value,
  };

  btnRegisterSubmit.disabled = true;
  btnRegisterSubmit.textContent = 'Registering in Keycloak via Alem...';

  try {
    console.log(`[Alem Gateway] POST ${ALEM_API_BASE}/register:`, payload.username);
    const response = await fetch(`${ALEM_API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (response.ok && data.success) {
      regSuccess.innerHTML = `
        <strong>Registration Successful!</strong><br />
        Пользователь <b>${payload.username}</b> создан в Keycloak (ID: <code>${data.data?.userId || 'ok'}</code>).
        <p style="margin-top: 4px; font-size: 11px;">Переключение на форму входа...</p>
      `;
      regSuccess.classList.remove('hidden');

      // Clear password field
      regPassword.value = '';

      // Auto fill login form and switch to login tab after brief pause
      setTimeout(() => {
        tabBtnLogin.click();
        inputUsername.value = payload.username;
        inputPassword.value = payload.password;
        checkUser2FA(payload.username);
      }, 1500);
    } else {
      regError.textContent = data.message || 'Registration failed';
      regError.classList.remove('hidden');
    }
  } catch (err) {
    regError.textContent = `Network error connecting to Alem: ${err.message}`;
    regError.classList.remove('hidden');
  } finally {
    btnRegisterSubmit.disabled = false;
    btnRegisterSubmit.textContent = 'Register in Keycloak (POST /register)';
  }
});

// ---------------------------------------------------------------------------
// Token Exchange (RFC 8693): токен alem → токен second-backend через Keycloak.
// Три шага: ① second отклоняет токен alem, ② обмен в Keycloak, ③ second принимает новый токен.
// ---------------------------------------------------------------------------
const SECOND_CLIENT_ID = 'second-backend';

const btnTeRunAll = document.getElementById('btn-te-run-all');
const teSummary = document.getElementById('te-summary');
const teCompare = document.getElementById('te-compare');
const teCompareBody = document.getElementById('te-compare-body');
const teCompareEmpty = document.getElementById('te-compare-empty');
const btnTeIntrospectAlem = document.getElementById('btn-te-introspect-alem');
const btnTeIntrospectSecond = document.getElementById('btn-te-introspect-second');
const btnTeCopy = document.getElementById('btn-te-copy');
const teRawSecond = document.getElementById('te-raw-second');
const teLastTitle = document.getElementById('te-last-title');
const teLastStatus = document.getElementById('te-last-status');
const teLastJson = document.getElementById('te-last-json');

const TE_COMPARE_FIELDS = [
  ['azp', 'Кому выдан токен (клиент Keycloak)'],
  ['aud', 'Для кого предназначен'],
  ['iss', 'Кто выдал'],
  ['sub', 'ID пользователя'],
  ['preferred_username', 'Логин пользователя'],
  ['scope', 'Права (scope)'],
  ['exp', 'Действует до'],
];

const teSteps = [1, 2, 3].map((n) => ({
  item: document.getElementById(`te-step-${n}`),
  button: document.getElementById(`btn-te-step-${n}`),
  result: document.getElementById(`te-result-${n}`),
}));

let teSecondToken = null;
let teBusy = false;

function getAlemAccessToken() {
  return (rawAccess?.value || currentSession?.accessToken || keycloak?.token || '').trim();
}

function formatTime(epochSeconds) {
  return epochSeconds ? new Date(epochSeconds * 1000).toLocaleTimeString() : '—';
}

function formatClaim(name, value) {
  if (value === undefined || value === null) return '—';
  if (name === 'exp' && typeof value === 'number') return formatTime(value);
  if (Array.isArray(value)) return value.join(', ');
  return String(value);
}

// state: idle | running | ok | fail
function setStep(n, state, title, lines = []) {
  const step = teSteps[n - 1];
  step.item.dataset.state = state;
  step.result.replaceChildren();

  if (state === 'idle') {
    step.result.classList.add('hidden');
    return;
  }

  const icon = { running: '…', ok: '✔', fail: '✖' }[state];
  const head = document.createElement('div');
  head.className = 'te-result-title';
  head.textContent = `${icon} ${title}`;
  step.result.appendChild(head);

  for (const line of lines) {
    const row = document.createElement('div');
    row.className = 'te-result-line';
    row.textContent = line;
    step.result.appendChild(row);
  }
  step.result.classList.remove('hidden');
}

function updateSummary() {
  const states = teSteps.map((s) => s.item.dataset.state);
  const failed = states.indexOf('fail');

  if (states.every((state) => state === 'ok')) {
    teSummary.textContent = '✔ Итог: Token Exchange работает. Second пускает только токен, полученный через Keycloak.';
    teSummary.className = 'te-summary te-summary-ok';
  } else if (failed !== -1) {
    teSummary.textContent = `✖ Шаг ${failed + 1} не прошёл — подсказка в шаге выше.`;
    teSummary.className = 'te-summary te-summary-fail';
  } else {
    teSummary.className = 'te-summary hidden';
  }
}

function updateTeButtons() {
  teSteps[2].button.disabled = teBusy || !teSecondToken;
  teSteps[0].button.disabled = teBusy;
  teSteps[1].button.disabled = teBusy;
  btnTeRunAll.disabled = teBusy;
  btnTeIntrospectSecond.disabled = !teSecondToken;
  btnTeCopy.disabled = !teSecondToken;
}

function resetTokenExchangeUI() {
  teSecondToken = null;
  teBusy = false;
  [1, 2, 3].forEach((n) => setStep(n, 'idle'));
  updateSummary();
  teCompare.classList.add('hidden');
  teCompareEmpty.classList.remove('hidden');
  teCompareBody.replaceChildren();
  teRawSecond.value = '';
  updateTeButtons();
}

function showLastResponse(title, status, body) {
  teLastTitle.textContent = title;
  teLastStatus.textContent = status === 0 ? 'нет ответа' : String(status);
  teLastStatus.className = `badge ${status >= 200 && status < 300 ? 'badge-success' : 'badge-danger'}`;
  teLastJson.textContent = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
}

// Возвращает { status, data }; status = 0, если сервис не ответил.
async function callSecond(title, path, options) {
  try {
    const resp = await fetch(`${SECOND_API_BASE}${path}`, options);
    const data = await resp.json().catch(() => ({}));
    showLastResponse(title, resp.status, data);
    return { status: resp.status, data };
  } catch (err) {
    showLastResponse(title, 0, err.message);
    return { status: 0, data: null };
  }
}

function postJson(body) {
  return { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function bearer(token) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

// Перевод ошибки API на понятный язык: [что случилось, что сделать]
function explainError(status, data) {
  const message = data?.message || '';
  if (status === 0) {
    return ['Сервис second (:8081) не отвечает.', 'Запустите его: docker compose up -d'];
  }
  if (message.includes('Keycloak (') || message.includes('JWKS Keycloak')) {
    return ['Second не может связаться с Keycloak (:8180).', 'Проверьте, что контейнер keycloak запущен.'];
  }
  if (message.includes('(expiration)')) {
    return ['Токен alem истёк.', 'Нажмите «Refresh» вверху страницы и повторите.'];
  }
  if (message.includes('Audience mapper')) {
    return ['Токен alem не предназначен для second (в aud нет second-backend).',
      'Keycloak → Clients → test-app → Client scopes → test-app-dedicated → добавьте Audience mapper «second-backend».'];
  }
  if (message.includes('Standard Token Exchange') || message.includes('Capability config')) {
    return ['В Keycloak выключен обмен токенов для second-backend.',
      'Keycloak → Clients → second-backend → Settings → Capability config → Standard Token Exchange: On.'];
  }
  if (message.includes('client-secret')) {
    return ['Keycloak не принял пароль клиента second-backend (client secret).',
      'Сверьте keycloak.client-secret в second с Clients → second-backend → Credentials.'];
  }
  if (message.includes('(signature)') || message.includes('(issuer)')) {
    return ['Токен не прошёл проверку подписи или издателя.', message];
  }
  return [message || `Неожиданный ответ сервера (HTTP ${status}).`, 'Подробности — в «Подробнее» → Последний ответ API.'];
}

function failStep(n, title, status, data) {
  const [what, todo] = explainError(status, data);
  setStep(n, 'fail', title, [what, `Что сделать: ${todo}`]);
  return false;
}

function requireAlemToken(n) {
  const token = getAlemAccessToken();
  if (!token) {
    setStep(n, 'fail', 'Нет токена alem', ['Сначала войдите в систему.']);
  }
  return token;
}

async function runStep1() {
  const token = requireAlemToken(1);
  if (!token) return false;
  setStep(1, 'running', 'Отправляем токен alem в second…');

  const { status, data } = await callSecond('GET /api/second/me (токен alem)', '/second/me', bearer(token));
  const azp = parseJwt(token).azp || '—';

  if (status === 401 && data?.message?.includes('authorized_party')) {
    setStep(1, 'ok', 'Second отклонил токен alem — так и должно быть', [
      `Причина: токен выдан для «${azp}», а не для «${SECOND_CLIENT_ID}».`,
    ]);
    return true;
  }
  if (status === 200) {
    setStep(1, 'fail', 'Second принял токен alem без обмена', [
      'Так быть не должно: second обязан проверять, кому выдан токен (azp).',
    ]);
    return false;
  }
  return failStep(1, 'Не удалось проверить токен', status, data);
}

async function runStep2() {
  const subjectToken = requireAlemToken(2);
  if (!subjectToken) return false;

  teSecondToken = null;
  setStep(3, 'idle');
  setStep(2, 'running', 'Обмениваем токен в Keycloak…');
  updateTeButtons();

  const { status, data } = await callSecond('POST /api/auth/token-exchange', '/auth/token-exchange',
    postJson({ subject_token: subjectToken }));

  if (status !== 200 || !data?.access_token) {
    updateTeButtons();
    return failStep(2, 'Keycloak не выдал новый токен', status, data);
  }

  teSecondToken = data.access_token;
  teRawSecond.value = teSecondToken;

  const before = parseJwt(subjectToken);
  const after = parseJwt(teSecondToken);
  const sameUser = before.sub === after.sub;
  setStep(2, 'ok', 'Keycloak выдал новый токен для second', [
    `Кому выдан: ${before.azp || '—'} → ${after.azp || '—'}`,
    `Пользователь: ${after.preferred_username || after.sub || '—'} ${sameUser ? '(тот же)' : '(ИЗМЕНИЛСЯ!)'}`,
    `Действует до: ${formatTime(after.exp)}`,
  ]);
  renderCompare(before, after);
  updateTeButtons();
  return true;
}

async function runStep3() {
  if (!teSecondToken) {
    setStep(3, 'fail', 'Нет токена second', ['Сначала выполните шаг 2.']);
    return false;
  }
  setStep(3, 'running', 'Отправляем новый токен в second…');

  const { status, data } = await callSecond('GET /api/second/me (токен second)', '/second/me', bearer(teSecondToken));

  if (status === 200 && data?.success) {
    const user = data.data?.user || {};
    setStep(3, 'ok', 'Second принял новый токен', [
      `Пользователь: ${user.username || '—'}${user.email ? ` (${user.email})` : ''}`,
    ]);
    return true;
  }
  return failStep(3, 'Second не принял новый токен', status, data);
}

function renderCompare(before, after) {
  teCompareBody.replaceChildren();
  for (const [field, meaning] of TE_COMPARE_FIELDS) {
    const valueBefore = formatClaim(field, before[field]);
    const valueAfter = formatClaim(field, after[field]);
    const row = document.createElement('tr');
    if (valueBefore !== valueAfter) row.className = 'te-changed';

    [field, meaning, valueBefore, valueAfter].forEach((text, i) => {
      const cell = document.createElement('td');
      if (i === 1) {
        cell.textContent = text;
      } else {
        const code = document.createElement('code');
        code.textContent = text;
        cell.appendChild(code);
      }
      row.appendChild(cell);
    });
    teCompareBody.appendChild(row);
  }
  teCompare.classList.remove('hidden');
  teCompareEmpty.classList.add('hidden');
}

async function runTeStep(fn) {
  if (teBusy) return false;
  teBusy = true;
  updateTeButtons();
  try {
    return await fn();
  } finally {
    teBusy = false;
    updateTeButtons();
    updateSummary();
  }
}

btnTeRunAll?.addEventListener('click', () => runTeStep(async () => {
  [1, 2, 3].forEach((n) => setStep(n, 'idle'));
  return (await runStep1()) && (await runStep2()) && (await runStep3());
}));
teSteps[0].button?.addEventListener('click', () => runTeStep(runStep1));
teSteps[1].button?.addEventListener('click', () => runTeStep(runStep2));
teSteps[2].button?.addEventListener('click', () => runTeStep(runStep3));

btnTeIntrospectAlem?.addEventListener('click', () => {
  const token = getAlemAccessToken();
  if (token) callSecond('POST /api/auth/token-exchange/introspect (токен alem)', '/auth/token-exchange/introspect', postJson({ token }));
});
btnTeIntrospectSecond?.addEventListener('click', () => {
  if (teSecondToken) {
    callSecond('POST /api/auth/token-exchange/introspect (токен second)', '/auth/token-exchange/introspect',
      postJson({ token: teSecondToken }));
  }
});
btnTeCopy?.addEventListener('click', async () => {
  if (!teSecondToken) return;
  try {
    await navigator.clipboard.writeText(teSecondToken);
    btnTeCopy.textContent = 'Скопировано';
    setTimeout(() => { btnTeCopy.textContent = 'Copy'; }, 1500);
  } catch (err) {
    console.warn('Clipboard error:', err);
  }
});

// Run initial precheck on startup
checkUser2FA(inputUsername.value.trim());

// Start app
init();
