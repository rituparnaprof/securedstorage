// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 rituparnaprof
// SecuredStorage - Client Application Logic & UI Controller

// Modern Flat Vector SVGs (Lucide / Feather, MIT/ISC License - GPL-3.0 Compatible)
const SVG_ICON_EYE = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`;
const SVG_ICON_EYE_OFF = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>`;
const SVG_ICON_EDIT = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>`;
const SVG_ICON_DELETE = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/></svg>`;
const SVG_ICON_COPY = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`;
const SVG_ICON_CHECK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;

// 1. HARDENED ANTI-EXFILTRATION: Intercept and block all copy/cut/selection events
document.addEventListener('copy', (e) => e.preventDefault());
document.addEventListener('cut', (e) => e.preventDefault());
document.addEventListener('contextmenu', (e) => e.preventDefault());
document.addEventListener('dragstart', (e) => e.preventDefault());

document.addEventListener('keydown', (e) => {
  const isCtrlOrCmd = e.ctrlKey || e.metaKey;
  const key = e.key.toLowerCase();
  // Block Ctrl/Cmd + C (Copy), X (Cut), A (Select All)
  if (isCtrlOrCmd && ['c', 'x', 'a', 'u', 's'].includes(key)) {
    e.preventDefault();
    return false;
  }
  // Block F12, DevTools shortcuts
  if (e.key === 'F12' || (isCtrlOrCmd && e.shiftKey && ['i', 'j', 'c'].includes(key))) {
    e.preventDefault();
    return false;
  }
});

// Tauri IPC wrapper with dynamic resolution for Tauri v2
function getTauriInvoke() {
  if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
    return window.__TAURI__.core.invoke;
  }
  if (window.__TAURI__ && typeof window.__TAURI__.invoke === 'function') {
    return window.__TAURI__.invoke;
  }
  return null;
}

async function invokeCommand(command, args = {}) {
  const invoke = getTauriInvoke();
  if (typeof invoke === 'function') {
    return await invoke(command, args);
  }
  
  // Standalone browser dev preview fallback only when accessed via standard http server
  if (window.location.protocol === 'http:' && window.location.hostname !== 'tauri.localhost') {
    console.warn(`[SecuredStorage] Running in browser preview for: ${command}`);
    return mockBackendHandler(command, args);
  }

  console.error(`[SecuredStorage] Tauri IPC bridge unavailable for command: ${command}`);
  throw new Error(`Native secure backend connection unavailable (window.__TAURI__ not initialized).`);
}

// In-Memory Dev Mock (Allows testing UI layout in standard browser preview if needed)
let mockVaultCreated = false;
let mockEntries = [];
async function mockBackendHandler(command, args) {
  if (command === 'check_vault_exists') return mockVaultCreated;
  if (command === 'initialize_vault') {
    mockVaultCreated = true;
    mockEntries = [];
    return "SEC-9F2A-8C31-E04D-2B5C-681E-A9F0-713B-4D8E";
  }
  if (command === 'trigger_biometric_scan') {
    // In mock browser preview, simulate user scanning biometrics
    await new Promise(r => setTimeout(r, 1500));
    return true;
  }
  if (command === 'recover_vault') {
    return {
      new_recovery_key: "SEC-B2C3-D4E5-F6A7-8901-2345-6789-0ABC",
      entries: mockEntries.map(e => ({
        id: e.id,
        website: e.website,
        username: '••••••••••••',
        password: '••••••••••••',
        notes: '••••••••••••'
      }))
    };
  }
  if (command === 'unlock_vault_password' || command === 'unlock_vault_biometric') {
    return mockEntries.map(e => ({
      id: e.id,
      website: e.website,
      username: '••••••••••••',
      password: '••••••••••••',
      notes: '••••••••••••'
    }));
  }
  if (command === 'reveal_field') {
    const entry = mockEntries.find(e => e.id === args.entryId);
    return entry ? entry[args.fieldName] : '••••••••••••';
  }
  if (command === 'add_entry') {
    const id = Date.now().toString();
    mockEntries.push({ id, ...args });
    return mockEntries.map(e => ({
      id: e.id,
      website: e.website,
      username: '••••••••••••',
      password: '••••••••••••',
      notes: '••••••••••••'
    }));
  }
  if (command === 'delete_entry') {
    if (!args.masterPassword || args.masterPassword.trim() === '') {
      throw new Error("Master password cannot be empty");
    }
    mockEntries = mockEntries.filter(e => e.id !== args.entryId);
    return mockEntries.map(e => ({
      id: e.id,
      website: e.website,
      username: '••••••••••••',
      password: '••••••••••••',
      notes: '••••••••••••'
    }));
  }
  if (command === 'get_entry_for_edit') {
    if (!args.masterPassword || args.masterPassword.trim() === '') {
      throw new Error("Master password cannot be empty");
    }
    const entry = mockEntries.find(e => e.id === args.entryId);
    if (!entry) throw new Error("Entry not found");
    return entry;
  }
  if (command === 'update_entry') {
    if (!args.masterPassword || args.masterPassword.trim() === '') {
      throw new Error("Master password cannot be empty");
    }
    const idx = mockEntries.findIndex(e => e.id === args.entryId);
    if (idx !== -1) {
      mockEntries[idx] = {
        ...mockEntries[idx],
        website: args.website,
        username: args.username,
        password: args.password,
        notes: args.notes
      };
    }
    return mockEntries.map(e => ({
      id: e.id,
      website: e.website,
      username: '••••••••••••',
      password: '••••••••••••',
      notes: '••••••••••••'
    }));
  }
  if (command === 'copy_credential_field') {
    return 30; // 30 seconds TTL
  }
  if (command === 'clear_clipboard') {
    return true;
  }
  if (command === 'lock_vault') return "LOCKED";
  return null;
}

// State & DOM Elements
let currentEntries = [];
let unmaskTimers = {};
let idleTimer = null;
const IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes inactivity auto-lock

const clipboardToast = document.getElementById('clipboardToast');
const toastMessage = document.getElementById('toastMessage');
const toastClearNowBtn = document.getElementById('toastClearNowBtn');

const initScreen = document.getElementById('initScreen');
const authScreen = document.getElementById('authScreen');
const vaultScreen = document.getElementById('vaultScreen');
const headerActions = document.getElementById('headerActions');
const vaultTableBody = document.getElementById('vaultTableBody');
const emptyVaultMsg = document.getElementById('emptyVaultMsg');
const searchInput = document.getElementById('searchInput');

// Auth Screen Elements
const tabBio = document.getElementById('tabBio');
const tabPassword = document.getElementById('tabPassword');
const tabRecovery = document.getElementById('tabRecovery');
const bioAuthTab = document.getElementById('bioAuthTab');
const passwordAuthTab = document.getElementById('passwordAuthTab');
const recoveryAuthTab = document.getElementById('recoveryAuthTab');

// Biometric Two-Step Elements
const bioStep1 = document.getElementById('bioStep1');
const bioStep2 = document.getElementById('bioStep2');
const btnScanTouchID = document.getElementById('btnScanTouchID');
const btnReScanBio = document.getElementById('btnReScanBio');
const bioPin = document.getElementById('bioPin');
const authPassword = document.getElementById('authPassword');
const btnBioUnlock = document.getElementById('btnBioUnlock');
const btnPasswordUnlock = document.getElementById('btnPasswordUnlock');
const authError = document.getElementById('authError');

// Recovery Elements
const recoveryInputKey = document.getElementById('recoveryInputKey');
const recoveryNewPassword = document.getElementById('recoveryNewPassword');
const recoveryNewPin = document.getElementById('recoveryNewPin');
const btnRecoverVault = document.getElementById('btnRecoverVault');

// Init & Emergency Recovery Key Elements
const initPassword = document.getElementById('initPassword');
const initPin = document.getElementById('initPin');
const btnCreateVault = document.getElementById('btnCreateVault');
const initError = document.getElementById('initError');
const recoveryKeyScreen = document.getElementById('recoveryKeyScreen');
const displayRecoveryKey = document.getElementById('displayRecoveryKey');
const chkSavedRecoveryKey = document.getElementById('chkSavedRecoveryKey');
const btnConfirmRecoveryKey = document.getElementById('btnConfirmRecoveryKey');

// Modal Elements
const addModal = document.getElementById('addModal');
const addEntryBtn = document.getElementById('addEntryBtn');
const closeModalBtn = document.getElementById('closeModalBtn');
const cancelModalBtn = document.getElementById('cancelModalBtn');
const saveCredentialBtn = document.getElementById('saveCredentialBtn');
const btnGeneratePass = document.getElementById('btnGeneratePass');
const modalWebsite = document.getElementById('modalWebsite');
const modalUser = document.getElementById('modalUser');
const modalPass = document.getElementById('modalPass');
const modalNotes = document.getElementById('modalNotes');
const modalError = document.getElementById('modalError');

// Edit Authentication Modal Elements
const editAuthModal = document.getElementById('editAuthModal');
const editAuthPassword = document.getElementById('editAuthPassword');
const editAuthError = document.getElementById('editAuthError');
const confirmEditAuthBtn = document.getElementById('confirmEditAuthBtn');
const cancelEditAuthBtn = document.getElementById('cancelEditAuthBtn');
const closeEditAuthBtn = document.getElementById('closeEditAuthBtn');

// Edit Credential Modal Elements
const editModal = document.getElementById('editModal');
const editEntryId = document.getElementById('editEntryId');
const editWebsite = document.getElementById('editWebsite');
const editUser = document.getElementById('editUser');
const editPass = document.getElementById('editPass');
const btnGenerateEditPass = document.getElementById('btnGenerateEditPass');
const editNotes = document.getElementById('editNotes');
const editModalError = document.getElementById('editModalError');
const saveEditCredentialBtn = document.getElementById('saveEditCredentialBtn');
const cancelEditModalBtn = document.getElementById('cancelEditModalBtn');
const closeEditModalBtn = document.getElementById('closeEditModalBtn');

// Delete Authentication Modal Elements
const deleteAuthModal = document.getElementById('deleteAuthModal');
const deleteTargetSite = document.getElementById('deleteTargetSite');
const deleteAuthPassword = document.getElementById('deleteAuthPassword');
const deleteAuthError = document.getElementById('deleteAuthError');
const confirmDeleteAuthBtn = document.getElementById('confirmDeleteAuthBtn');
const cancelDeleteAuthBtn = document.getElementById('cancelDeleteAuthBtn');
const closeDeleteAuthBtn = document.getElementById('closeDeleteAuthBtn');

const lockVaultBtn = document.getElementById('lockVaultBtn');
const themeToggleBtn = document.getElementById('themeToggleBtn');
const themeIcon = document.getElementById('themeIcon');
const themeText = document.getElementById('themeText');

// Theme Management: Light / Dark Mode with System Preference Fallback
function setupTheme() {
  const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
  let currentTheme = localStorage.getItem('ss_theme') || (prefersLight ? 'light' : 'dark');
  
  applyTheme(currentTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      currentTheme = currentTheme === 'light' ? 'dark' : 'light';
      applyTheme(currentTheme);
      try { localStorage.setItem('ss_theme', currentTheme); } catch(err) {}
    });
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  if (themeIcon && themeText) {
    if (theme === 'light') {
      themeIcon.textContent = '🌙';
      themeText.textContent = 'Dark Mode';
    } else {
      themeIcon.textContent = '☀️';
      themeText.textContent = 'Light Mode';
    }
  }
}

// Initialize application state
async function initApp() {
  setupTheme();
  resetIdleTimer();

  try {
    const exists = await invokeCommand('check_vault_exists');
    if (exists) {
      showScreen('auth');
    } else {
      showScreen('init');
    }
  } catch (err) {
    showScreen('init');
  }
}

function resetBioSteps() {
  if (bioStep1 && bioStep2) {
    bioStep1.classList.remove('hidden');
    bioStep2.classList.add('hidden');
  }
  if (btnScanTouchID) {
    btnScanTouchID.disabled = false;
    btnScanTouchID.innerHTML = '<span>Scan Touch ID / Biometrics</span>';
  }
  if (bioPin) {
    bioPin.value = '';
  }
}

let isScanningBiometric = false;
let biometricCanceledByUser = false;

async function triggerBiometric(isUserInitiated = false) {
  if (isScanningBiometric) return;
  if (authScreen.classList.contains('hidden')) return;
  if (bioAuthTab.classList.contains('hidden')) return;
  if (!bioStep1 || bioStep1.classList.contains('hidden')) return;

  // Polite biometric prompt: if user dismissed/canceled Touch ID, don't auto-prompt again
  if (!isUserInitiated && biometricCanceledByUser) return;

  isScanningBiometric = true;
  hideError(authError);
  if (btnScanTouchID) {
    btnScanTouchID.disabled = true;
    btnScanTouchID.innerHTML = '<span>Scanning Biometric... (touch sensor now)</span>';
  }

  try {
    await invokeCommand('trigger_biometric_scan');
    // Biometric Verified: Immediately transition to Step 2 (enter 6-digit PIN)
    biometricCanceledByUser = false;
    bioStep1.classList.add('hidden');
    bioStep2.classList.remove('hidden');
    bioPin.value = '';
    bioPin.focus();
  } catch (err) {
    const errMsg = err ? err.toString() : '';
    // If canceled by user or not recognized, keep calm and let user decide when to scan
    if (errMsg.toLowerCase().includes('cancel') || errMsg.toLowerCase().includes('not recognized')) {
      biometricCanceledByUser = true;
      showError(authError, 'Touch ID canceled. Click below to try again or switch to Master Password.');
    } else {
      showError(authError, errMsg);
    }
    resetBioSteps();
  } finally {
    isScanningBiometric = false;
  }
}

function switchTab(target) {
  tabBio.classList.remove('active');
  tabPassword.classList.remove('active');
  if (tabRecovery) tabRecovery.classList.remove('active');

  bioAuthTab.classList.add('hidden');
  passwordAuthTab.classList.add('hidden');
  if (recoveryAuthTab) recoveryAuthTab.classList.add('hidden');
  hideError(authError);

  if (target === 'bio') {
    tabBio.classList.add('active');
    bioAuthTab.classList.remove('hidden');
    resetBioSteps();
    // Auto-trigger biometric prompt politely if not canceled
    setTimeout(() => {
      triggerBiometric(false);
    }, 250);
  } else if (target === 'password') {
    tabPassword.classList.add('active');
    passwordAuthTab.classList.remove('hidden');
    if (authPassword) authPassword.focus();
  } else if (target === 'recovery') {
    if (tabRecovery) tabRecovery.classList.add('active');
    if (recoveryAuthTab) recoveryAuthTab.classList.remove('hidden');
    if (recoveryInputKey) recoveryInputKey.focus();
  }
}

function showScreen(name) {
  initScreen.classList.add('hidden');
  if (recoveryKeyScreen) recoveryKeyScreen.classList.add('hidden');
  authScreen.classList.add('hidden');
  vaultScreen.classList.add('hidden');
  headerActions.classList.add('hidden');

  if (name === 'init') {
    initScreen.classList.remove('hidden');
  } else if (name === 'recoveryKey') {
    if (recoveryKeyScreen) recoveryKeyScreen.classList.remove('hidden');
  } else if (name === 'auth') {
    authScreen.classList.remove('hidden');
    bioPin.value = '';
    authPassword.value = '';
    hideError(authError);
    switchTab('bio');
  } else if (name === 'vault') {
    vaultScreen.classList.remove('hidden');
    headerActions.classList.remove('hidden');
  }
}

// Inactivity Auto-Lock (5 minutes of idle time)
function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (!vaultScreen.classList.contains('hidden')) {
      handleLockVault();
    }
  }, IDLE_TIMEOUT_MS);
}

['mousemove', 'mousedown', 'keydown', 'touchstart'].forEach(evt => {
  window.addEventListener(evt, resetIdleTimer, { passive: true });
});

// Tab Navigation Event Listeners
tabBio.addEventListener('click', () => {
  // If user explicitly clicked the Biometric tab, allow scanning even if previously canceled
  biometricCanceledByUser = false;
  switchTab('bio');
});
tabPassword.addEventListener('click', () => switchTab('password'));
if (tabRecovery) tabRecovery.addEventListener('click', () => switchTab('recovery'));

// Step 1: Scan Touch ID / Biometrics button listener
if (btnScanTouchID) {
  btnScanTouchID.addEventListener('click', () => triggerBiometric(true));
}

if (btnReScanBio) {
  btnReScanBio.addEventListener('click', () => {
    resetBioSteps();
    hideError(authError);
    triggerBiometric(true);
  });
}

// Step 2: Unlock with 6-Digit PIN
btnBioUnlock.addEventListener('click', async () => {
  const pin = bioPin.value;
  if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin)) {
    showError(authError, 'Please enter your 6-digit numeric PIN.');
    bioPin.focus();
    return;
  }

  btnBioUnlock.disabled = true;
  btnBioUnlock.textContent = 'Decrypting...';

  try {
    const entries = await invokeCommand('unlock_vault_biometric', { pin });
    currentEntries = entries;
    renderVaultTable(entries);
    showScreen('vault');
  } catch (err) {
    showError(authError, err.toString());
    bioPin.value = '';
    bioPin.focus();
  } finally {
    btnBioUnlock.disabled = false;
    btnBioUnlock.textContent = 'Decrypt & Unlock Vault';
  }
});

// Auto-submit PIN when 6 digits are typed
bioPin.addEventListener('input', () => {
  if (bioPin.value.length === 6 && /^\d{6}$/.test(bioPin.value)) {
    btnBioUnlock.click();
  }
});

// Create Vault: Generates Emergency Paper Recovery Key (Slot 3)
btnCreateVault.addEventListener('click', async () => {
  const password = initPassword.value;
  const pin = initPin.value;

  if (!password || password.length < 8) {
    showError(initError, 'Master Password must be at least 8 characters long.');
    return;
  }
  if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin)) {
    showError(initError, 'Hardware PIN must be exactly 6 numeric digits (000000–999999).');
    return;
  }

  btnCreateVault.disabled = true;
  btnCreateVault.textContent = 'Deriving Keys & Encrypting...';

  try {
    const recoveryKey = await invokeCommand('initialize_vault', { masterPassword: password, pin });
    initPassword.value = '';
    initPin.value = '';
    hideError(initError);

    // Display Emergency Recovery Key
    displayRecoveryKey.textContent = recoveryKey;
    chkSavedRecoveryKey.checked = false;
    btnConfirmRecoveryKey.disabled = true;
    showScreen('recoveryKey');
  } catch (err) {
    showError(initError, err.toString());
  } finally {
    btnCreateVault.disabled = false;
    btnCreateVault.textContent = 'Encrypt & Create Vault';
  }
});

if (chkSavedRecoveryKey) {
  chkSavedRecoveryKey.addEventListener('change', () => {
    btnConfirmRecoveryKey.disabled = !chkSavedRecoveryKey.checked;
  });
}

if (btnConfirmRecoveryKey) {
  btnConfirmRecoveryKey.addEventListener('click', () => {
    currentEntries = [];
    renderVaultTable([]);
    showScreen('vault');
  });
}

// Recover Vault using Emergency Paper Recovery Key
if (btnRecoverVault) {
  btnRecoverVault.addEventListener('click', async () => {
    const recoveryKey = (recoveryInputKey.value || '').trim();
    const newPassword = recoveryNewPassword.value;
    const newPin = recoveryNewPin.value;

    if (!recoveryKey || recoveryKey.length < 16) {
      showError(authError, 'Please enter your complete Emergency Paper Recovery Key.');
      return;
    }
    if (!newPassword || newPassword.length < 8) {
      showError(authError, 'New Master Password must be at least 8 characters long.');
      return;
    }
    if (!newPin || newPin.length !== 6 || !/^\d{6}$/.test(newPin)) {
      showError(authError, 'New PIN must be exactly 6 numeric digits (000000–999999).');
      return;
    }

    btnRecoverVault.disabled = true;
    btnRecoverVault.textContent = 'Recovering & Rotating Keys...';

    try {
      const res = await invokeCommand('recover_vault', {
        recoveryKey,
        newPassword,
        newPin
      });

      recoveryInputKey.value = '';
      recoveryNewPassword.value = '';
      recoveryNewPin.value = '';

      // Present the rotated new recovery key
      displayRecoveryKey.textContent = res.new_recovery_key;
      chkSavedRecoveryKey.checked = false;
      btnConfirmRecoveryKey.disabled = true;
      currentEntries = res.entries;

      btnConfirmRecoveryKey.onclick = () => {
        renderVaultTable(currentEntries);
        showScreen('vault');
      };

      showScreen('recoveryKey');
    } catch (err) {
      showError(authError, err.toString());
    } finally {
      btnRecoverVault.disabled = false;
      btnRecoverVault.textContent = 'Recover Vault & Reset Credentials';
    }
  });
}

// Unlock with Master Password
btnPasswordUnlock.addEventListener('click', async () => {
  const password = authPassword.value;
  if (!password) {
    showError(authError, 'Please enter your Master Password.');
    return;
  }

  btnPasswordUnlock.disabled = true;
  btnPasswordUnlock.textContent = 'Verifying Password...';

  try {
    const entries = await invokeCommand('unlock_vault_password', { password });
    currentEntries = entries;
    renderVaultTable(entries);
    showScreen('vault');
  } catch (err) {
    showError(authError, err.toString());
  } finally {
    btnPasswordUnlock.disabled = false;
    btnPasswordUnlock.textContent = 'Unlock with Password';
  }
});

// Ephemeral Clipboard Countdown & Management
let clipboardCountdownTimer = null;
let clipboardRemainingSeconds = 0;

function showClipboardToast(fieldName, ttlSeconds = 30) {
  if (clipboardCountdownTimer) {
    clearInterval(clipboardCountdownTimer);
    clipboardCountdownTimer = null;
  }

  clipboardRemainingSeconds = ttlSeconds;
  const label = fieldName === 'password' ? 'Password' : 'Username';
  if (toastMessage) {
    toastMessage.textContent = `${label} copied to clipboard. Auto-clearing in ${clipboardRemainingSeconds}s.`;
  }
  if (clipboardToast) {
    clipboardToast.classList.remove('hidden');
  }

  clipboardCountdownTimer = setInterval(() => {
    clipboardRemainingSeconds--;
    if (clipboardRemainingSeconds <= 0) {
      clearInterval(clipboardCountdownTimer);
      clipboardCountdownTimer = null;
      if (toastMessage) toastMessage.textContent = 'Clipboard auto-cleared securely.';
      setTimeout(() => {
        if (clipboardToast) clipboardToast.classList.add('hidden');
      }, 2500);
    } else {
      if (toastMessage) {
        toastMessage.textContent = `${label} copied to clipboard. Auto-clearing in ${clipboardRemainingSeconds}s.`;
      }
    }
  }, 1000);
}

async function handleClearClipboardNow() {
  if (clipboardCountdownTimer) {
    clearInterval(clipboardCountdownTimer);
    clipboardCountdownTimer = null;
  }
  try {
    await invokeCommand('clear_clipboard');
  } catch (e) {
    console.error('[SecuredStorage] Failed to clear clipboard:', e);
  }
  if (toastMessage) toastMessage.textContent = 'Clipboard cleared securely.';
  setTimeout(() => {
    if (clipboardToast) clipboardToast.classList.add('hidden');
  }, 1800);
}

if (toastClearNowBtn) {
  toastClearNowBtn.addEventListener('click', handleClearClipboardNow);
}

async function handleCopyCredentialField(entryId, fieldName, btnEl) {
  try {
    const ttl = await invokeCommand('copy_credential_field', { entryId, fieldName });
    // Visual button feedback
    btnEl.innerHTML = SVG_ICON_CHECK;
    btnEl.classList.add('copied');
    setTimeout(() => {
      btnEl.innerHTML = SVG_ICON_COPY;
      btnEl.classList.remove('copied');
    }, 1500);

    showClipboardToast(fieldName, ttl || 30);
  } catch (err) {
    console.error('[SecuredStorage] Copy failed:', err);
  }
}

// Lock Vault
async function handleLockVault() {
  clearAllUnmaskTimers();
  handleClearClipboardNow();
  biometricCanceledByUser = false;
  try {
    await invokeCommand('lock_vault');
  } catch (e) {}
  currentEntries = [];
  renderVaultTable([]);
  showScreen('auth');
}
lockVaultBtn.addEventListener('click', handleLockVault);

// Render Vault Table: STRICT MASKING (Site is visible; all other fields are ••••••••••••)
function renderVaultTable(entries) {
  vaultTableBody.innerHTML = '';
  const filter = (searchInput.value || '').toLowerCase().trim();

  const filtered = entries.filter(e => {
    return !filter || (e.website && e.website.toLowerCase().includes(filter));
  });

  if (filtered.length === 0) {
    emptyVaultMsg.classList.remove('hidden');
    return;
  }
  emptyVaultMsg.classList.add('hidden');

  filtered.forEach(entry => {
    const tr = document.createElement('tr');
    tr.id = `row-${entry.id}`;
    tr.className = 'vault-row';

    // Site (Plaintext visible)
    const tdWeb = document.createElement('td');
    tdWeb.className = 'website-cell';
    tdWeb.textContent = entry.website || '(No Site)';
    tr.appendChild(tdWeb);

    // Username (Masked with Copy button)
    const tdUser = document.createElement('td');
    const userWrapper = document.createElement('div');
    userWrapper.className = 'cell-content-wrapper';

    const spanUser = document.createElement('span');
    spanUser.id = `cell-user-${entry.id}`;
    spanUser.className = 'masked-text';
    spanUser.textContent = '••••••••••••';

    const btnCopyUser = document.createElement('button');
    btnCopyUser.className = 'btn-cell-copy';
    btnCopyUser.title = 'Copy Username to Clipboard (Auto-clearing in 30s)';
    btnCopyUser.innerHTML = SVG_ICON_COPY;
    btnCopyUser.addEventListener('click', (e) => {
      e.stopPropagation();
      handleCopyCredentialField(entry.id, 'username', btnCopyUser);
    });

    userWrapper.appendChild(spanUser);
    userWrapper.appendChild(btnCopyUser);
    tdUser.appendChild(userWrapper);
    tr.appendChild(tdUser);

    // Password (Masked with Copy button)
    const tdPass = document.createElement('td');
    const passWrapper = document.createElement('div');
    passWrapper.className = 'cell-content-wrapper';

    const spanPass = document.createElement('span');
    spanPass.id = `cell-pass-${entry.id}`;
    spanPass.className = 'masked-text';
    spanPass.textContent = '••••••••••••';

    const btnCopyPass = document.createElement('button');
    btnCopyPass.className = 'btn-cell-copy';
    btnCopyPass.title = 'Copy Password to Clipboard (Auto-clearing in 30s)';
    btnCopyPass.innerHTML = SVG_ICON_COPY;
    btnCopyPass.addEventListener('click', (e) => {
      e.stopPropagation();
      handleCopyCredentialField(entry.id, 'password', btnCopyPass);
    });

    passWrapper.appendChild(spanPass);
    passWrapper.appendChild(btnCopyPass);
    tdPass.appendChild(passWrapper);
    tr.appendChild(tdPass);

    // Notes (Masked)
    const tdNotes = document.createElement('td');
    const spanNotes = document.createElement('span');
    spanNotes.id = `cell-notes-${entry.id}`;
    spanNotes.className = 'masked-text';
    spanNotes.textContent = '••••••••••••';
    tdNotes.appendChild(spanNotes);
    tr.appendChild(tdNotes);

    // Actions: View (Reveal), Edit (Master Password Gated), and Delete
    const tdActions = document.createElement('td');
    tdActions.className = 'actions-cell';

    const actionsWrapper = document.createElement('div');
    actionsWrapper.className = 'actions-wrapper';
    
    // 1. View / Reveal Button
    const revealBtn = document.createElement('button');
    revealBtn.id = `btn-reveal-${entry.id}`;
    revealBtn.className = 'btn-icon-action view';
    revealBtn.title = 'Reveal fields for 10 seconds';
    revealBtn.innerHTML = SVG_ICON_EYE;
    revealBtn.addEventListener('click', () => handleEphemeralReveal(entry.id));

    // 2. Edit Button (Requires Master Password)
    const editBtn = document.createElement('button');
    editBtn.id = `btn-edit-${entry.id}`;
    editBtn.className = 'btn-icon-action edit';
    editBtn.title = 'Edit Credential (Master Password required)';
    editBtn.innerHTML = SVG_ICON_EDIT;
    editBtn.addEventListener('click', () => handleEditEntry(entry.id));

    // 3. Delete Button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn-icon-action delete';
    deleteBtn.title = 'Delete Credential (Master Password required)';
    deleteBtn.innerHTML = SVG_ICON_DELETE;
    deleteBtn.addEventListener('click', () => handleDeleteEntry(entry.id));

    actionsWrapper.appendChild(revealBtn);
    actionsWrapper.appendChild(editBtn);
    actionsWrapper.appendChild(deleteBtn);
    tdActions.appendChild(actionsWrapper);
    tr.appendChild(tdActions);

    vaultTableBody.appendChild(tr);
  });
}

// Search Filter
searchInput.addEventListener('input', () => {
  renderVaultTable(currentEntries);
});

// Ephemeral Reveal: Unmasks Username, Password, Notes for 10 seconds only
async function handleEphemeralReveal(entryId) {
  if (unmaskTimers[entryId]) {
    clearTimeout(unmaskTimers[entryId]);
    remaskRow(entryId);
    delete unmaskTimers[entryId];
    return;
  }

  try {
    const [userVal, passVal, notesVal] = await Promise.all([
      invokeCommand('reveal_field', { entryId, fieldName: 'username' }),
      invokeCommand('reveal_field', { entryId, fieldName: 'password' }),
      invokeCommand('reveal_field', { entryId, fieldName: 'notes' })
    ]);

    const cellUser = document.getElementById(`cell-user-${entryId}`);
    const cellPass = document.getElementById(`cell-pass-${entryId}`);
    const cellNotes = document.getElementById(`cell-notes-${entryId}`);
    const revealBtn = document.getElementById(`btn-reveal-${entryId}`);

    if (cellUser) { cellUser.textContent = userVal; cellUser.className = 'unmasked-badge'; }
    if (cellPass) { cellPass.textContent = passVal; cellPass.className = 'unmasked-badge'; }
    if (cellNotes) { cellNotes.textContent = notesVal || '(None)'; cellNotes.className = 'unmasked-badge'; }
    if (revealBtn) {
      revealBtn.innerHTML = SVG_ICON_EYE_OFF;
      revealBtn.title = 'Hide fields';
      revealBtn.classList.add('active-reveal');
    }

    // Start 10-second auto-remask timer
    unmaskTimers[entryId] = setTimeout(() => {
      remaskRow(entryId);
      delete unmaskTimers[entryId];
    }, 10000);

  } catch (err) {
    console.error('Failed to reveal entry:', err);
  }
}

function remaskRow(entryId) {
  const cellUser = document.getElementById(`cell-user-${entryId}`);
  const cellPass = document.getElementById(`cell-pass-${entryId}`);
  const cellNotes = document.getElementById(`cell-notes-${entryId}`);
  const revealBtn = document.getElementById(`btn-reveal-${entryId}`);

  if (cellUser) { cellUser.textContent = '••••••••••••'; cellUser.className = 'masked-text'; }
  if (cellPass) { cellPass.textContent = '••••••••••••'; cellPass.className = 'masked-text'; }
  if (cellNotes) { cellNotes.textContent = '••••••••••••'; cellNotes.className = 'masked-text'; }
  if (revealBtn) {
    revealBtn.innerHTML = SVG_ICON_EYE;
    revealBtn.title = 'Reveal fields for 10 seconds';
    revealBtn.classList.remove('active-reveal');
  }
}

function clearAllUnmaskTimers() {
  Object.keys(unmaskTimers).forEach(id => {
    clearTimeout(unmaskTimers[id]);
    remaskRow(id);
  });
  unmaskTimers = {};
}

// Add Credential Modal
addEntryBtn.addEventListener('click', () => {
  modalWebsite.value = '';
  modalUser.value = '';
  modalPass.value = '';
  modalNotes.value = '';
  hideError(modalError);
  addModal.classList.remove('hidden');
});

closeModalBtn.addEventListener('click', () => addModal.classList.add('hidden'));
cancelModalBtn.addEventListener('click', () => addModal.classList.add('hidden'));

// Password Generator
btnGeneratePass.addEventListener('click', () => {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_+=';
  let pass = '';
  const cryptoObj = window.crypto;
  const values = new Uint32Array(20);
  cryptoObj.getRandomValues(values);
  for (let i = 0; i < 20; i++) {
    pass += chars[values[i] % chars.length];
  }
  modalPass.value = pass;
});

// Save Credential
saveCredentialBtn.addEventListener('click', async () => {
  const website = modalWebsite.value.trim();
  const username = modalUser.value.trim();
  const password = modalPass.value;
  const notes = modalNotes.value.trim();

  if (!website) {
    showError(modalError, 'Site is required.');
    return;
  }
  if (!password) {
    showError(modalError, 'Password is required.');
    return;
  }

  try {
    const updated = await invokeCommand('add_entry', {
      application: '',
      website,
      username,
      password,
      notes
    });
    currentEntries = updated;
    renderVaultTable(updated);
    addModal.classList.add('hidden');
  } catch (err) {
    showError(modalError, err.toString());
  }
});

// -----------------------------------------------------------------------------
// DELETE CREDENTIAL WORKFLOW (MASTER PASSWORD GATEKEEPER)
// -----------------------------------------------------------------------------
let targetDeleteEntryId = null;

function handleDeleteEntry(entryId) {
  targetDeleteEntryId = entryId;
  const entry = currentEntries.find(e => e.id === entryId);
  const siteName = entry ? (entry.website || 'this credential') : 'this credential';
  if (deleteTargetSite) deleteTargetSite.textContent = siteName;
  if (deleteAuthPassword) deleteAuthPassword.value = '';
  hideError(deleteAuthError);
  if (deleteAuthModal) {
    deleteAuthModal.classList.remove('hidden');
    setTimeout(() => {
      if (deleteAuthPassword) deleteAuthPassword.focus();
    }, 50);
  }
}

async function confirmDeleteAuth() {
  const masterPassword = deleteAuthPassword.value;
  if (!masterPassword) {
    showError(deleteAuthError, 'Master Password is required.');
    return;
  }

  if (confirmDeleteAuthBtn) {
    confirmDeleteAuthBtn.disabled = true;
    confirmDeleteAuthBtn.textContent = 'Verifying & Deleting...';
  }

  try {
    const updated = await invokeCommand('delete_entry', {
      entryId: targetDeleteEntryId,
      masterPassword
    });
    currentEntries = updated;
    renderVaultTable(updated);
    if (deleteAuthModal) deleteAuthModal.classList.add('hidden');
    targetDeleteEntryId = null;
    if (deleteAuthPassword) deleteAuthPassword.value = '';
  } catch (err) {
    showError(deleteAuthError, 'Verification failed: ' + err.toString());
  } finally {
    if (confirmDeleteAuthBtn) {
      confirmDeleteAuthBtn.disabled = false;
      confirmDeleteAuthBtn.textContent = 'Delete Credential';
    }
  }
}


// -----------------------------------------------------------------------------
// EDIT CREDENTIAL WORKFLOW (MASTER PASSWORD GATEKEEPER)
// -----------------------------------------------------------------------------
let targetEditEntryId = null;
let currentEditMasterPassword = null;

// Open Master Password Verification Dialog before editing
function handleEditEntry(entryId) {
  targetEditEntryId = entryId;
  currentEditMasterPassword = null;
  editAuthPassword.value = '';
  hideError(editAuthError);
  editAuthModal.classList.remove('hidden');
  setTimeout(() => editAuthPassword.focus(), 50);
}

// Confirm Master Password and transition to Edit Form
async function confirmEditAuth() {
  const masterPassword = editAuthPassword.value;
  if (!masterPassword) {
    showError(editAuthError, 'Master Password is required.');
    return;
  }

  try {
    const entry = await invokeCommand('get_entry_for_edit', {
      entryId: targetEditEntryId,
      masterPassword
    });

    currentEditMasterPassword = masterPassword;
    editAuthModal.classList.add('hidden');

    // Populate Edit Modal with current values
    editEntryId.value = entry.id;
    editWebsite.value = entry.website || '';
    editUser.value = entry.username || '';
    editPass.value = entry.password || '';
    editNotes.value = entry.notes || '';
    hideError(editModalError);

    editModal.classList.remove('hidden');
    setTimeout(() => editWebsite.focus(), 50);
  } catch (err) {
    showError(editAuthError, 'Verification failed: ' + err.toString());
  }
}

// Save Updated Credential
async function saveEditedEntry() {
  const entryId = editEntryId.value;
  const website = editWebsite.value.trim();
  const username = editUser.value.trim();
  const password = editPass.value;
  const notes = editNotes.value.trim();

  if (!website) {
    showError(editModalError, 'Site is required.');
    return;
  }
  if (!password) {
    showError(editModalError, 'Password is required.');
    return;
  }

  try {
    const updated = await invokeCommand('update_entry', {
      entryId,
      website,
      username,
      password,
      notes,
      masterPassword: currentEditMasterPassword
    });

    currentEntries = updated;
    renderVaultTable(updated);
    editModal.classList.add('hidden');
    currentEditMasterPassword = null;
    targetEditEntryId = null;
  } catch (err) {
    showError(editModalError, 'Update failed: ' + err.toString());
  }
}

// Edit Modal Event Listeners
if (closeEditAuthBtn) closeEditAuthBtn.addEventListener('click', () => editAuthModal.classList.add('hidden'));
if (cancelEditAuthBtn) cancelEditAuthBtn.addEventListener('click', () => editAuthModal.classList.add('hidden'));
if (confirmEditAuthBtn) confirmEditAuthBtn.addEventListener('click', confirmEditAuth);
if (editAuthPassword) {
  editAuthPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmEditAuth();
  });
}

if (closeEditModalBtn) closeEditModalBtn.addEventListener('click', () => editModal.classList.add('hidden'));
if (cancelEditModalBtn) cancelEditModalBtn.addEventListener('click', () => editModal.classList.add('hidden'));
if (saveEditCredentialBtn) saveEditCredentialBtn.addEventListener('click', saveEditedEntry);

if (btnGenerateEditPass) {
  btnGenerateEditPass.addEventListener('click', () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let pass = '';
    const array = new Uint32Array(20);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < 20; i++) {
      pass += chars[array[i] % chars.length];
    }
    editPass.value = pass;
  });
}

// Delete Modal Event Listeners
if (closeDeleteAuthBtn) closeDeleteAuthBtn.addEventListener('click', () => deleteAuthModal.classList.add('hidden'));
if (cancelDeleteAuthBtn) cancelDeleteAuthBtn.addEventListener('click', () => deleteAuthModal.classList.add('hidden'));
if (confirmDeleteAuthBtn) confirmDeleteAuthBtn.addEventListener('click', confirmDeleteAuth);
if (deleteAuthPassword) {
  deleteAuthPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmDeleteAuth();
  });
}

// Global Modal Escape key listener
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (addModal && !addModal.classList.contains('hidden')) addModal.classList.add('hidden');
    if (editAuthModal && !editAuthModal.classList.contains('hidden')) editAuthModal.classList.add('hidden');
    if (editModal && !editModal.classList.contains('hidden')) editModal.classList.add('hidden');
    if (deleteAuthModal && !deleteAuthModal.classList.contains('hidden')) deleteAuthModal.classList.add('hidden');
  }
});

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideError(el) {
  el.textContent = '';
  el.classList.add('hidden');
}

// Start on DOM ready
document.addEventListener('DOMContentLoaded', initApp);
