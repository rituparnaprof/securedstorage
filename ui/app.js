/*
 * SecuredStorage - PQC-Compliant Offline Password Vault
 * Copyright (C) 2026 Rituparna Ghosh
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// SecuredStorage - Client UI State Controller & Anti-Exfiltration Event Traps

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

// Tauri IPC wrapper with fallback detection for latest Tauri v2
const tauriInvoke = (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function')
  ? window.__TAURI__.core.invoke
  : (window.__TAURI__ && typeof window.__TAURI__.invoke === 'function')
    ? window.__TAURI__.invoke
    : null;

async function invokeCommand(command, args = {}) {
  if (typeof tauriInvoke === 'function') {
    return await tauriInvoke(command, args);
  }
  // If running in development browser preview without Tauri backend
  console.warn(`[SecuredStorage] Running in standalone webview preview for: ${command}`);
  return mockBackendHandler(command, args);
}

// In-Memory Dev Mock (Allows testing UI in standard browser preview if needed)
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
    return true;
  }
  if (command === 'recover_vault') {
    return {
      new_recovery_key: "SEC-B2C3-D4E5-F6A7-8901-2345-6789-0ABC",
      entries: mockEntries.map(e => ({
        id: e.id,
        website: e.website,
        application: '••••••••••••',
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
      application: '••••••••••••',
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
      application: '••••••••••••',
      username: '••••••••••••',
      password: '••••••••••••',
      notes: '••••••••••••'
    }));
  }
  if (command === 'delete_entry') {
    mockEntries = mockEntries.filter(e => e.id !== args.entryId);
    return mockEntries.map(e => ({
      id: e.id,
      website: e.website,
      application: '••••••••••••',
      username: '••••••••••••',
      password: '••••••••••••',
      notes: '••••••••••••'
    }));
  }
  if (command === 'lock_vault') return "LOCKED";
  return null;
}

// State & DOM Elements
let currentEntries = [];
let unmaskTimers = {};
let idleTimer = null;
const IDLE_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes auto-lock

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
  setupEventListeners();

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

async function autoTriggerBiometric() {
  if (isScanningBiometric) return;
  if (authScreen.classList.contains('hidden')) return;
  if (bioAuthTab.classList.contains('hidden')) return;
  if (!bioStep1 || bioStep1.classList.contains('hidden')) return;

  isScanningBiometric = true;
  hideError(authError);
  if (btnScanTouchID) {
    btnScanTouchID.disabled = true;
    btnScanTouchID.innerHTML = '<span>Scanning Biometric... (touch sensor now)</span>';
  }

  try {
    await invokeCommand('trigger_biometric_scan');
    // Biometric Verified: Immediately transition to Step 2 (enter 6-digit PIN)
    bioStep1.classList.add('hidden');
    bioStep2.classList.remove('hidden');
    bioPin.value = '';
    bioPin.focus();
  } catch (err) {
    showError(authError, err.toString());
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
    // Auto-trigger native biometrics (Touch ID / Hello / PAM) immediately!
    setTimeout(() => {
      autoTriggerBiometric();
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

// Inactivity Auto-Lock
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

// Auto-lock on window blur / minimization
window.addEventListener('blur', () => {
  if (!vaultScreen.classList.contains('hidden')) {
    handleLockVault();
  }
});

// Tab Navigation Event Listeners
tabBio.addEventListener('click', () => switchTab('bio'));
tabPassword.addEventListener('click', () => switchTab('password'));
if (tabRecovery) tabRecovery.addEventListener('click', () => switchTab('recovery'));

// Step 1: Scan Touch ID / Biometrics button listener
if (btnScanTouchID) {
  btnScanTouchID.addEventListener('click', autoTriggerBiometric);
}

if (btnReScanBio) {
  btnReScanBio.addEventListener('click', () => {
    resetBioSteps();
    hideError(authError);
    autoTriggerBiometric();
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

// Lock Vault
async function handleLockVault() {
  clearAllUnmaskTimers();
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

    // Site (Plaintext visible)
    const tdWeb = document.createElement('td');
    tdWeb.className = 'website-cell';
    tdWeb.textContent = entry.website || '(No Site)';
    tr.appendChild(tdWeb);

    // Username (Masked)
    const tdUser = document.createElement('td');
    tdUser.id = `cell-user-${entry.id}`;
    tdUser.className = 'masked-cell';
    tdUser.textContent = '••••••••••••';
    tr.appendChild(tdUser);

    // Password (Masked)
    const tdPass = document.createElement('td');
    tdPass.id = `cell-pass-${entry.id}`;
    tdPass.className = 'masked-cell';
    tdPass.textContent = '••••••••••••';
    tr.appendChild(tdPass);

    // Notes (Masked)
    const tdNotes = document.createElement('td');
    tdNotes.id = `cell-notes-${entry.id}`;
    tdNotes.className = 'masked-cell';
    tdNotes.textContent = '••••••••••••';
    tr.appendChild(tdNotes);

    // Actions: Ephemeral Reveal & Delete
    const tdActions = document.createElement('td');
    
    const revealBtn = document.createElement('button');
    revealBtn.className = 'btn-icon';
    revealBtn.title = 'Reveal fields for 10 seconds';
    revealBtn.textContent = '👁️ Reveal';
    revealBtn.addEventListener('click', () => handleEphemeralReveal(entry.id));

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn-icon delete';
    deleteBtn.title = 'Delete Credential';
    deleteBtn.textContent = '🗑️';
    deleteBtn.style.marginLeft = '6px';
    deleteBtn.addEventListener('click', () => handleDeleteEntry(entry.id));

    tdActions.appendChild(revealBtn);
    tdActions.appendChild(deleteBtn);
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

    if (cellUser) { cellUser.textContent = userVal; cellUser.className = 'unmasked-cell'; }
    if (cellPass) { cellPass.textContent = passVal; cellPass.className = 'unmasked-cell'; }
    if (cellNotes) { cellNotes.textContent = notesVal || '(None)'; cellNotes.className = 'unmasked-cell'; }

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

  if (cellUser) { cellUser.textContent = '••••••••••••'; cellUser.className = 'masked-cell'; }
  if (cellPass) { cellPass.textContent = '••••••••••••'; cellPass.className = 'masked-cell'; }
  if (cellNotes) { cellNotes.textContent = '••••••••••••'; cellNotes.className = 'masked-cell'; }
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
  const cryptoObj = window.crypto || window.msCrypto;
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

// Delete Credential
async function handleDeleteEntry(entryId) {
  if (!confirm('Are you sure you want to permanently delete this credential?')) return;
  try {
    const updated = await invokeCommand('delete_entry', { entryId });
    currentEntries = updated;
    renderVaultTable(updated);
  } catch (err) {
    alert('Failed to delete entry: ' + err);
  }
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideError(el) {
  el.textContent = '';
  el.classList.add('hidden');
}

function setupEventListeners() {}

// Start on DOM ready
document.addEventListener('DOMContentLoaded', initApp);
