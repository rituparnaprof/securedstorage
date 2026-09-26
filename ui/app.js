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

// Tauri IPC wrapper with fallback detection
const tauri = window.__TAURI__ ? window.__TAURI__.core : null;

async function invokeCommand(command, args = {}) {
  if (tauri && typeof tauri.invoke === 'function') {
    return await tauri.invoke(command, args);
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
    return "OK";
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
const bioAuthTab = document.getElementById('bioAuthTab');
const passwordAuthTab = document.getElementById('passwordAuthTab');
const bioPin = document.getElementById('bioPin');
const authPassword = document.getElementById('authPassword');
const btnBioUnlock = document.getElementById('btnBioUnlock');
const btnPasswordUnlock = document.getElementById('btnPasswordUnlock');
const authError = document.getElementById('authError');

// Init Screen Elements
const initPassword = document.getElementById('initPassword');
const initPin = document.getElementById('initPin');
const btnCreateVault = document.getElementById('btnCreateVault');
const initError = document.getElementById('initError');

// Modal Elements
const addModal = document.getElementById('addModal');
const addEntryBtn = document.getElementById('addEntryBtn');
const closeModalBtn = document.getElementById('closeModalBtn');
const cancelModalBtn = document.getElementById('cancelModalBtn');
const saveCredentialBtn = document.getElementById('saveCredentialBtn');
const btnGeneratePass = document.getElementById('btnGeneratePass');
const modalApp = document.getElementById('modalApp');
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

function showScreen(name) {
  initScreen.classList.add('hidden');
  authScreen.classList.add('hidden');
  vaultScreen.classList.add('hidden');
  headerActions.classList.add('hidden');

  if (name === 'init') {
    initScreen.classList.remove('hidden');
  } else if (name === 'auth') {
    authScreen.classList.remove('hidden');
    bioPin.value = '';
    authPassword.value = '';
    hideError(authError);
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

// Tab Navigation
tabBio.addEventListener('click', () => {
  tabBio.classList.add('active');
  tabPassword.classList.remove('active');
  bioAuthTab.classList.remove('hidden');
  passwordAuthTab.classList.add('hidden');
  hideError(authError);
});

tabPassword.addEventListener('click', () => {
  tabPassword.classList.add('active');
  tabBio.classList.remove('active');
  passwordAuthTab.classList.remove('hidden');
  bioAuthTab.classList.add('hidden');
  hideError(authError);
});

// Create Vault
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

  try {
    await invokeCommand('initialize_vault', { masterPassword: password, pin });
    initPassword.value = '';
    initPin.value = '';
    currentEntries = [];
    renderVaultTable([]);
    showScreen('vault');
  } catch (err) {
    showError(initError, err.toString());
  }
});

// Unlock with Biometric + 6-Digit PIN
btnBioUnlock.addEventListener('click', async () => {
  const pin = bioPin.value;
  if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin)) {
    showError(authError, 'Please enter your 6-digit numeric PIN.');
    return;
  }

  try {
    const entries = await invokeCommand('unlock_vault_biometric', { pin });
    currentEntries = entries;
    renderVaultTable(entries);
    showScreen('vault');
  } catch (err) {
    showError(authError, err.toString());
  }
});

// Unlock with Master Password
btnPasswordUnlock.addEventListener('click', async () => {
  const password = authPassword.value;
  if (!password) {
    showError(authError, 'Please enter your Master Password.');
    return;
  }

  try {
    const entries = await invokeCommand('unlock_vault_password', { password });
    currentEntries = entries;
    renderVaultTable(entries);
    showScreen('vault');
  } catch (err) {
    showError(authError, err.toString());
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

// Render Vault Table: STRICT MASKING (Website is visible; all other fields are ••••••••••••)
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

    // Website (Plaintext visible)
    const tdWeb = document.createElement('td');
    tdWeb.className = 'website-cell';
    tdWeb.textContent = entry.website || '(No Website)';
    tr.appendChild(tdWeb);

    // Application (Masked)
    const tdApp = document.createElement('td');
    tdApp.id = `cell-app-${entry.id}`;
    tdApp.className = 'masked-cell';
    tdApp.textContent = '••••••••••••';
    tr.appendChild(tdApp);

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

// Ephemeral Reveal: Unmasks App, Username, Password, Notes for 10 seconds only
async function handleEphemeralReveal(entryId) {
  if (unmaskTimers[entryId]) {
    clearTimeout(unmaskTimers[entryId]);
    remaskRow(entryId);
    delete unmaskTimers[entryId];
    return;
  }

  try {
    const [appVal, userVal, passVal, notesVal] = await Promise.all([
      invokeCommand('reveal_field', { entryId, fieldName: 'application' }),
      invokeCommand('reveal_field', { entryId, fieldName: 'username' }),
      invokeCommand('reveal_field', { entryId, fieldName: 'password' }),
      invokeCommand('reveal_field', { entryId, fieldName: 'notes' })
    ]);

    const cellApp = document.getElementById(`cell-app-${entryId}`);
    const cellUser = document.getElementById(`cell-user-${entryId}`);
    const cellPass = document.getElementById(`cell-pass-${entryId}`);
    const cellNotes = document.getElementById(`cell-notes-${entryId}`);

    if (cellApp) { cellApp.textContent = appVal; cellApp.className = 'unmasked-cell'; }
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
  const cellApp = document.getElementById(`cell-app-${entryId}`);
  const cellUser = document.getElementById(`cell-user-${entryId}`);
  const cellPass = document.getElementById(`cell-pass-${entryId}`);
  const cellNotes = document.getElementById(`cell-notes-${entryId}`);

  if (cellApp) { cellApp.textContent = '••••••••••••'; cellApp.className = 'masked-cell'; }
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
  modalApp.value = '';
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
  const application = modalApp.value.trim();
  const website = modalWebsite.value.trim();
  const username = modalUser.value.trim();
  const password = modalPass.value;
  const notes = modalNotes.value.trim();

  if (!website) {
    showError(modalError, 'Website is required.');
    return;
  }
  if (!password) {
    showError(modalError, 'Password is required.');
    return;
  }

  try {
    const updated = await invokeCommand('add_entry', {
      application,
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
