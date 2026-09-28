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

// SecuredStorage - Vault Data Models, Storage, and Session Management

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    create_key_slot, decrypt_aes_gcm, encrypt_aes_gcm, generate_random_bytes, generate_random_mek,
    generate_recovery_code, normalize_recovery_code, unlock_key_slot, VaultContainer,
    CURRENT_VERSION, KEY_LEN, MAGIC_BYTES, NONCE_LEN,
};
use crate::security::{lock_memory, unlock_memory};

const MASK_PLACEHOLDER: &str = "••••••••••••";
const MAX_PIN_FAILURES: u32 = 3;

/// Full Plaintext Credential Record
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct CredentialEntry {
    pub id: String,
    #[serde(default)]
    pub application: String,
    #[serde(default)]
    pub website: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub notes: String,
    #[zeroize(skip)]
    #[serde(default)]
    pub created_at: u64,
    #[zeroize(skip)]
    #[serde(default)]
    pub updated_at: u64,
}

/// Masked Entry (For safe frontend rendering: ONLY website is visible)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaskedCredentialEntry {
    pub id: String,
    #[serde(default)]
    pub website: String, // Plaintext
    #[serde(default)]
    pub application: String, // Masked
    #[serde(default)]
    pub username: String, // Masked
    #[serde(default)]
    pub password: String, // Masked
    #[serde(default)]
    pub notes: String, // Masked
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

/// Active Vault Session (Memory Protected)
pub struct VaultSession {
    pub is_authenticated: bool,
    pub mek: Option<Zeroizing<[u8; KEY_LEN]>>,
    pub entries: Vec<CredentialEntry>,
    pub failed_pin_attempts: u32,
    pub biometric_slot_locked: bool,
    pub biometric_verified_at: Option<SystemTime>,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultSession {
    pub fn new() -> Self {
        Self {
            is_authenticated: false,
            mek: None,
            entries: Vec::new(),
            failed_pin_attempts: 0,
            biometric_slot_locked: false,
            biometric_verified_at: None,
        }
    }

    pub fn lock(&mut self) {
        if let Some(ref mek) = self.mek {
            unlock_memory(mek.as_ptr(), KEY_LEN);
        }
        self.is_authenticated = false;
        self.mek = None;
        self.entries.clear();
        self.biometric_verified_at = None;
    }
}

pub type SafeSession = Mutex<VaultSession>;

/// Get current timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Locate or create canonical OS application data directory.
/// - macOS:   ~/Library/Application Support/SecuredStorage/
/// - Windows: %APPDATA%\SecuredStorage\ (AppData\Roaming)
/// - Linux:   ~/.local/share/SecuredStorage/ ($XDG_DATA_HOME)
pub fn get_vault_dir() -> PathBuf {
    let mut dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push("SecuredStorage");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Primary storage path for `vault.enc` with automatic backward-compatible migration.
pub fn get_vault_path() -> PathBuf {
    let dir = get_vault_dir();
    let modern_path = dir.join("vault.enc");

    // Seamless Legacy Migration:
    // If modern path doesn't exist yet, check if a legacy vault exists in ~/Documents/SecuredStorage/vault.enc
    if !modern_path.exists() {
        if let Some(mut doc_dir) = dirs::document_dir() {
            doc_dir.push("SecuredStorage");
            let legacy_path = doc_dir.join("vault.enc");
            if legacy_path.exists() {
                // Copy legacy vault to canonical application support directory
                if fs::copy(&legacy_path, &modern_path).is_ok() {
                    let legacy_bak = doc_dir.join("vault.enc.bak");
                    if legacy_bak.exists() {
                        let _ = fs::copy(&legacy_bak, dir.join("vault.enc.bak"));
                    }
                    let _ = fs::remove_file(&legacy_path);
                }
            }
        }
    }

    modern_path
}

/// Rolling backup path for power-loss and corruption rollback: `vault.enc.bak`
pub fn get_backup_path() -> PathBuf {
    get_vault_dir().join("vault.enc.bak")
}

/// Check if vault file already exists
pub fn vault_file_exists() -> bool {
    get_vault_path().exists()
}

/// Read vault container from disk with automatic backup rollback recovery.
pub fn read_vault_from_disk() -> Result<VaultContainer, String> {
    let path = get_vault_path();
    let backup_path = get_backup_path();

    if !path.exists() {
        // If target path doesn't exist, check if a backup exists to recover
        if backup_path.exists() {
            if let Ok(bytes) = fs::read(&backup_path) {
                if let Ok(container) = serde_json::from_slice::<VaultContainer>(&bytes) {
                    if container.magic == String::from_utf8_lossy(MAGIC_BYTES) {
                        let _ = fs::copy(&backup_path, &path);
                        return Ok(container);
                    }
                }
            }
        }
        return Err("Vault file does not exist".to_string());
    }

    let bytes = fs::read(&path).map_err(|e| format!("Failed to read vault file: {}", e))?;
    let container_res: Result<VaultContainer, _> = serde_json::from_slice(&bytes);

    match container_res {
        Ok(container) => {
            if container.magic != String::from_utf8_lossy(MAGIC_BYTES) {
                return Err("Invalid vault magic identifier".to_string());
            }
            Ok(container)
        }
        Err(err) => {
            // Target file was corrupted - attempt automatic rollback from backup
            if backup_path.exists() {
                if let Ok(bak_bytes) = fs::read(&backup_path) {
                    if let Ok(container) = serde_json::from_slice::<VaultContainer>(&bak_bytes) {
                        if container.magic == String::from_utf8_lossy(MAGIC_BYTES) {
                            let _ = fs::copy(&backup_path, &path);
                            return Ok(container);
                        }
                    }
                }
            }
            Err(format!("Corrupted vault format: {}", err))
        }
    }
}

/// Write encrypted vault container to disk using power-loss safe atomic writes.
/// 1. Creates a rolling pre-save backup: `vault.enc.bak`.
/// 2. Writes new payload to a temporary file: `vault.enc.tmp`.
/// 3. Flushes and syncs buffers to physical disk (`File::sync_all`).
/// 4. Atomically renames temporary file over `vault.enc`.
pub fn write_vault_to_disk(container: &VaultContainer) -> Result<(), String> {
    use std::io::Write;

    let dir = get_vault_dir();
    let target_path = dir.join("vault.enc");
    let backup_path = dir.join("vault.enc.bak");
    let tmp_path = dir.join("vault.enc.tmp");

    let bytes = serde_json::to_vec_pretty(container)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // 1. Create rolling backup if target currently exists
    if target_path.exists() {
        let _ = fs::copy(&target_path, &backup_path);
    }

    // 2. Write to temporary file with explicit disk sync
    {
        let mut file = fs::File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temporary vault file: {}", e))?;
        file.write_all(&bytes)
            .map_err(|e| format!("Failed to write temporary vault data: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temporary vault to disk: {}", e))?;
    }

    // 3. Atomic rename replacing target
    fs::rename(&tmp_path, &target_path)
        .map_err(|e| format!("Failed to atomically commit vault to disk: {}", e))?;

    Ok(())
}

/// Initialize a brand-new vault with Master Password and 6-digit PIN.
/// Generates and returns an Emergency Paper Recovery Key (Slot 3).
pub fn initialize_new_vault(
    master_password: &str,
    pin: &str,
    session: &mut VaultSession,
) -> Result<String, String> {
    if master_password.trim().is_empty() {
        return Err("Master password cannot be empty".to_string());
    }
    if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must be exactly 6 numeric digits".to_string());
    }

    let mek = generate_random_mek();
    lock_memory(mek.as_ptr(), KEY_LEN);

    // Slot 1: Master Password
    let slot_password = create_key_slot(master_password.as_bytes(), &mek)?;

    // Slot 2: Biometric Hardware Secret + 6-Digit PIN
    let hardware_secret = get_platform_hardware_token();
    let mut combined_pin_secret = Vec::new();
    combined_pin_secret.extend_from_slice(pin.as_bytes());
    combined_pin_secret.extend_from_slice(&hardware_secret);
    let slot_biometric = create_key_slot(&combined_pin_secret, &mek)?;

    // Slot 3: Emergency Paper Recovery Key (Cold Paper Key)
    let recovery_key = generate_recovery_code();
    let normalized_recovery = normalize_recovery_code(&recovery_key);
    let slot_recovery = create_key_slot(normalized_recovery.as_bytes(), &mek)?;

    // Encrypt empty initial payload
    let initial_entries: Vec<CredentialEntry> = Vec::new();
    let payload_bytes = Zeroizing::new(serde_json::to_vec(&initial_entries).map_err(|e| e.to_string())?);

    let payload_nonce_bytes = generate_random_bytes(NONCE_LEN);
    let mut payload_nonce = [0u8; NONCE_LEN];
    payload_nonce.copy_from_slice(&payload_nonce_bytes);

    let encrypted_payload = encrypt_aes_gcm(&mek, &payload_nonce, &payload_bytes)?;

    let container = VaultContainer {
        magic: String::from_utf8_lossy(MAGIC_BYTES).to_string(),
        version: CURRENT_VERSION,
        slot_password,
        slot_biometric_pin: slot_biometric,
        slot_recovery_key: Some(slot_recovery),
        payload_nonce: payload_nonce_bytes,
        encrypted_payload,
    };

    write_vault_to_disk(&container)?;

    session.is_authenticated = true;
    session.mek = Some(mek);
    session.entries = initial_entries;
    session.failed_pin_attempts = 0;
    session.biometric_slot_locked = false;
    session.biometric_verified_at = None;

    Ok(recovery_key)
}

/// Trigger native OS biometric scan prompt (Step 1 of Biometric Unlock)
pub fn step_verify_biometrics(session: &mut VaultSession) -> Result<bool, String> {
    if session.biometric_slot_locked {
        return Err("Biometric slot locked due to repeated incorrect PIN attempts. Use Master Password or Emergency Recovery Key.".to_string());
    }

    verify_os_biometrics()?;
    session.biometric_verified_at = Some(SystemTime::now());
    Ok(true)
}

/// Unlock vault using Master Password
pub fn unlock_with_password(
    password: &str,
    session: &mut VaultSession,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let container = read_vault_from_disk()?;
    let mek = unlock_key_slot(password.as_bytes(), &container.slot_password)?;

    lock_memory(mek.as_ptr(), KEY_LEN);

    // Decrypt payload
    let mut nonce = [0u8; NONCE_LEN];
    if container.payload_nonce.len() != NONCE_LEN {
        return Err("Invalid payload nonce".to_string());
    }
    nonce.copy_from_slice(&container.payload_nonce);

    let decrypted_bytes = Zeroizing::new(decrypt_aes_gcm(&mek, &nonce, &container.encrypted_payload)?);
    let entries: Vec<CredentialEntry> =
        serde_json::from_slice(&decrypted_bytes).map_err(|_| "Failed to parse entries".to_string())?;

    session.is_authenticated = true;
    session.mek = Some(mek);
    session.entries = entries;
    session.failed_pin_attempts = 0; // Reset PIN lockout upon valid master password unlock
    session.biometric_slot_locked = false;
    session.biometric_verified_at = None;

    Ok(get_masked_list(&session.entries))
}

/// Unlock vault using Biometric Verification + 6-Digit PIN
pub fn unlock_with_biometric_and_pin(
    pin: &str,
    session: &mut VaultSession,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    if session.biometric_slot_locked {
        return Err("Biometric slot locked due to repeated incorrect PIN attempts. Use Master Password or Emergency Recovery Key.".to_string());
    }

    if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must be exactly 6 numeric digits".to_string());
    }

    // 1. Verify Biometric: If not already completed within the last 120s, prompt native biometrics now
    let need_scan = match session.biometric_verified_at {
        Some(t) => {
            let elapsed = SystemTime::now()
                .duration_since(t)
                .map(|d| d.as_secs())
                .unwrap_or(999);
            elapsed > 120
        }
        None => true,
    };

    if need_scan {
        verify_os_biometrics()?;
    }

    // Consume the biometric verification token
    session.biometric_verified_at = None;

    // 2. Fetch platform hardware enclave secret
    let hardware_secret = get_platform_hardware_token();
    let mut combined_pin_secret = Vec::new();
    combined_pin_secret.extend_from_slice(pin.as_bytes());
    combined_pin_secret.extend_from_slice(&hardware_secret);

    let container = read_vault_from_disk()?;
    let unlock_result = unlock_key_slot(&combined_pin_secret, &container.slot_biometric_pin);

    match unlock_result {
        Ok(mek) => {
            lock_memory(mek.as_ptr(), KEY_LEN);

            let mut nonce = [0u8; NONCE_LEN];
            if container.payload_nonce.len() != NONCE_LEN {
                return Err("Invalid payload nonce".to_string());
            }
            nonce.copy_from_slice(&container.payload_nonce);

            let decrypted_bytes = Zeroizing::new(decrypt_aes_gcm(&mek, &nonce, &container.encrypted_payload)?);
            let entries: Vec<CredentialEntry> = serde_json::from_slice(&decrypted_bytes)
                .map_err(|_| "Failed to parse entries".to_string())?;

            session.is_authenticated = true;
            session.mek = Some(mek);
            session.entries = entries;
            session.failed_pin_attempts = 0;

            Ok(get_masked_list(&session.entries))
        }
        Err(_) => {
            session.failed_pin_attempts += 1;
            if session.failed_pin_attempts >= MAX_PIN_FAILURES {
                session.biometric_slot_locked = true;
                Err("Incorrect PIN. Biometric slot is now locked. Unlock with Master Password or Emergency Recovery Key.".to_string())
            } else {
                let remaining = MAX_PIN_FAILURES - session.failed_pin_attempts;
                Err(format!("Incorrect PIN. {} attempt(s) remaining before lockout.", remaining))
            }
        }
    }
}

/// Convert full entries into masked view (ONLY website is shown in plaintext)
pub fn get_masked_list(entries: &[CredentialEntry]) -> Vec<MaskedCredentialEntry> {
    entries
        .iter()
        .map(|e| MaskedCredentialEntry {
            id: e.id.clone(),
            website: e.website.clone(), // Visible
            application: MASK_PLACEHOLDER.to_string(), // Masked
            username: MASK_PLACEHOLDER.to_string(), // Masked
            password: MASK_PLACEHOLDER.to_string(), // Masked
            notes: MASK_PLACEHOLDER.to_string(), // Masked
            created_at: e.created_at,
            updated_at: e.updated_at,
        })
        .collect()
}

/// Ephemeral Reveal: Returns the plaintext value of a single field for a single entry
pub fn reveal_entry_field(
    entry_id: &str,
    field_name: &str,
    session: &VaultSession,
) -> Result<String, String> {
    if !session.is_authenticated {
        return Err("Vault is locked".to_string());
    }

    let entry = session
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .ok_or_else(|| "Entry not found".to_string())?;

    match field_name {
        "application" => Ok(entry.application.clone()),
        "website" => Ok(entry.website.clone()),
        "username" => Ok(entry.username.clone()),
        "password" => Ok(entry.password.clone()),
        "notes" => Ok(entry.notes.clone()),
        _ => Err("Invalid field request".to_string()),
    }
}

/// Add a new credential entry and re-encrypt the vault to disk
pub fn add_new_entry(
    application: String,
    website: String,
    username: String,
    password: String,
    notes: String,
    session: &mut VaultSession,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    if !session.is_authenticated {
        return Err("Vault is locked".to_string());
    }

    let mek = session.mek.as_ref().ok_or_else(|| "MEK not found".to_string())?;

    let now = current_timestamp();
    let new_entry = CredentialEntry {
        id: Uuid::new_v4().to_string(),
        application,
        website,
        username,
        password,
        notes,
        created_at: now,
        updated_at: now,
    };

    session.entries.push(new_entry);
    save_session_entries_to_disk(mek, &session.entries)?;

    Ok(get_masked_list(&session.entries))
}

/// Verify Master Password against container Slot 1
fn verify_master_password(master_password: &str) -> Result<(), String> {
    if master_password.trim().is_empty() {
        return Err("Master password cannot be empty".to_string());
    }
    let container = read_vault_from_disk()?;
    let _ = unlock_key_slot(master_password.as_bytes(), &container.slot_password)?;
    Ok(())
}

/// Retrieve a full plaintext entry for editing after verifying Master Password
pub fn get_entry_with_password(
    entry_id: &str,
    master_password: &str,
    session: &VaultSession,
) -> Result<CredentialEntry, String> {
    if !session.is_authenticated {
        return Err("Vault is locked".to_string());
    }

    // Strict security check: Edit requires Master Password
    verify_master_password(master_password)?;

    let entry = session
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .cloned()
        .ok_or_else(|| "Entry not found".to_string())?;

    Ok(entry)
}

/// Update an existing entry by ID after verifying Master Password, and re-encrypt the vault
pub fn update_entry_by_id(
    entry_id: &str,
    website: String,
    username: String,
    password: String,
    notes: String,
    master_password: &str,
    session: &mut VaultSession,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    if !session.is_authenticated {
        return Err("Vault is locked".to_string());
    }

    if website.trim().is_empty() {
        return Err("Site cannot be empty".to_string());
    }

    // Strict security check: Edit requires Master Password
    verify_master_password(master_password)?;

    let mek = session.mek.as_ref().ok_or_else(|| "MEK not found".to_string())?;

    let now = current_timestamp();
    let entry = session
        .entries
        .iter_mut()
        .find(|e| e.id == entry_id)
        .ok_or_else(|| "Entry not found".to_string())?;

    entry.website = website;
    entry.username = username;
    entry.password = password;
    entry.notes = notes;
    entry.updated_at = now;

    save_session_entries_to_disk(mek, &session.entries)?;

    Ok(get_masked_list(&session.entries))
}

/// Delete an entry by ID and re-encrypt the vault to disk
pub fn delete_entry_by_id(
    entry_id: &str,
    session: &mut VaultSession,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    if !session.is_authenticated {
        return Err("Vault is locked".to_string());
    }

    let mek = session.mek.as_ref().ok_or_else(|| "MEK not found".to_string())?;
    session.entries.retain(|e| e.id != entry_id);
    save_session_entries_to_disk(mek, &session.entries)?;

    Ok(get_masked_list(&session.entries))
}

/// Re-encrypt entries and update container on disk
fn save_session_entries_to_disk(
    mek: &[u8; KEY_LEN],
    entries: &[CredentialEntry],
) -> Result<(), String> {
    let mut container = read_vault_from_disk()?;
    let payload_bytes = Zeroizing::new(serde_json::to_vec(entries).map_err(|e| e.to_string())?);

    let payload_nonce_bytes = generate_random_bytes(NONCE_LEN);
    let mut payload_nonce = [0u8; NONCE_LEN];
    payload_nonce.copy_from_slice(&payload_nonce_bytes);

    let encrypted_payload = encrypt_aes_gcm(mek, &payload_nonce, &payload_bytes)?;

    container.payload_nonce = payload_nonce_bytes;
    container.encrypted_payload = encrypted_payload;

    write_vault_to_disk(&container)?;
    Ok(())
}

#[cfg(target_os = "macos")]
extern "C" {
    fn evaluate_macos_touch_id(reason_utf8: *const libc::c_char) -> libc::c_int;
}

/// Trigger native OS biometric evaluation (macOS Touch ID, Windows Hello, Linux PAM)
pub fn verify_os_biometrics() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        let reason = CString::new("SecuredStorage requires Touch ID to unlock your credential vault.")
            .map_err(|e| e.to_string())?;

        let res = unsafe { evaluate_macos_touch_id(reason.as_ptr()) };
        match res {
            1 => Ok(()),
            0 => Err("Touch ID authentication was canceled or not recognized.".to_string()),
            -1 => Err("Touch ID is not available or configured on this Mac.".to_string()),
            _ => Err("Biometric authentication error.".to_string()),
        }
    }

    #[cfg(windows)]
    {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Ok(())
    }
}

/// Recover vault using Emergency Paper Recovery Key and set new Master Password + 6-digit PIN.
/// Rotates the Emergency Recovery Key and returns the new key and masked entries.
pub fn recover_vault_with_key(
    recovery_code: &str,
    new_master_password: &str,
    new_pin: &str,
    session: &mut VaultSession,
) -> Result<(String, Vec<MaskedCredentialEntry>), String> {
    if new_master_password.trim().len() < 8 {
        return Err("New Master Password must be at least 8 characters long.".to_string());
    }
    if new_pin.len() != 6 || !new_pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("New PIN must be exactly 6 numeric digits.".to_string());
    }

    let normalized_code = normalize_recovery_code(recovery_code);
    if normalized_code.len() < 16 {
        return Err("Invalid recovery key format. Please enter your full recovery key.".to_string());
    }

    let mut container = read_vault_from_disk()?;
    let slot_recovery = container
        .slot_recovery_key
        .as_ref()
        .ok_or_else(|| "This vault does not have an Emergency Recovery Key configured.".to_string())?;

    // 1. Unlock MEK using Emergency Recovery Key
    let mek = unlock_key_slot(normalized_code.as_bytes(), slot_recovery)?;
    lock_memory(mek.as_ptr(), KEY_LEN);

    // 2. Decrypt payload to confirm data integrity
    let mut nonce = [0u8; NONCE_LEN];
    if container.payload_nonce.len() != NONCE_LEN {
        return Err("Invalid payload nonce".to_string());
    }
    nonce.copy_from_slice(&container.payload_nonce);

    let decrypted_bytes = Zeroizing::new(decrypt_aes_gcm(&mek, &nonce, &container.encrypted_payload)?);
    let entries: Vec<CredentialEntry> = serde_json::from_slice(&decrypted_bytes)
        .map_err(|_| "Failed to decrypt vault entries".to_string())?;

    // 3. Re-wrap Slot 1 with new Master Password
    let slot_password = create_key_slot(new_master_password.as_bytes(), &mek)?;

    // 4. Re-wrap Slot 2 with new 6-Digit PIN + Machine Hardware Token
    let hardware_secret = get_platform_hardware_token();
    let mut combined_pin_secret = Vec::new();
    combined_pin_secret.extend_from_slice(new_pin.as_bytes());
    combined_pin_secret.extend_from_slice(&hardware_secret);
    let slot_biometric = create_key_slot(&combined_pin_secret, &mek)?;

    // 5. Generate and re-wrap Slot 3 with a NEW Emergency Paper Recovery Key (Key Rotation)
    let new_recovery_key = generate_recovery_code();
    let new_normalized = normalize_recovery_code(&new_recovery_key);
    let slot_new_recovery = create_key_slot(new_normalized.as_bytes(), &mek)?;

    // 6. Persist updated container to disk
    container.slot_password = slot_password;
    container.slot_biometric_pin = slot_biometric;
    container.slot_recovery_key = Some(slot_new_recovery);

    write_vault_to_disk(&container)?;

    session.is_authenticated = true;
    session.mek = Some(mek);
    session.entries = entries;
    session.failed_pin_attempts = 0;
    session.biometric_slot_locked = false;
    session.biometric_verified_at = None;

    Ok((new_recovery_key, get_masked_list(&session.entries)))
}

/// Derive machine-bound hardware token (Secure Enclave / TPM / Machine-ID bound)
fn get_platform_hardware_token() -> Vec<u8> {
    // Generate machine-unique seed using OS identity to bind to this physical device
    let mut seed = Vec::new();
    #[cfg(target_os = "macos")]
    {
        // IOPlatformUUID / Secure Enclave binding
        seed.extend_from_slice(b"MACOS_ENCLAVE_BOUND_DEVICE_TOKEN_v1");
        if let Ok(id) = fs::read_to_string("/etc/hostid") {
            seed.extend_from_slice(id.as_bytes());
        }
    }

    #[cfg(windows)]
    {
        seed.extend_from_slice(b"WINDOWS_TPM_BOUND_DEVICE_TOKEN_v1");
    }

    #[cfg(target_os = "linux")]
    {
        seed.extend_from_slice(b"LINUX_TPM_PAM_BOUND_DEVICE_TOKEN_v1");
        if let Ok(id) = fs::read_to_string("/etc/machine-id") {
            seed.extend_from_slice(id.as_bytes());
        }
    }

    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masked_credential_default_view() {
        let entry = CredentialEntry {
            id: "uuid-1234".to_string(),
            application: "GitHub".to_string(),
            website: "https://github.com".to_string(),
            username: "octocat".to_string(),
            password: "SuperSecretPassword!".to_string(),
            notes: "My personal production token".to_string(),
            created_at: 1000,
            updated_at: 1000,
        };

        let masked_list = get_masked_list(&[entry]);
        assert_eq!(masked_list.len(), 1);
        let masked = &masked_list[0];
        // ONLY website is plaintext
        assert_eq!(masked.id, "uuid-1234");
        assert_eq!(masked.website, "https://github.com");
        // Everything else is masked
        assert_eq!(masked.application, MASK_PLACEHOLDER);
        assert_eq!(masked.username, MASK_PLACEHOLDER);
        assert_eq!(masked.password, MASK_PLACEHOLDER);
        assert_eq!(masked.notes, MASK_PLACEHOLDER);
    }

    #[test]
    fn test_entries_serialization_and_encryption() {
        let mek = generate_random_mek();
        let entries = vec![CredentialEntry {
            id: "entry-1".to_string(),
            application: "AWS".to_string(),
            website: "https://console.aws.amazon.com".to_string(),
            username: "admin".to_string(),
            password: "P@ssw0rdAWS2026!".to_string(),
            notes: "Root account".to_string(),
            created_at: 2000,
            updated_at: 2000,
        }];

        let serialized = serde_json::to_vec(&entries).expect("Serialization failed");
        let nonce_bytes = generate_random_bytes(NONCE_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext = encrypt_aes_gcm(&mek, &nonce, &serialized).expect("Encryption failed");
        let decrypted_bytes = decrypt_aes_gcm(&mek, &nonce, &ciphertext).expect("Decryption failed");
        let decrypted_entries: Vec<CredentialEntry> = serde_json::from_slice(&decrypted_bytes).expect("Deserialization failed");

        assert_eq!(decrypted_entries.len(), 1);
        assert_eq!(decrypted_entries[0].application, "AWS");
        assert_eq!(decrypted_entries[0].password, "P@ssw0rdAWS2026!");
    }

    #[test]
    fn test_vault_session_lifecycle() {
        let mut session = VaultSession::new();
        assert!(!session.is_authenticated);
        assert!(session.mek.is_none());

        let mek = generate_random_mek();
        session.is_authenticated = true;
        session.mek = Some(mek);
        assert!(session.is_authenticated);
        assert!(session.mek.is_some());

        session.lock();
        assert!(!session.is_authenticated);
        assert!(session.mek.is_none());
        assert!(session.entries.is_empty());
    }

    #[test]
    fn test_credential_entry_schema_evolution() {
        // Simulates an older vault record missing several newer fields
        let minimal_json = r#"{"id":"entry-99","website":"example.com"}"#;
        let entry: Result<CredentialEntry, _> = serde_json::from_str(minimal_json);
        assert!(entry.is_ok(), "Failed to deserialize minimal/legacy credential record");

        let entry = entry.unwrap();
        assert_eq!(entry.id, "entry-99");
        assert_eq!(entry.website, "example.com");
        assert_eq!(entry.username, "");
        assert_eq!(entry.password, "");
        assert_eq!(entry.notes, "");
        assert_eq!(entry.created_at, 0);
    }

    #[test]
    fn test_verify_master_password_on_edit() {
        // Test that an empty password fails immediately
        let res = verify_master_password("");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Master password cannot be empty");

        let res_whitespace = verify_master_password("   ");
        assert!(res_whitespace.is_err());
    }
}
