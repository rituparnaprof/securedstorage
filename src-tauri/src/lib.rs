// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * SecuredStorage - PQC-Compliant Offline Password Vault
 * Copyright (C) 2026 rituparnaprof
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

// SecuredStorage - Tauri Library Entry Point & IPC Command Handlers

pub mod crypto;
pub mod security;
pub mod vault;

use tauri::{Manager, State};
use vault::{
    add_new_entry, delete_entry_by_id, get_entry_with_password, initialize_new_vault,
    recover_vault_with_key, reveal_entry_field, step_verify_biometrics,
    unlock_with_biometric_and_pin, unlock_with_password, update_entry_by_id, vault_file_exists,
    CredentialEntry, MaskedCredentialEntry, SafeSession, VaultSession,
};

#[derive(serde::Serialize)]
pub struct RecoveryResult {
    pub new_recovery_key: String,
    pub entries: Vec<MaskedCredentialEntry>,
}

#[tauri::command]
fn check_vault_exists() -> bool {
    vault_file_exists()
}

#[tauri::command]
fn initialize_vault(
    master_password: String,
    pin: String,
    session: State<'_, SafeSession>,
) -> Result<String, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    let recovery_key = initialize_new_vault(&master_password, &pin, &mut sess)?;
    Ok(recovery_key)
}

#[tauri::command]
fn trigger_biometric_scan(session: State<'_, SafeSession>) -> Result<bool, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    step_verify_biometrics(&mut sess)
}

#[tauri::command]
fn unlock_vault_password(
    password: String,
    session: State<'_, SafeSession>,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    unlock_with_password(&password, &mut sess)
}

#[tauri::command]
fn unlock_vault_biometric(
    pin: String,
    session: State<'_, SafeSession>,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    unlock_with_biometric_and_pin(&pin, &mut sess)
}

#[tauri::command]
fn recover_vault(
    recovery_key: String,
    new_password: String,
    new_pin: String,
    session: State<'_, SafeSession>,
) -> Result<RecoveryResult, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    let (new_key, entries) =
        recover_vault_with_key(&recovery_key, &new_password, &new_pin, &mut sess)?;
    Ok(RecoveryResult {
        new_recovery_key: new_key,
        entries,
    })
}

#[tauri::command]
fn reveal_field(
    entry_id: String,
    field_name: String,
    session: State<'_, SafeSession>,
) -> Result<String, String> {
    let sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    reveal_entry_field(&entry_id, &field_name, &sess)
}

#[tauri::command]
fn add_entry(
    application: String,
    website: String,
    username: String,
    password: String,
    notes: String,
    session: State<'_, SafeSession>,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    add_new_entry(application, website, username, password, notes, &mut sess)
}

#[tauri::command]
fn get_entry_for_edit(
    entry_id: String,
    master_password: String,
    session: State<'_, SafeSession>,
) -> Result<CredentialEntry, String> {
    let sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    get_entry_with_password(&entry_id, &master_password, &sess)
}

#[tauri::command]
fn update_entry(
    entry_id: String,
    website: String,
    username: String,
    password: String,
    notes: String,
    master_password: String,
    session: State<'_, SafeSession>,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    update_entry_by_id(
        &entry_id,
        website,
        username,
        password,
        notes,
        &master_password,
        &mut sess,
    )
}

#[tauri::command]
fn delete_entry(
    entry_id: String,
    master_password: String,
    session: State<'_, SafeSession>,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    delete_entry_by_id(&entry_id, &master_password, &mut sess)
}

#[tauri::command]
fn lock_vault(session: State<'_, SafeSession>) -> Result<String, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    sess.lock();
    Ok("Vault locked".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    security::apply_process_hardening();

    tauri::Builder::default()
        .manage(std::sync::Mutex::new(VaultSession::new()))
        .setup(|app| {
            if let Some(main_window) = app.get_webview_window("main") {
                security::apply_window_capture_protection(&main_window);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            check_vault_exists,
            initialize_vault,
            trigger_biometric_scan,
            unlock_vault_password,
            unlock_vault_biometric,
            recover_vault,
            reveal_field,
            add_entry,
            get_entry_for_edit,
            update_entry,
            delete_entry,
            lock_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running SecuredStorage application");
}
