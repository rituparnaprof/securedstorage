// SecuredStorage - Tauri Library Entry Point & IPC Command Handlers

pub mod crypto;
pub mod security;
pub mod vault;

use tauri::{AppHandle, Manager, State};
use vault::{
    add_new_entry, delete_entry_by_id, initialize_new_vault, reveal_entry_field,
    unlock_with_biometric_and_pin, unlock_with_password, vault_file_exists, MaskedCredentialEntry,
    SafeSession, VaultSession,
};

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
    initialize_new_vault(&master_password, &pin, &mut sess)?;
    Ok("Vault successfully initialized".to_string())
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
fn delete_entry(
    entry_id: String,
    session: State<'_, SafeSession>,
) -> Result<Vec<MaskedCredentialEntry>, String> {
    let mut sess = session.lock().map_err(|_| "Failed to lock session".to_string())?;
    delete_entry_by_id(&entry_id, &mut sess)
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
            unlock_vault_password,
            unlock_vault_biometric,
            reveal_field,
            add_entry,
            delete_entry,
            lock_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running SecuredStorage application");
}
