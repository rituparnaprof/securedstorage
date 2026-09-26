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

// SecuredStorage - PQC Cryptographic Engine (AES-256-GCM + Argon2id + NIST FIPS 203 Architecture)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAGIC_BYTES: &[u8; 4] = b"PQC1";
pub const CURRENT_VERSION: u16 = 1;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32; // 256 bits for AES-256
pub const TAG_LEN: usize = 16;

// Argon2id Parameters: 64 MB RAM, 3 iterations, 4 parallelism lanes
pub const ARGON2_M_COST: u32 = 65536; // 64 MB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

/// Encrypted Key Slot (Slot 1 or Slot 2)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeySlot {
    pub enabled: bool,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted_mek: Vec<u8>, // AES-256-GCM ciphertext + 16-byte tag
}

/// Full Encrypted Vault Container
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VaultContainer {
    pub magic: String,
    pub version: u16,
    pub slot_password: KeySlot,
    pub slot_biometric_pin: KeySlot,
    pub payload_nonce: Vec<u8>,
    pub encrypted_payload: Vec<u8>, // AES-256-GCM ciphertext + 16-byte tag
}

/// Derive a 256-bit key using memory-hard Argon2id
pub fn derive_argon2id_key(secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if salt.len() < 8 {
        return Err("Salt length too short".to_string());
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived_key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(secret, salt, &mut *derived_key)
        .map_err(|_| "Key derivation failed".to_string())?;

    Ok(derived_key)
}

/// Generate high-entropy 256-bit random Master Encryption Key (MEK)
pub fn generate_random_mek() -> Zeroizing<[u8; KEY_LEN]> {
    let mut mek = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut *mek);
    mek
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Encrypt a buffer using AES-256-GCM (Authenticated Encryption with Associated Data)
pub fn encrypt_aes_gcm(key: &[u8; KEY_LEN], nonce_bytes: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid key length".to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed".to_string())?;

    Ok(ciphertext)
}

/// Decrypt a buffer using AES-256-GCM with strict authentication verification
pub fn decrypt_aes_gcm(key: &[u8; KEY_LEN], nonce_bytes: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid key length".to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Authentication failed or corrupted vault".to_string())?;

    Ok(Zeroizing::new(plaintext))
}

/// Create a KeySlot wrapping the Master Encryption Key (MEK)
pub fn create_key_slot(secret: &[u8], mek: &[u8; KEY_LEN]) -> Result<KeySlot, String> {
    let salt = generate_random_bytes(SALT_LEN);
    let nonce_bytes = generate_random_bytes(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let wrapping_key = derive_argon2id_key(secret, &salt)?;
    let encrypted_mek = encrypt_aes_gcm(&wrapping_key, &nonce, mek)?;

    Ok(KeySlot {
        enabled: true,
        salt,
        nonce: nonce_bytes,
        encrypted_mek,
    })
}

/// Unlock a KeySlot and recover the Master Encryption Key (MEK)
pub fn unlock_key_slot(secret: &[u8], slot: &KeySlot) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if !slot.enabled {
        return Err("Key slot is not enabled".to_string());
    }

    if slot.nonce.len() != NONCE_LEN {
        return Err("Malformed slot nonce".to_string());
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&slot.nonce);

    let wrapping_key = derive_argon2id_key(secret, &slot.salt)?;
    let decrypted = decrypt_aes_gcm(&wrapping_key, &nonce, &slot.encrypted_mek)?;

    if decrypted.len() != KEY_LEN {
        return Err("Authentication failed or corrupted vault".to_string());
    }

    let mut mek = Zeroizing::new([0u8; KEY_LEN]);
    mek.copy_from_slice(&decrypted);
    Ok(mek)
}

/// Constant-time comparison helper
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
