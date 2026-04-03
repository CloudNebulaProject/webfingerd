use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::Engine;
use rand::Rng;

/// Generate a prefixed token: `{id}.{random_secret}`.
/// The id allows O(1) lookup; the secret is verified via argon2.
/// The `id` parameter is the entity UUID this token belongs to.
pub fn generate_token(id: &str) -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{id}.{secret}")
}

/// Generate a non-prefixed secret (for registration secrets that don't need lookup).
pub fn generate_secret() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token (or its secret part) with argon2.
pub fn hash_token(token: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(token.as_bytes(), &salt)?.to_string())
}

/// Verify a token against a stored argon2 hash.
pub fn verify_token(token: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Split a prefixed token into (id, secret).
/// Returns None if the token is not in `id.secret` format.
pub fn split_token(token: &str) -> Option<(&str, &str)> {
    token.split_once('.')
}
