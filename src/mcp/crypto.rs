//! MCP token wrapping.
//!
//! The vault TOTP secret stays an EncString under the user key. When the user opts an entry in,
//! the extension seals a second copy with a key derived from the MCP access token:
//!
//! ```text
//! key = HKDF-SHA256(ikm = utf8(token), salt = key_salt, info = "vaultwarden-mcp-totp-v1")
//! packed = base64url(nonce[12] || AES-256-GCM(plaintext, aad) || tag[16])
//! aad = utf8("v1|{field}|{user_id}|{source}|{source_id}|{alias}")
//! ```
//!
//! `field` is `secret`, `issuer`, `account`, or `host`. The alias is the normalized lowercase
//! alias. The server stores only `SHA-256(token)` and the salt. It derives this key when the
//! token is presented, and it does not write the key or the plaintext.
//!
//! Keep this in lockstep with `scripts/mcp-crypto.mjs` and the extension file
//! `apps/browser/src/authenticator/mcp/mcp-crypto.ts`.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    digest, hkdf,
};

pub const HKDF_INFO: &[u8] = b"vaultwarden-mcp-totp-v1";
pub const TOKEN_PREFIX: &str = "vw_mcp_";

pub fn zeroize(buf: &mut [u8]) {
    for byte in buf {
        *byte = 0;
        std::hint::black_box(*byte);
    }
}

pub struct McpKey([u8; 32]);

impl McpKey {
    pub fn derive(token: &str, salt: &[u8]) -> Result<Self, ring::error::Unspecified> {
        let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = hkdf_salt.extract(token.as_bytes());
        let mut key = [0u8; 32];
        prk.expand(&[HKDF_INFO], hkdf::HKDF_SHA256)?.fill(&mut key)?;
        Ok(Self(key))
    }

    #[cfg(test)]
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<String, ring::error::Unspecified> {
        use ring::rand::{SecureRandom, SystemRandom};

        let unbound = UnboundKey::new(&AES_256_GCM, &self.0)?;
        let key = LessSafeKey::new(unbound);
        let mut nonce_bytes = [0u8; 12];
        SystemRandom::new().fill(&mut nonce_bytes)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)?;
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)?;
        let mut packed = Vec::with_capacity(12 + in_out.len());
        packed.extend_from_slice(&nonce_bytes);
        packed.extend_from_slice(&in_out);
        zeroize(&mut in_out);
        Ok(BASE64URL_NOPAD.encode(&packed))
    }

    pub fn open(&self, aad: &[u8], packed_b64: &str) -> Result<Vec<u8>, ()> {
        let packed = BASE64URL_NOPAD.decode(packed_b64.as_bytes()).map_err(|_| ())?;
        if packed.len() < 12 + 16 {
            return Err(());
        }
        let (nonce_bytes, ciphertext) = packed.split_at(12);
        let unbound = UnboundKey::new(&AES_256_GCM, &self.0).map_err(|_| ())?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| ())?;
        let mut in_out = ciphertext.to_vec();
        let plain = key.open_in_place(nonce, Aad::from(aad), &mut in_out).map_err(|_| ())?;
        let owned = plain.to_vec();
        zeroize(&mut in_out);
        Ok(owned)
    }
}

impl Drop for McpKey {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

pub fn generate_token() -> String {
    let bytes = crate::crypto::get_random_bytes::<32>();
    format!("{TOKEN_PREFIX}{}", BASE64URL_NOPAD.encode(&bytes))
}

pub fn generate_salt() -> String {
    BASE64URL_NOPAD.encode(&crate::crypto::get_random_bytes::<32>())
}

pub fn decode_salt(salt: &str) -> Result<Vec<u8>, ()> {
    let decoded = BASE64URL_NOPAD.decode(salt.as_bytes()).map_err(|_| ())?;
    if decoded.len() < 16 {
        return Err(());
    }
    Ok(decoded)
}

pub fn token_hash(token: &str) -> String {
    HEXLOWER.encode(digest::digest(&digest::SHA256, token.as_bytes()).as_ref())
}

pub fn aad(user_id: &str, source: &str, source_id: &str, alias: &str, field: &str) -> Vec<u8> {
    format!("v1|{field}|{user_id}|{source}|{source_id}|{alias}").into_bytes()
}

/// Reject a wrapped token that is actually the bearer token, so we never store it in `token_enc`.
pub fn looks_like_wrapped_secret(value: &str, token: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100_000
        && value != token
        && !value.starts_with(TOKEN_PREFIX)
        && (value.contains('|') || value.contains('.'))
}

pub fn ciphertext_well_formed(value: &str) -> bool {
    if value.len() > 12_000 {
        return false;
    }
    match BASE64URL_NOPAD.decode(value.as_bytes()) {
        Ok(bytes) => bytes.len() >= 12 + 16,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_wrong_token_fails() {
        let token = generate_token();
        let salt = decode_salt(&generate_salt()).unwrap();
        let key = McpKey::derive(&token, &salt).unwrap();
        let bound = aad("user", "authenticator", "entry", "gitlab", "secret");
        let packed = key.seal(&bound, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let opened = key.open(&bound, &packed).unwrap();
        assert_eq!(opened, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

        let other = McpKey::derive("vw_mcp_other-token-value-not-the-same", &salt).unwrap();
        assert!(other.open(&bound, &packed).is_err());
        let wrong_aad = aad("user", "authenticator", "entry", "github", "secret");
        assert!(key.open(&wrong_aad, &packed).is_err());
    }

    #[test]
    fn token_hash_does_not_echo_the_token() {
        let token = generate_token();
        let hash = token_hash(&token);
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("vw_mcp"));
        assert!(looks_like_wrapped_secret("2.iv|ct|mac", &token));
        assert!(!looks_like_wrapped_secret(&token, &token));
    }
}
