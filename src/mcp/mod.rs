//! Opt-in MCP access to TOTP codes.
//!
//! Vault entries stay encrypted to the user key. A separate ciphertext, sealed to a key derived
//! from a revocable MCP access token, is the only secret this module can open, and only while
//! that token is presented.

mod alias;
mod crypto;
mod limit;
pub mod protocol;
mod service;
pub mod stdio;
mod totp;

pub use limit::{allow_ip, allow_token};
pub use service::{
    EntryInput, IssuedToken, McpSession, OpenError, audit_anonymous, audit_user, delete_source, get_code, issue_token,
    list_aliases, revoke_user, rotate_token, search, store_entry,
};
