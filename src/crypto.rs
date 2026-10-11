//! Small keyed-hash helpers. Everything identifying is HMAC'd with a server
//! secret before it is stored or used as a key.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_hex(secret: &[u8], domain: &str, data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac takes any key length");
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// First 8 bytes of the HMAC as a map key.
pub fn keyed_u64(secret: &[u8], domain: &str, data: &[u8]) -> u64 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac takes any key length");
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(data);
    let out = mac.finalize().into_bytes();
    u64::from_be_bytes(out[..8].try_into().expect("32 bytes"))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Constant-time string comparison.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Load the server secret from `<dir>/secret`, creating it (0600) if absent.
pub fn load_or_create_secret(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("secret");
    if let Ok(text) = fs::read_to_string(&path) {
        let bytes = hex::decode(text.trim()).context("secret file is not hex")?;
        if bytes.len() >= 32 {
            return Ok(bytes);
        }
    }
    fs::create_dir_all(dir)?;
    let secret = random_hex(32);
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .or_else(|_| {
            fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
        })
        .with_context(|| format!("write {}", path.display()))?;
    f.write_all(secret.as_bytes())?;
    Ok(hex::decode(secret)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_depends_on_secret_domain_and_data() {
        let a = hmac_hex(b"k1", "d", b"x");
        assert_eq!(a, hmac_hex(b"k1", "d", b"x"));
        assert_ne!(a, hmac_hex(b"k2", "d", b"x"));
        assert_ne!(a, hmac_hex(b"k1", "e", b"x"));
        assert_ne!(a, hmac_hex(b"k1", "d", b"y"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn secret_is_created_once_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s1 = load_or_create_secret(dir.path()).unwrap();
        let s2 = load_or_create_secret(dir.path()).unwrap();
        assert_eq!(s1, s2);
        assert!(s1.len() >= 32);
        let mode = fs::metadata(dir.path().join("secret"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn random_hex_is_random_and_sized() {
        assert_eq!(random_hex(16).len(), 32);
        assert_ne!(random_hex(16), random_hex(16));
    }
}
