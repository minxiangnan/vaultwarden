//! RFC 6238 TOTP. The dynamic binary code is HMAC truncated, then reduced modulo 10^digits.
//! Steam Guard uses the same binary code and a 5-character alphabet instead of decimal digits.

use ring::hmac;

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

#[derive(Debug)]
pub enum TotpError {
    Algorithm,
    Digits,
    Period,
    Secret,
}

pub fn decode_base32_secret(secret: &str) -> Result<Vec<u8>, TotpError> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(TotpError::Secret);
    }
    data_encoding::BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| TotpError::Secret)
}

pub fn generate(
    algorithm: &str,
    secret: &[u8],
    digits: u32,
    period: u64,
    steam: bool,
    unix_time: u64,
) -> Result<TotpCode, TotpError> {
    if !(1..=86400).contains(&period) {
        return Err(TotpError::Period);
    }
    if !(5..=10).contains(&digits) {
        return Err(TotpError::Digits);
    }
    if secret.is_empty() {
        return Err(TotpError::Secret);
    }
    let counter = unix_time / period;
    let binary = hotp_binary(algorithm, secret, counter)?;
    let code = if steam {
        steam_code(binary)
    } else {
        let modulo = 10u64.pow(digits);
        format!("{:0width$}", binary % modulo, width = digits as usize)
    };
    let elapsed = unix_time % period;
    Ok(TotpCode {
        code,
        seconds_remaining: period - elapsed,
        period,
    })
}

fn hotp_binary(algorithm: &str, secret: &[u8], counter: u64) -> Result<u64, TotpError> {
    let key_alg = match algorithm {
        "SHA1" => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => hmac::HMAC_SHA256,
        "SHA512" => hmac::HMAC_SHA512,
        _ => return Err(TotpError::Algorithm),
    };
    let key = hmac::Key::new(key_alg, secret);
    let mac = hmac::sign(&key, &counter.to_be_bytes());
    let mac = mac.as_ref();
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([mac[offset] & 0x7f, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
    Ok(u64::from(bin))
}

fn steam_code(binary: u64) -> String {
    let mut value = binary;
    let mut out = String::with_capacity(5);
    for _ in 0..5 {
        let index = usize::try_from(value % 26).unwrap_or(0);
        out.push(STEAM_ALPHABET[index] as char);
        value /= STEAM_ALPHABET.len() as u64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(len: usize) -> Vec<u8> {
        b"1234567890123456789012345678901234567890123456789012345678901234"[..len].to_vec()
    }

    // RFC 6238 appendix B, 8 digits, step 30.
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            ("SHA1", 20, 59u64, "94287082"),
            ("SHA256", 32, 59, "46119246"),
            ("SHA512", 64, 59, "90693936"),
            ("SHA1", 20, 1_111_111_109, "07081804"),
            ("SHA256", 32, 1_111_111_109, "68084774"),
            ("SHA512", 64, 1_111_111_109, "25091201"),
            ("SHA1", 20, 1_111_111_111, "14050471"),
            ("SHA256", 32, 1_111_111_111, "67062674"),
            ("SHA512", 64, 1_111_111_111, "99943326"),
            ("SHA1", 20, 1_234_567_890, "89005924"),
            ("SHA256", 32, 1_234_567_890, "91819424"),
            ("SHA512", 64, 1_234_567_890, "93441116"),
            ("SHA1", 20, 2_000_000_000, "69279037"),
            ("SHA256", 32, 2_000_000_000, "90698825"),
            ("SHA512", 64, 2_000_000_000, "38618901"),
            ("SHA1", 20, 20_000_000_000, "65353130"),
            ("SHA256", 32, 20_000_000_000, "77737706"),
            ("SHA512", 64, 20_000_000_000, "47863826"),
        ];
        for (alg, len, time, expected) in cases {
            let code = generate(alg, &secret(len), 8, 30, false, time).unwrap();
            assert_eq!(code.code, expected, "{alg} at {time}");
        }
    }

    #[test]
    fn six_digits_are_the_low_order_digits_and_period_60_changes_the_counter() {
        let code = generate("SHA1", &secret(20), 6, 30, false, 59).unwrap();
        assert_eq!(code.code, "287082");
        assert_eq!(code.seconds_remaining, 1);

        let at_30 = generate("SHA1", &secret(20), 8, 60, false, 59).unwrap();
        let at_step = generate("SHA1", &secret(20), 8, 30, false, 59).unwrap();
        assert_ne!(at_30.code, at_step.code);
        assert_eq!(at_30.seconds_remaining, 1);
    }

    #[test]
    fn base32_secret_matches_the_raw_rfc_seed() {
        let raw = secret(20);
        let encoded = data_encoding::BASE32_NOPAD.encode(&raw);
        let decoded = decode_base32_secret(&format!("  {encoded}  ")).unwrap();
        assert_eq!(decoded, raw);
        let code = generate("SHA1", &decoded, 8, 30, false, 59).unwrap();
        assert_eq!(code.code, "94287082");
    }
}
