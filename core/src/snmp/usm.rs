//! SNMPv3 User-based Security Model: keys, authentication and encryption.
//! RFC 3414 (MD5, SHA-1, DES), RFC 7860 (SHA-2), RFC 3826 (AES-128).

use aes::cipher::{
    block_padding::NoPadding, AsyncStreamCipher, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priv {
    Des,
    Aes128,
}

impl Auth {
    pub fn parse(s: &str) -> Option<Auth> {
        Some(
            match s.trim().to_ascii_uppercase().replace('_', "-").as_str() {
                "MD5" => Auth::Md5,
                "SHA" | "SHA1" | "SHA-1" => Auth::Sha1,
                "SHA-224" | "SHA224" => Auth::Sha224,
                "SHA-256" | "SHA256" => Auth::Sha256,
                "SHA-384" | "SHA384" => Auth::Sha384,
                "SHA-512" | "SHA512" => Auth::Sha512,
                _ => return None,
            },
        )
    }

    /// Length of the msgAuthenticationParameters field (truncated HMAC).
    pub fn mac_len(self) -> usize {
        match self {
            Auth::Md5 | Auth::Sha1 => 12,
            Auth::Sha224 => 16,
            Auth::Sha256 => 24,
            Auth::Sha384 => 32,
            Auth::Sha512 => 48,
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn go<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            Auth::Md5 => go::<Md5>(parts),
            Auth::Sha1 => go::<Sha1>(parts),
            Auth::Sha224 => go::<Sha224>(parts),
            Auth::Sha256 => go::<Sha256>(parts),
            Auth::Sha384 => go::<Sha384>(parts),
            Auth::Sha512 => go::<Sha512>(parts),
        }
    }

    /// Password → key (1 MiB of repeated password, RFC 3414 A.2.1).
    pub fn password_to_key(self, password: &[u8]) -> Vec<u8> {
        fn go<D: Digest>(pw: &[u8]) -> Vec<u8> {
            let mut d = D::new();
            let mut chunk = [0u8; 64];
            let mut idx = 0usize;
            for _ in 0..(1_048_576 / 64) {
                for b in chunk.iter_mut() {
                    *b = pw[idx % pw.len()];
                    idx += 1;
                }
                d.update(chunk);
            }
            d.finalize().to_vec()
        }
        match self {
            Auth::Md5 => go::<Md5>(password),
            Auth::Sha1 => go::<Sha1>(password),
            Auth::Sha224 => go::<Sha224>(password),
            Auth::Sha256 => go::<Sha256>(password),
            Auth::Sha384 => go::<Sha384>(password),
            Auth::Sha512 => go::<Sha512>(password),
        }
    }

    /// Key localised on the agent's engine ID: H(Ku || engineID || Ku).
    pub fn localize(self, ku: &[u8], engine_id: &[u8]) -> Vec<u8> {
        self.digest(&[ku, engine_id, ku])
    }

    /// HMAC of the message, truncated to the protocol's length.
    pub fn mac(self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        macro_rules! h {
            ($d:ty) => {{
                let mut m = <Hmac<$d> as Mac>::new_from_slice(key).expect("chiave HMAC");
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }};
        }
        let mut full = match self {
            Auth::Md5 => h!(Md5),
            Auth::Sha1 => h!(Sha1),
            Auth::Sha224 => h!(Sha224),
            Auth::Sha256 => h!(Sha256),
            Auth::Sha384 => h!(Sha384),
            Auth::Sha512 => h!(Sha512),
        };
        full.truncate(self.mac_len());
        full
    }
}

impl Priv {
    pub fn parse(s: &str) -> Option<Priv> {
        match s.trim().to_ascii_uppercase().as_str() {
            "DES" => Some(Priv::Des),
            "AES" | "AES128" | "AES-128" => Some(Priv::Aes128),
            _ => None,
        }
    }
}

/// Encrypts the ScopedPDU. Returns (ciphertext, msgPrivacyParameters).
pub fn encrypt(
    p: Priv,
    key: &[u8],
    boots: u32,
    time: u32,
    salt: u64,
    plain: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    match p {
        Priv::Des => {
            if key.len() < 16 {
                return Err(crate::t!("Chiave DES troppo corta", "DES key too short").into());
            }
            // salt = engineBoots || local counter; IV = pre-IV XOR salt
            let mut salt_b = boots.to_be_bytes().to_vec();
            salt_b.extend_from_slice(&(salt as u32).to_be_bytes());
            let iv: Vec<u8> = key[8..16].iter().zip(&salt_b).map(|(a, b)| a ^ b).collect();
            let mut buf = plain.to_vec();
            buf.resize(plain.len().div_ceil(8) * 8, 0);
            let n = buf.len();
            let enc = cbc::Encryptor::<des::Des>::new_from_slices(&key[..8], &iv)
                .map_err(|e| e.to_string())?;
            enc.encrypt_padded_mut::<NoPadding>(&mut buf, n)
                .map_err(|e| e.to_string())?;
            Ok((buf, salt_b))
        }
        Priv::Aes128 => {
            if key.len() < 16 {
                return Err(crate::t!("Chiave AES troppo corta", "AES key too short").into());
            }
            let salt_b = salt.to_be_bytes().to_vec();
            let mut iv = boots.to_be_bytes().to_vec();
            iv.extend_from_slice(&time.to_be_bytes());
            iv.extend_from_slice(&salt_b);
            let mut buf = plain.to_vec();
            cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(&key[..16], &iv)
                .map_err(|e| e.to_string())?
                .encrypt(&mut buf);
            Ok((buf, salt_b))
        }
    }
}

/// Decrypts the ScopedPDU of a response, with the response's boots/time and salt.
pub fn decrypt(
    p: Priv,
    key: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if salt.len() != 8 {
        return Err(crate::t!(
            "Parametri di cifratura non validi nella risposta",
            "Invalid encryption parameters in the response"
        )
        .into());
    }
    match p {
        Priv::Des => {
            if !data.len().is_multiple_of(8) || key.len() < 16 {
                return Err(crate::t!(
                    "Dati DES non validi nella risposta",
                    "Invalid DES data in the response"
                )
                .into());
            }
            let iv: Vec<u8> = key[8..16].iter().zip(salt).map(|(a, b)| a ^ b).collect();
            let mut buf = data.to_vec();
            cbc::Decryptor::<des::Des>::new_from_slices(&key[..8], &iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|e| e.to_string())?;
            Ok(buf)
        }
        Priv::Aes128 => {
            let mut iv = boots.to_be_bytes().to_vec();
            iv.extend_from_slice(&time.to_be_bytes());
            iv.extend_from_slice(salt);
            let mut buf = data.to_vec();
            cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&key[..16], &iv)
                .map_err(|e| e.to_string())?
                .decrypt(&mut buf);
            Ok(buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Test vectors from RFC 3414 A.3 ("maplesyrup", engineID 00..02)
    #[test]
    fn vettori_rfc3414() {
        let engine = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let ku = Auth::Md5.password_to_key(b"maplesyrup");
        assert_eq!(hex(&ku), "9faf3283884e92834ebc9847d8edd963");
        assert_eq!(
            hex(&Auth::Md5.localize(&ku, &engine)),
            "526f5eed9fcce26f8964c2930787d82b"
        );
        let ku = Auth::Sha1.password_to_key(b"maplesyrup");
        assert_eq!(hex(&ku), "9fb5cc0381497b3793528939ff788d5d79145211");
        assert_eq!(
            hex(&Auth::Sha1.localize(&ku, &engine)),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );
    }

    #[test]
    fn cifratura_andata_e_ritorno() {
        let key = Auth::Sha1.localize(&Auth::Sha1.password_to_key(b"privpass123"), b"engine-x");
        let plain = b"scoped pdu di prova, lunghezza non multipla di 8";
        for p in [Priv::Des, Priv::Aes128] {
            let (enc, salt) = encrypt(p, &key, 7, 1234, 0xdead_beef_0102_0304, plain).unwrap();
            assert_ne!(&enc[..plain.len()], &plain[..]);
            let dec = decrypt(p, &key, 7, 1234, &salt, &enc).unwrap();
            assert_eq!(&dec[..plain.len()], &plain[..]);
        }
        assert_eq!(Auth::Sha512.mac(&key, b"x").len(), 48);
        assert_eq!(Auth::parse("sha-256"), Some(Auth::Sha256));
        assert_eq!(Priv::parse("aes"), Some(Priv::Aes128));
    }
}
