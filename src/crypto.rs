use anyhow::{anyhow, Context, Result};
use hex::decode;

use xsalsa20poly1305::aead::generic_array::{typenum::U24, GenericArray};
use xsalsa20poly1305::aead::{Aead, NewAead};
use xsalsa20poly1305::XSalsa20Poly1305;

pub const NONCE_LENGTH: usize = 24;
pub const SECRET_LENGTH: usize = 32;
pub const SECRET_HEX_LENGTH: usize = SECRET_LENGTH * 2;

pub trait FromHex: Sized {
    fn from_hex(bs: &str) -> Result<Self>;
}

pub type Nonce = GenericArray<u8, U24>;

impl FromHex for Nonce {
    fn from_hex(bs: &str) -> Result<Nonce> {
        let raw = decode_hex_with_length_check(&bs, NONCE_LENGTH)?;

        let nonce = GenericArray::clone_from_slice(&raw);

        Ok(nonce)
    }
}

impl FromHex for XSalsa20Poly1305 {
    fn from_hex(bs: &str) -> Result<XSalsa20Poly1305> {
        let raw = decode_hex_with_length_check(bs, SECRET_LENGTH)?;

        let key = GenericArray::from_slice(&raw);

        Ok(XSalsa20Poly1305::new(&*key))
    }
}

fn decode_hex_with_length_check(s: &str, length: usize) -> Result<Vec<u8>> {
    let raw = decode(&s)?;

    if raw.len() != length {
        return Err(anyhow!(
            "invalid key length; supplied: {}, required: {}",
            raw.len(),
            length
        ));
    }

    Ok(raw)
}

// Helper function for structopt to check if a key str is correct
// TODO get Result<XSalsa20Poly1305> working
pub fn parse_secret_key(src: &str) -> Result<String> {
    if src.len() != SECRET_HEX_LENGTH {
        return Err(anyhow!(
            "Invalid key length ({}). Key must be supplied as {} byte hex string.",
            src.len(),
            SECRET_HEX_LENGTH
        ));
    }

    XSalsa20Poly1305::from_hex(src)?;

    Ok(src.to_owned())
}

pub fn open_secret_box(
    cipher_message_hex: &str,
    nonce_hex: &str,
    key_hex: &str,
) -> Result<Vec<u8>> {
    let salsa = XSalsa20Poly1305::from_hex(&key_hex).context("key hex decode failed")?;
    let nonce = Nonce::from_hex(&nonce_hex).context("nonce hex decode failed")?;
    let cipher_message = decode(cipher_message_hex).context("cipher_message hex decode failed")?;

    let text = salsa
        .decrypt(&nonce, cipher_message.as_slice())
        .map_err(|e| anyhow!(e))
        .context("open_secret_box failed")?;

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn parse_secret_key__is_valid_secret_key() {
        let result =
            parse_secret_key("acf25040d90e3c73abf1c395e7262bc3b5f9b1e35b96c74dcf72faba4663e98b");

        assert!(result.is_ok());
        assert_eq!(
            "acf25040d90e3c73abf1c395e7262bc3b5f9b1e35b96c74dcf72faba4663e98b".to_owned(),
            result.unwrap()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_secret_key__key_too_short() {
        let expected =
            anyhow!("Invalid key length (62). Key must be supplied as 64 byte hex string.");

        let result =
            parse_secret_key("acf25040d90e3c73abf1c395e7262bc3b5f9b1e35b96c74dcf72faba4663e9");

        assert!(result.is_err());

        assert_eq!(result.unwrap_err().to_string(), expected.to_string());
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_secret_key__empty_str() {
        let expected =
            anyhow!("Invalid key length (0). Key must be supplied as 64 byte hex string.");

        let result = parse_secret_key("");

        assert!(result.is_err());

        assert_eq!(result.unwrap_err().to_string(), expected.to_string());
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_secret_key__odd_hex_str() {
        let expected = anyhow!("Invalid character 'z' at position 62");

        let result =
            parse_secret_key("acf25040d90e3c73abf1c395e7262bc3b5f9b1e35b96c74dcf72faba4663eeza");

        // println!("{:?}", result);

        assert!(result.is_err());

        assert_eq!(result.unwrap_err().to_string(), expected.to_string());
    }

    #[test]
    #[allow(non_snake_case)]
    fn open_secret_box__valid_result() {
        let cipher_message_hex = "ada51644748daf427493a56888fc800cf05dc95a5a6275f04b75141e7df91f7aa27428070b649cbd097d19436f77c35dc9e9e85d76dea5dac2";
        let nonce_hex = "a352d1818e216951241fb49f54bc98dae66aac4a5f053af5";
        let key_hex = "18644e493574c44d9ea7c13ae62d80283bf8ff45083b8cbf7c2b62141a07000e";

        let expected: Vec<u8> = vec![
            123, 34, 110, 111, 116, 101, 95, 110, 111, 116, 101, 115, 34, 58, 34, 110, 111, 116,
            101, 34, 44, 34, 110, 111, 116, 101, 95, 116, 105, 116, 108, 101, 34, 58, 34, 78, 111,
            116, 101, 34, 125,
        ];

        let result = open_secret_box(cipher_message_hex, nonce_hex, key_hex);

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    #[allow(non_snake_case)]
    fn open_secret_box__decryption_error__wrong_key() {
        let cipher_message_hex = "ada51644748daf427493a56888fc800cf05dc95a5a6275f04b75141e7df91f7aa27428070b649cbd097d19436f77c35dc9e9e85d76dea5dac2";
        let nonce_hex = "a352d1818e216951241fb49f54bc98dae66aac4a5f053af5";
        let key_hex = "18644e493574c44d9ea7c13ae62d80283bf8ff45083b8cbf7c2b62141a070000";

        let expected = "open_secret_box failed".to_string();

        let result = open_secret_box(cipher_message_hex, nonce_hex, key_hex);

        assert!(result.is_err());

        assert_eq!(result.unwrap_err().to_string(), expected);
    }
}
