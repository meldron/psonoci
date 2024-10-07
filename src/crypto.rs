use anyhow::{anyhow, Context, Result};
use hex::{decode, encode};
use rand::prelude::*;
use xsalsa20poly1305::aead::generic_array::{typenum::U24, GenericArray};
use xsalsa20poly1305::aead::Aead;
use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

pub const NONCE_LENGTH: usize = 24;
pub const SECRET_LENGTH: usize = 32;
pub const SECRET_HEX_LENGTH: usize = SECRET_LENGTH * 2;

pub trait FromHex: Sized {
    fn from_hex(bs: &str) -> Result<Self>;
}

pub type Nonce = GenericArray<u8, U24>;

impl FromHex for Nonce {
    fn from_hex(bs: &str) -> Result<Nonce> {
        let raw = decode_hex_with_length_check(bs, NONCE_LENGTH)?;

        let nonce = GenericArray::clone_from_slice(&raw);

        Ok(nonce)
    }
}

impl FromHex for XSalsa20Poly1305 {
    fn from_hex(bs: &str) -> Result<XSalsa20Poly1305> {
        let raw = decode_hex_with_length_check(bs, SECRET_LENGTH)?;

        let key = GenericArray::from_slice(&raw);

        Ok(XSalsa20Poly1305::new(key))
    }
}

fn decode_hex_with_length_check(s: &str, length: usize) -> Result<Vec<u8>> {
    let raw = decode(s)?;

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
    let salsa = XSalsa20Poly1305::from_hex(key_hex).context("key hex decode failed")?;
    let nonce = Nonce::from_hex(nonce_hex).context("nonce hex decode failed")?;
    let cipher_message = decode(cipher_message_hex).context("cipher_message hex decode failed")?;

    let text = salsa
        .decrypt(&nonce, cipher_message.as_slice())
        .map_err(|e| anyhow!(e))
        .context("open_secret_box failed")?;

    Ok(text)
}

pub fn create_nonce_hex() -> String {
    let mut rng = thread_rng();
    let mut nonce_raw = [0u8; NONCE_LENGTH];
    rng.fill(&mut nonce_raw);

    encode(nonce_raw)
}

pub fn seal_secret_box_hex(plaintext: &[u8], nonce_hex: &str, key_hex: &str) -> Result<String> {
    let salsa = XSalsa20Poly1305::from_hex(key_hex).context("key hex decode failed")?;

    let nonce = Nonce::from_hex(nonce_hex).context("nonce hex decode failed")?;

    let cipher_message = salsa
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!(e))
        .context("seal_secret_box_hex failed")?;

    let cipher_message_hex = encode(cipher_message);

    Ok(cipher_message_hex)
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
    fn seal_secret_box__valid_result() {
        let nonce_hex = "a352d1818e216951241fb49f54bc98dae66aac4a5f053af5";
        let key_hex = "18644e493574c44d9ea7c13ae62d80283bf8ff45083b8cbf7c2b62141a07000e";

        let plaintext: Vec<u8> = vec![
            123, 34, 110, 111, 116, 101, 95, 110, 111, 116, 101, 115, 34, 58, 34, 110, 111, 116,
            101, 34, 44, 34, 110, 111, 116, 101, 95, 116, 105, 116, 108, 101, 34, 58, 34, 78, 111,
            116, 101, 34, 125,
        ];

        let cipher_message_hex = "ada51644748daf427493a56888fc800cf05dc95a5a6275f04b75141e7df91f7aa27428070b649cbd097d19436f77c35dc9e9e85d76dea5dac2";

        let result = seal_secret_box_hex(&plaintext, nonce_hex, key_hex);

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), cipher_message_hex);
    }

    #[test]
    #[allow(non_snake_case)]
    fn seal_secret_box2__valid_result() {
        let nonce_hex = "5dbcc17d0d25f2eb9eaddffb6ed932911178f97f91cc4688";
        let key_hex = "acf25040d90e3c73abf1c395e7262bc3b5f9b1e35b96c74dcf72faba4663e98b";

        let plaintext: &str = r#"{"website_password_url_filter":null,"website_password_notes":null,"website_password_password":"test","website_password_username":null,"website_password_url":null,"website_password_title":"nana","application_password_notes":null,"application_password_password":null,"application_password_username":null,"application_password_title":null,"bookmark_url_filter":null,"bookmark_notes":null,"bookmark_url":null,"bookmark_title":null,"mail_gpg_own_key_private":null,"mail_gpg_own_key_public":null,"mail_gpg_own_key_name":null,"mail_gpg_own_key_email":null,"mail_gpg_own_key_title":null,"note_notes":null,"note_title":null}"#;
        let cipher_message_hex = "cf4ab94155fe497ce5ecd9d54ed8b61d730c5c0ead10f973a7973747c09827348946b333d9749c4e581b9cbc12adf7969797d3bf310b121ae20b302c63f27ab8b90da229538cb26dc8efdca4296c518e518ef52dc07ceafa71285254956034c41c2323ea86d45299a6d77a14bb95de7b38f4d9f7d51cd2fa5b7cbb8d3afbec3a72ad4c497b3d809ba2fa44ab1ee7c2c707e9a3100afe7c5c4bfd1651a21aaa875cf0e3a30f7f677bd0384f59a47cdd21ee002f59d1ea3a2daf9e6efef6828a237d1bd9966a5440a8cb860602133b7697dbf19e6f8efa3cb31fb1ef7afae594f01468a8285781d64e733b2d1aad0d52cbaaec49bc160e8ebe70ad91a89f5600fb14bf90a5389214ec300ac0625fa38760dc2ce4737d9aa4186ce20beab0e268d636dc1749d586c90270bb881bbe6f04765f23ee02424b2d3c9f255f6de14f8194ce92b442187de9a8d3531e0ba4268718f835f1da06e5c515e3fce075bb69c58b248a34dbdb564464fb5e0deca69de14088725f3dbdd0e376b46f12753bd25cba1542cf982dbb0bc37ea58602765367e30ead24ce03c0be45b8b1c0bc932cfcd9199e737d5cd934523bec34981b08947422da24c56842f8f412d06c1e79f65eb4db2ee7bc0cfb8de5c8bbc3ecc1e2919e09569718cd68dd7cd0d56c38f0c0ccfa70042e1d584c9d67f382802964e94a74a56e70180b4080f0e2fde2234650138345d1148265ac09829a97ae287b10ce8bbfcfebf1cea08adc0cc0d0d43ee4b95b262c9cef848f83cf76621f327cfbbb0d51257f4c911c15d465b2e7a10347d3dac7d73f8006be6b1c0b189c8b2ca5ca06dac193123b0a5e92829aae96558672bcac5a8762f9b7c7070f17394d1764b0057d76404b668331";

        let result = seal_secret_box_hex(plaintext.as_bytes(), nonce_hex, key_hex);

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), cipher_message_hex);
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
