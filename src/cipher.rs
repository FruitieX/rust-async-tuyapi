use aes::cipher::block_padding::Pkcs7;
use aes_gcm::{
    aead::{consts::U12, AeadInPlace},
    Aes128Gcm, KeyInit as AeadKeyInit, Nonce, Tag,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ErrorKind;
use crate::mesparse::TuyaVersion;
use crate::Result;

/// TuyaCipher is a low level api for encrypting and decrypting Vec<u8>'s.
#[derive(Clone)]
pub(crate) struct TuyaCipher {
    key: Vec<u8>,
    version: TuyaVersion,
}

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

fn maybe_strip_header(version: &TuyaVersion, data: &[u8]) -> Vec<u8> {
    if data.len() > 3 && &data[..3] == version.as_bytes() {
        match version {
            TuyaVersion::ThreeOne => data.split_at(19).1.to_vec(),
            TuyaVersion::ThreeThree | TuyaVersion::ThreeFour | TuyaVersion::ThreeFive => {
                data.split_at(15).1.to_vec()
            }
        }
    } else {
        data.to_vec()
    }
}

impl TuyaCipher {
    pub fn create(key: &[u8], version: TuyaVersion) -> TuyaCipher {
        TuyaCipher {
            key: key.to_vec(),
            version,
        }
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = key
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        use aes::cipher::{BlockEncryptMut, KeyInit};

        if self.version == TuyaVersion::ThreeFive {
            return self.encrypt_gcm_with_random_iv(data, None);
        }

        let ct = Aes128EcbEnc::new_from_slice(self.key.as_slice())?
            .encrypt_padded_vec_mut::<Pkcs7>(data);

        match self.version {
            TuyaVersion::ThreeOne => Ok(base64::engine::general_purpose::STANDARD
                .encode(ct)
                .as_bytes()
                .to_vec()),
            TuyaVersion::ThreeThree | TuyaVersion::ThreeFour | TuyaVersion::ThreeFive => {
                Ok(ct.to_vec())
            }
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        use aes::cipher::{BlockDecryptMut, KeyInit};

        if self.version == TuyaVersion::ThreeFive {
            return self.decrypt_gcm_packet(data);
        }

        // Different header size in version 3.1 and 3.3
        let data = maybe_strip_header(&self.version, data);

        // 3.1 is base64 encoded, 3.3 is not
        let data = match self.version {
            TuyaVersion::ThreeOne => base64::engine::general_purpose::STANDARD.decode(&data)?,
            TuyaVersion::ThreeThree | TuyaVersion::ThreeFour | TuyaVersion::ThreeFive => {
                data.to_vec()
            }
        };

        let pt = Aes128EcbDec::new_from_slice(self.key.as_slice())?
            .decrypt_padded_vec_mut::<Pkcs7>(&data)?;

        Ok(pt.to_vec())
    }

    pub fn md5(&self, payload: &[u8]) -> Vec<u8> {
        let hash_line: Vec<u8> = [
            b"data=",
            payload,
            b"||lpv=",
            self.version.as_bytes(),
            b"||",
            self.key.as_ref(),
        ]
        .iter()
        .flat_map(|bytes| bytes.iter())
        .copied()
        .collect();
        let digest: [u8; 16] = md5::compute(hash_line).into();
        digest[4..16].to_vec()
    }

    pub fn hmac(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key)?;
        mac.update(payload);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    pub fn encrypt_gcm_with_iv(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = self.gcm_cipher()?;
        let nonce = Self::nonce_from_iv(iv)?;
        let mut buffer = data.to_vec();
        let _tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buffer)
            .map_err(|_| ErrorKind::CipherError("aes-gcm encryption failed"))?;
        Ok(buffer)
    }

    pub fn encrypt_gcm_with_random_iv(&self, data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let iv = Self::timestamp_iv();
        self.encrypt_gcm_with_aad_and_iv(data, aad.unwrap_or_default(), &iv)
    }

    pub fn encrypt_gcm_with_aad_and_iv(
        &self,
        data: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = self.gcm_cipher()?;
        let nonce = Self::nonce_from_iv(iv)?;
        let mut buffer = data.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buffer)
            .map_err(|_| ErrorKind::CipherError("aes-gcm packet encryption failed"))?;

        let mut encrypted = Vec::with_capacity(iv.len() + buffer.len() + tag.len());
        encrypted.extend_from_slice(iv);
        encrypted.extend_from_slice(&buffer);
        encrypted.extend_from_slice(&tag);
        Ok(encrypted)
    }

    pub fn decrypt_gcm_packet(&self, data: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self.decrypt_gcm_message(data)?;
        let payload = match plaintext.get(..4) {
            Some(prefix) if prefix[0..3] == [0, 0, 0] => &plaintext[4..],
            _ => plaintext.as_slice(),
        };
        Ok(self.normalize_tuya_payload(payload))
    }

    pub fn decrypt_gcm_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 42 {
            return Err(ErrorKind::ParsingIncomplete);
        }

        let header = &data[..14];
        let iv = &data[14..26];
        let tag = &data[data.len() - 16..];
        let mut ciphertext = data[26..data.len() - 16].to_vec();

        let cipher = self.gcm_cipher()?;
        let nonce = Self::nonce_from_iv(iv)?;
        let tag_bytes: [u8; 16] = tag
            .try_into()
            .map_err(|_| ErrorKind::CipherError("invalid aes-gcm tag length"))?;
        let tag: Tag = tag_bytes.into();
        cipher
            .decrypt_in_place_detached(&nonce, header, &mut ciphertext, &tag)
            .map_err(|_| ErrorKind::CipherError("aes-gcm packet decryption failed"))?;

        Ok(ciphertext)
    }

    fn normalize_tuya_payload(&self, payload: &[u8]) -> Vec<u8> {
        let payload = maybe_strip_header(&self.version, payload);
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            return payload;
        };

        let serde_json::Value::Object(mut object) = value else {
            return payload;
        };

        let time = object.remove("t");
        let Some(data) = object.remove("data") else {
            return serde_json::to_vec(&serde_json::Value::Object(object)).unwrap_or(payload);
        };

        match data {
            serde_json::Value::Object(mut inner) => {
                if let Some(time) = time {
                    inner.insert("t".to_string(), time);
                }
                serde_json::to_vec(&serde_json::Value::Object(inner)).unwrap_or(payload)
            }
            other => serde_json::to_vec(&other).unwrap_or(payload),
        }
    }

    fn gcm_cipher(&self) -> Result<Aes128Gcm> {
        Aes128Gcm::new_from_slice(self.key.as_slice())
            .map_err(|_| ErrorKind::CipherError("invalid aes-gcm key length"))
    }

    fn nonce_from_iv(iv: &[u8]) -> Result<Nonce<U12>> {
        let iv: [u8; 12] = iv
            .get(..12)
            .ok_or(ErrorKind::CipherError("invalid aes-gcm iv length"))?
            .try_into()
            .map_err(|_| ErrorKind::CipherError("invalid aes-gcm iv length"))?;
        Ok(iv.into())
    }

    fn timestamp_iv() -> [u8; 12] {
        let ticks = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().saturating_mul(10))
            .unwrap_or(0);
        let text = ticks.to_string();
        let bytes = text.as_bytes();
        let prefix = if bytes.len() >= 12 {
            &bytes[..12]
        } else {
            bytes
        };

        let mut iv = [b'0'; 12];
        let start = 12 - prefix.len();
        iv[start..].copy_from_slice(prefix);
        iv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maybe_strip_header_with_correct_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
        let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(maybe_strip_header(&cipher.version, message), expected)
    }

    #[test]
    fn maybe_strip_header_without_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(maybe_strip_header(&cipher.version, &message), message)
    }

    #[test]
    fn encrypt_message() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let data =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes();
        let result = cipher.encrypt(data).unwrap();

        let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(expected, result);
    }

    #[test]
    fn encrypt_message_without_base64_encoding() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let data =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes();
        let result = cipher.encrypt(data).unwrap();

        let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(expected, result);
    }

    #[test]
    fn decrypt_message_with_header_and_base_64_encoding() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(message).unwrap();
        assert_eq!(&expected, &decrypted);
    }

    #[test]
    fn decrypt_message_with_version_threethree() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeThree);
        let message = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        let message = base64::engine::general_purpose::STANDARD
            .decode(message)
            .unwrap();
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(&message).unwrap();
        assert_eq!(&expected, &decrypted);
        // In the case of ThreeThree version,  the boolean it does not matter. It is always NOT
        // base64 encoded.
        let decrypted = cipher.decrypt(&message).unwrap();
        assert_eq!(&expected, &decrypted);
    }

    #[test]
    fn decrypt_message_without_header_and_base64_encoding() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(message).unwrap();
        assert_eq!(&expected, &decrypted);
    }

    #[test]
    fn decrypt_message_where_payload_is_not_json() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"3.133ed3d4a21effe90rt1hJFzMJPF3x9UhPTCiXw==";
        let expected = "gw id invalid".as_bytes().to_owned();

        let decrypted = cipher.decrypt(message).unwrap();
        assert_eq!(&expected, &decrypted);
    }
}
