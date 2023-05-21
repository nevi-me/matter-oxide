use aes::Aes128;
use ccm::{
    aead::generic_array::GenericArray,
    consts::{U13, U16},
    Ccm,
};
use sha2::Sha256;

pub(crate) mod keypair;
pub(crate) mod sha256;
pub(crate) mod spake2p;

type AesCcm = Ccm<Aes128, U16, U13>;

// Random bytes generator
// TODO make it a drng
pub fn fill_random(out: &mut [u8]) {
    let mut rng = rfc6979::HmacDrbg::<Sha256>::new(&[], &[], &[]);
    rng.fill_bytes(out);
}

#[inline(always)]
pub fn pbkdf2_hmac(data: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(data, salt, iter as u32, key).unwrap();
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) {
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, key)
        .unwrap()
}

pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    data: &mut [u8],
    data_len: usize,
) -> usize {
    use ccm::{AeadInPlace, KeyInit};

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = AesCcm::new(key);

    let mut buffer = SliceBuffer::new(data, data_len);
    cipher
        .encrypt_in_place(nonce, associated_data, &mut buffer)
        .unwrap();
    buffer.len()
}

pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    data: &mut [u8],
) -> usize {
    use ccm::{AeadInPlace, KeyInit};

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = AesCcm::new(key);

    let mut buffer = SliceBuffer::new(data, data.len());
    cipher
        .decrypt_in_place(nonce, associated_data, &mut buffer)
        .unwrap();
    buffer.len()
}

#[derive(Debug)]
struct SliceBuffer<'a> {
    slice: &'a mut [u8],
    len: usize,
}

impl<'a> SliceBuffer<'a> {
    fn new(slice: &'a mut [u8], len: usize) -> Self {
        Self { slice, len }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl<'a> AsMut<[u8]> for SliceBuffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.slice[..self.len]
    }
}

impl<'a> AsRef<[u8]> for SliceBuffer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.slice[..self.len]
    }
}

impl<'a> ccm::aead::Buffer for SliceBuffer<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> ccm::aead::Result<()> {
        self.slice[self.len..][..other.len()].copy_from_slice(other);
        self.len += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::CRYPTO_AEAD_MIC_LENGTH_BYTES;

    use super::*;

    #[test]
    fn test_roundtrip_encryption() {
        let enc_key = hex_literal::hex!("9dd7718d0ce67d901f5f459f56195499");
        let dec_key = hex_literal::hex!("f300bd3aa66a7cc413b791ee6adb4ee8");
        let bytes = hex_literal::hex!("0502efb20100153600172402002403282404031818290324ff0118");
        let nonce = hex_literal::hex!("003ab44b3e0000000000000000");
        let header_bytes = hex_literal::hex!("050000003ab44b3e00000000000000000000000000000000");
        let encrypted = hex_literal::hex!("7a20b1b3c06f15888bcfa8cf525c664f67c9f62344c400a5d593deeb105874932d39cd449a8fbce6d82449");

        let mut payload = [bytes.to_vec(), [0u8; CRYPTO_AEAD_MIC_LENGTH_BYTES].to_vec()].concat();
        let data_len = payload.len();

        let enc1 = encrypt_in_place(
            &dec_key,
            &nonce,
            &header_bytes,
            &mut payload,
            data_len - CRYPTO_AEAD_MIC_LENGTH_BYTES,
        );
        assert_eq!(encrypted.len(), enc1);
        assert_eq!(hex::encode(&encrypted), hex::encode(&payload[..enc1]));

        let mut payload = encrypted.clone();

        let dec1 = decrypt_in_place(&dec_key, &nonce, &header_bytes, &mut payload);
        assert_eq!(bytes.len(), dec1);
        assert_eq!(&bytes[..], &payload[..dec1]);
    }
}
