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
    // This is probably incorrect
    let mut buffer = data[0..data_len].to_vec();
    cipher
        .encrypt_in_place(nonce, associated_data, &mut buffer)
        .unwrap();
    let len = buffer.len();
    data.clone_from_slice(&buffer[..]);

    len
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
    // This is probably incorrect
    let mut buffer = data.to_vec();
    cipher
        .decrypt_in_place(nonce, associated_data, &mut buffer)
        .unwrap();
    let len = buffer.len();
    data[..len].copy_from_slice(&buffer[..]);

    len
}
