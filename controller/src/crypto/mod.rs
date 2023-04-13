use sha2::Sha256;

pub(crate) mod keypair;
pub(crate) mod other;
pub(crate) mod sha256;
pub(crate) mod spake2p;

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

pub fn encrypt_in_place() {}
pub fn decrypt_in_place() {}
