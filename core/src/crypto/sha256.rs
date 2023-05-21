use hmac::Mac;
use sha2::Digest;

type HmacSha256I = hmac::Hmac<sha2::Sha256>;

#[derive(Clone)]
pub struct Sha256 {
    hasher: sha2::Sha256,
}

impl Sha256 {
    // TODO: if there's no need to hold these structs, make these free-standing functions.
    pub fn new() -> Self {
        Self {
            hasher: sha2::Sha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finish(self, digest: &mut [u8]) {
        let output = self.hasher.finalize();
        digest.copy_from_slice(output.as_slice());
    }
}

pub struct HmacSha256 {
    inner: HmacSha256I,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: HmacSha256I::new_from_slice(key).unwrap(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self, out: &mut [u8]) {
        let result = &self.inner.finalize().into_bytes()[..];
        out.clone_from_slice(result);
    }
}
