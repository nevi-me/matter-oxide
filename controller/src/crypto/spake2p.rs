use crypto_bigint::Encoding;
use crypto_bigint::U384;
use elliptic_curve::ops::*;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::Field;
use elliptic_curve::PrimeField;
use pbkdf2::pbkdf2_hmac;
use sha2::Digest;

use crate::constants::SHA256_HASH_LEN_BYTES;
use crate::constants::SPAKE2P_KEY_CONFIRM_INFO;
use crate::secure_channel::pake::CRYPTO_W_SIZE_BYTES;

use super::sha256::HmacSha256;

const MATTER_M_BIN: [u8; 65] = [
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d,
    0x20,
];
const MATTER_N_BIN: [u8; 65] = [
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb,
    0xe7,
];

enum Spake2PRole {
    Prover,
    Verifier,
}

pub struct Spake2P {
    role: Spake2PRole,
    random: p256::Scalar,
    w0: p256::Scalar,
    w1: p256::Scalar,
    m: p256::EncodedPoint,
    n: p256::EncodedPoint,
    l: p256::EncodedPoint,
    x: p256::EncodedPoint,
    y: p256::EncodedPoint,
    z: p256::EncodedPoint,
    v: p256::EncodedPoint,
}

impl Spake2P {
    pub fn new(passcode: u32, iterations: u16, salt: &[u8], is_prover: bool) -> Self {
        let mut rng = rand::thread_rng();
        let role = if is_prover {
            Spake2PRole::Prover
        } else {
            Spake2PRole::Verifier
        };
        let random = p256::Scalar::random(&mut rng);

        const P: p256::AffinePoint = p256::AffinePoint::GENERATOR;

        let m = p256::EncodedPoint::from_bytes(MATTER_M_BIN).unwrap();
        let n = p256::EncodedPoint::from_bytes(MATTER_N_BIN).unwrap();

        // Compute key share (w0, w1)
        let mut w0w1 = [0; CRYPTO_W_SIZE_BYTES * 2];
        pbkdf2_hmac::<sha2::Sha256>(&passcode.to_le_bytes(), salt, iterations as u32, &mut w0w1);

        let (w0, w1) = w0w1.split_at(CRYPTO_W_SIZE_BYTES);
        let w0 = Self::compute_w_scalar(w0);
        let w1 = Self::compute_w_scalar(w1);
        let l = (p256::AffinePoint::GENERATOR * w1).to_encoded_point(false);

        // Compute x (pA)
        let (x, y) = if is_prover {
            let m_affine = p256::AffinePoint::from_encoded_point(&m).unwrap();
            let x = Self::do_add_mul(P, random, m_affine, w0);
            let y = p256::EncodedPoint::default();
            (x, y)
        } else {
            let n_affine = p256::AffinePoint::from_encoded_point(&n).unwrap();
            let x = p256::EncodedPoint::default();
            let y = Self::do_add_mul(P, random, n_affine, w0);
            (x, y)
        };

        Self {
            role,
            random,
            w0,
            w1,
            m,
            n,
            l,
            x,
            y,
            z: p256::EncodedPoint::default(),
            v: p256::EncodedPoint::default(),
        }
    }

    pub fn our_key_share(&self) -> &[u8] {
        match &self.role {
            Spake2PRole::Prover => self.x.as_bytes(),
            Spake2PRole::Verifier => self.y.as_bytes(),
        }
    }

    pub fn compute_peer_key_share(&mut self, xy: &[u8]) {
        // This is either pA or pB depending on role
        // TODO: verify value
        let value = p256::EncodedPoint::from_bytes(xy).unwrap();

        // We follow matter-rs, which follows the C++ impl
        match self.role {
            Spake2PRole::Prover => {
                self.y = value;
                let tmp = self.random * self.w0;
                let n_neg = p256::AffinePoint::from_encoded_point(&self.n)
                    .unwrap()
                    .neg();
                let y = p256::AffinePoint::from_encoded_point(&value).unwrap();
                self.z = Self::do_add_mul(y, self.random, n_neg, tmp);
                self.v = Self::do_add_mul(y, self.w1, n_neg, self.w0 * self.w1);
            }
            Spake2PRole::Verifier => {
                let tmp = self.random * self.w0;
                let m_neg = p256::AffinePoint::from_encoded_point(&self.m)
                    .unwrap()
                    .neg();
                let l = p256::AffinePoint::from_encoded_point(&self.l).unwrap();
                let x = p256::AffinePoint::from_encoded_point(&value).unwrap();
                self.z = Self::do_add_mul(x, self.random, m_neg, tmp);
                self.v = (l * self.random).to_encoded_point(false);
            }
        }
    }

    pub fn compute_key_schedule(
        &mut self,
        context: &[u8],
        k_e: &mut [u8],
        c_a: &mut [u8],
        c_b: &mut [u8],
    ) {
        let mut hasher = sha2::Sha256::new();
        Self::add_to_tt(&mut hasher, context);
        Self::add_to_tt(&mut hasher, &[]);
        Self::add_to_tt(&mut hasher, &[]);
        Self::add_to_tt(&mut hasher, &MATTER_M_BIN);
        Self::add_to_tt(&mut hasher, &MATTER_N_BIN);
        Self::add_to_tt(&mut hasher, self.x.as_bytes());
        Self::add_to_tt(&mut hasher, self.y.as_bytes());
        Self::add_to_tt(&mut hasher, self.z.as_bytes());
        Self::add_to_tt(&mut hasher, self.v.as_bytes());
        Self::add_to_tt(&mut hasher, self.w0.to_bytes().as_slice());

        let hashed_transcript = hasher.finalize();

        let (ka, ke) = hashed_transcript.split_at(hashed_transcript.len() / 2);
        assert_eq!(ke.len(), k_e.len());
        k_e.copy_from_slice(ke);

        let mut kca_kcb = [0; SHA256_HASH_LEN_BYTES];
        crate::crypto::hkdf_sha256(&[], ka, &SPAKE2P_KEY_CONFIRM_INFO, &mut kca_kcb);
        let (kca, kcb) = kca_kcb.split_at(16);

        let mut mac = HmacSha256::new(kca);
        mac.update(self.y.as_bytes());
        mac.finish(c_a);

        let mut mac = HmacSha256::new(kcb);
        mac.update(self.x.as_bytes());
        mac.finish(c_b);
    }

    /// Extract W0 and W1
    fn compute_w_scalar(w: &[u8]) -> p256::Scalar {
        let operand: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut expanded = [0u8; 384 / 8];
        expanded[16..].copy_from_slice(&operand);
        let big_operand = U384::from_be_slice(&expanded);
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w);
        let big_w = U384::from_be_slice(&expanded);
        let w_res = big_w.reduce(&big_operand).unwrap();
        let mut w_out = [0u8; 32];
        w_out.copy_from_slice(&w_res.to_be_bytes()[16..]);

        p256::Scalar::from_repr(*elliptic_curve::generic_array::GenericArray::from_slice(
            &w_out,
        ))
        .unwrap()
    }
}

impl Spake2P {
    pub fn add_to_tt(tt: &mut sha2::Sha256, buf: &[u8]) {
        tt.update((buf.len() as u64).to_le_bytes());
        if !buf.is_empty() {
            tt.update(buf);
        }
    }

    #[inline(always)]
    fn do_add_mul(
        a: p256::AffinePoint,
        b: p256::Scalar,
        c: p256::AffinePoint,
        d: p256::Scalar,
    ) -> p256::EncodedPoint {
        ((a * b) + (c * d)).to_encoded_point(false)
    }
}
