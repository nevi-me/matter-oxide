use crypto_bigint::Encoding;
use crypto_bigint::U384;
use elliptic_curve::ops::*;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::Field;
use elliptic_curve::PrimeField;
use sha2::Digest;

use crate::constants::SHA256_HASH_LEN_BYTES;
use crate::constants::SPAKE2P_KEY_CONFIRM_INFO;

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

pub struct Spake2P {
    xy: p256::Scalar,
    w0: p256::Scalar,
    w1: p256::Scalar,
    m: p256::EncodedPoint,
    n: p256::EncodedPoint,
    l: p256::EncodedPoint,
    p_a: p256::EncodedPoint,
    p_b: p256::EncodedPoint,
}

impl Spake2P {
    pub fn new() -> Self {
        let m = p256::EncodedPoint::from_bytes(MATTER_M_BIN).unwrap();
        let n = p256::EncodedPoint::from_bytes(MATTER_N_BIN).unwrap();
        let l = p256::EncodedPoint::default();
        let p_a = p256::EncodedPoint::default();
        let p_b = p256::EncodedPoint::default();

        Spake2P {
            xy: p256::Scalar::ZERO,
            w0: p256::Scalar::ZERO,
            w1: p256::Scalar::ZERO,
            m,
            n,
            l,
            p_a,
            p_b,
        }
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, w0s: &[u8]) {
        // From the Matter Spec,
        //         w0 = w0s mod p
        //   where p is the order of the curve
        let operand: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut expanded = [0u8; 384 / 8];
        expanded[16..].copy_from_slice(&operand);
        let big_operand = U384::from_be_slice(&expanded);
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w0s);
        let big_w0 = U384::from_be_slice(&expanded);
        let w0_res = big_w0.reduce(&big_operand).unwrap();
        let mut w0_out = [0u8; 32];
        w0_out.copy_from_slice(&w0_res.to_be_bytes()[16..]);

        let w0s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&w0_out),
        )
        .unwrap();
        // Scalar is modulo the curve's order by definition, no further op needed
        self.w0 = w0s;
    }

    pub fn set_w1_from_w1s(&mut self, w1s: &[u8]) {
        // From the Matter Spec,
        //         w1 = w1s mod p
        //   where p is the order of the curve
        let operand: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut expanded = [0u8; 384 / 8];
        expanded[16..].copy_from_slice(&operand);
        let big_operand = U384::from_be_slice(&expanded);
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w1s);
        let big_w1 = U384::from_be_slice(&expanded);
        let w1_res = big_w1.reduce(&big_operand).unwrap();
        let mut w1_out = [0u8; 32];
        w1_out.copy_from_slice(&w1_res.to_be_bytes()[16..]);

        let w1s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&w1_out),
        )
        .unwrap();
        // Scalar is modulo the curve's order by definition, no further op needed
        self.w1 = w1s;
    }

    pub fn set_w0(&mut self, w0: &[u8]) {
        self.w0 =
            p256::Scalar::from_repr(*elliptic_curve::generic_array::GenericArray::from_slice(w0))
                .unwrap();
    }

    pub fn set_w1(&mut self, w1: &[u8]) {
        self.w1 =
            p256::Scalar::from_repr(*elliptic_curve::generic_array::GenericArray::from_slice(w1))
                .unwrap();
    }

    #[allow(dead_code)]
    pub fn set_l(&mut self, l: &[u8]) {
        self.l = p256::EncodedPoint::from_bytes(l).unwrap();
    }

    pub fn set_l_from_w1s(&mut self, w1s: &[u8]) {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        self.set_w1_from_w1s(w1s);
        self.l = (p256::AffinePoint::GENERATOR * self.w1).to_encoded_point(false);
    }

    pub fn compute_x(&mut self, x: &mut [u8]) {
        let mut rng = rand::thread_rng();
        self.xy = p256::Scalar::random(&mut rng);

        let p = p256::AffinePoint::GENERATOR;
        let m = p256::AffinePoint::from_encoded_point(&self.m).unwrap();
        self.p_a = Self::do_add_mul(p, self.xy, m, self.w0);
        let x_internal = self.p_a.as_bytes();
        x.copy_from_slice(x_internal);
    }

    pub fn compute_y(&mut self, y: &mut [u8]) {
        let mut rng = rand::thread_rng();
        self.xy = p256::Scalar::random(&mut rng);

        let p = p256::AffinePoint::GENERATOR;
        let n = p256::AffinePoint::from_encoded_point(&self.n).unwrap();
        self.p_b = Self::do_add_mul(p, self.xy, n, self.w0);
        let y_internal = self.p_b.as_bytes();
        y.copy_from_slice(y_internal);
    }

    pub fn get_x(&self) -> &[u8] {
        self.p_a.as_bytes()
    }

    fn get_tt(&self, context: &[u8], p_a: &[u8], p_b: &[u8], out: &mut [u8]) {
        let mut tt = sha2::Sha256::new();
        // Context
        Self::add_to_tt(&mut tt, context);
        // 2 empty identifiers
        // TODO: should these be 64-bit values?
        Self::add_to_tt(&mut tt, &[]);
        Self::add_to_tt(&mut tt, &[]);
        // M
        Self::add_to_tt(&mut tt, &MATTER_M_BIN);
        // N
        Self::add_to_tt(&mut tt, &MATTER_N_BIN);
        // X = pA
        Self::add_to_tt(&mut tt, p_a);
        // Y = pB
        Self::add_to_tt(&mut tt, p_b);

        let X = p256::EncodedPoint::from_bytes(p_a).unwrap();
        let X = p256::AffinePoint::from_encoded_point(&X).unwrap();
        let L = p256::AffinePoint::from_encoded_point(&self.l).unwrap();
        let M = p256::AffinePoint::from_encoded_point(&self.m).unwrap();
        let (Z, V) = Self::get_ZV_as_verifier(self.w0, L, M, X, self.xy);

        // Z
        Self::add_to_tt(&mut tt, Z.as_bytes());
        // V
        Self::add_to_tt(&mut tt, V.as_bytes());
        // w0
        Self::add_to_tt(&mut tt, self.w0.to_bytes().to_vec().as_ref());

        let h = tt.finalize();
        out.copy_from_slice(h.as_slice());
    }

    pub fn compute_p2(
        &self,
        context: &[u8],
        p_a: &[u8],
        p_b: &[u8],
        k_e: &mut [u8],
        c_a: &mut [u8],
        c_b: &mut [u8],
    ) {
        let mut tt = [0; SHA256_HASH_LEN_BYTES];
        self.get_tt(context, p_a, p_b, &mut tt);
        // Step 1: Ka || Ke = Hash(TT)
        let tt_len = tt.len();
        let (ka, ke_int) = tt.split_at(tt_len / 2);
        if ke_int.len() == k_e.len() {
            k_e.copy_from_slice(ke_int);
        } else {
            panic!("Unequal k_e lengths")
        }

        // Step 2: KcA || KcB = KDF(nil, Ka, "ConfirmationKeys")
        let mut kca_kcb: [u8; 32] = [0; 32];
        crate::crypto::hkdf_sha256(&[], ka, &SPAKE2P_KEY_CONFIRM_INFO, &mut kca_kcb);

        let (k_ca, k_cb) = kca_kcb.split_at(kca_kcb.len() / 2);

        // Step 3: cA = HMAC(KcA, pB), cB = HMAC(KcB, pA)
        let mut mac = HmacSha256::new(k_ca);
        mac.update(p_b);
        mac.finish(c_a);

        let mut mac = HmacSha256::new(k_cb);
        mac.update(p_a);
        mac.finish(c_b);
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

    #[inline(always)]
    #[allow(dead_code)]
    fn get_ZV_as_prover(
        w0: p256::Scalar,
        w1: p256::Scalar,
        N: p256::AffinePoint,
        Y: p256::AffinePoint,
        x: p256::Scalar,
    ) -> (p256::EncodedPoint, p256::EncodedPoint) {
        // As per the RFC, the operation here is:
        //   Z = h*x*(Y - w0*N)
        //   V = h*w1*(Y - w0*N)

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = x*w0
        //    Z = x*Y + tmp*N (N is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let mut tmp = x * w0;
        let N_neg = N.neg();
        let Z = Spake2P::do_add_mul(Y, x, N_neg, tmp);
        // Cofactor for P256 is 1, so that is a No-Op

        tmp = w1 * w0;
        let V = Spake2P::do_add_mul(Y, w1, N_neg, tmp);
        (Z, V)
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_verifier(
        w0: p256::Scalar,
        L: p256::AffinePoint,
        M: p256::AffinePoint,
        X: p256::AffinePoint,
        y: p256::Scalar,
    ) -> (p256::EncodedPoint, p256::EncodedPoint) {
        // As per the RFC, the operation here is:
        //   Z = h*y*(X - w0*M)
        //   V = h*y*L

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = y*w0
        //    Z = y*X + tmp*M (M is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let tmp = y * w0;
        let M_neg = M.neg();
        let Z = Spake2P::do_add_mul(X, y, M_neg, tmp);
        // Cofactor for P256 is 1, so that is a No-Op
        let V = (L * y).to_encoded_point(false);
        (Z, V)
    }
}
