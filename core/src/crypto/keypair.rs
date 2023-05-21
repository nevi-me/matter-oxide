use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    AffinePoint, EncodedPoint, PublicKey, SecretKey,
};
use x509_cert::{
    attr::AttributeType,
    der::{asn1::BitString, Any, Encode},
    name::RdnSequence,
    request::CertReq,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned},
};

use crate::constants::*;

pub enum KeyType {
    Private(SecretKey),
    Public(PublicKey),
}

pub struct KeyPair {
    key: KeyType,
}

impl KeyPair {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let secret_key = SecretKey::random(&mut rng);

        Self {
            key: KeyType::Private(secret_key),
        }
    }

    pub fn new_from_components(pub_key: &[u8], priv_key: &[u8]) -> Self {
        let secret_key = SecretKey::from_slice(priv_key).unwrap();
        let encoded_point = EncodedPoint::from_bytes(pub_key).unwrap();
        let public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();
        assert_eq!(public_key, secret_key.public_key());

        Self {
            key: KeyType::Private(secret_key),
        }
    }

    pub fn new_from_public(pub_key: &[u8]) -> Self {
        let encoded_point = EncodedPoint::from_bytes(pub_key).unwrap();
        Self {
            key: KeyType::Public(PublicKey::from_encoded_point(&encoded_point).unwrap()),
        }
    }

    fn public_key_point(&self) -> AffinePoint {
        match &self.key {
            KeyType::Private(k) => *(k.public_key().as_affine()),
            KeyType::Public(k) => *(k.as_affine()),
        }
    }

    fn private_key(&self) -> &SecretKey {
        match &self.key {
            KeyType::Private(key) => key,
            KeyType::Public(_) => panic!(),
        }
    }
}

impl KeyPair {
    fn get_private_key(&self, priv_key: &mut [u8]) -> usize {
        match &self.key {
            KeyType::Private(key) => {
                let bytes = key.to_bytes();
                let slice = bytes.as_slice();
                let len = slice.len();
                priv_key.copy_from_slice(slice);
                len
            }
            KeyType::Public(_) => panic!(),
        }
    }
    fn get_csr<'a>(&self, out_csr: &'a mut [u8]) -> &'a [u8] {
        use p256::ecdsa::signature::Signer;

        let subject = RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(
            vec![x509_cert::attr::AttributeTypeAndValue {
                // Organization name: http://www.oid-info.com/get/2.5.4.10
                oid: x509_cert::attr::AttributeType::new_unwrap("2.5.4.10"),
                value: x509_cert::attr::AttributeValue::new(
                    x509_cert::der::Tag::Utf8String,
                    "CSR".as_bytes(),
                )
                .unwrap(),
            }]
            .try_into()
            .unwrap(),
        )]);
        let mut pubkey = [0; 65];
        self.get_public_key(&mut pubkey);
        let info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject,
            public_key: SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifier {
                    // ecPublicKey(1) http://www.oid-info.com/get/1.2.840.10045.2.1
                    oid: AttributeType::new_unwrap("1.2.840.10045.2.1"),
                    parameters: Some(
                        Any::new(
                            x509_cert::der::Tag::ObjectIdentifier,
                            // prime256v1 http://www.oid-info.com/get/1.2.840.10045.3.1.7
                            AttributeType::new_unwrap("1.2.840.10045.3.1.7").as_bytes(),
                        )
                        .unwrap(),
                    ),
                },
                subject_public_key: BitString::from_bytes(&pubkey).unwrap(),
            },
            attributes: Default::default(),
        };
        let mut message = vec![];
        info.encode(&mut message).unwrap();

        // Can't use self.sign_msg as the signature has to be in DER format
        let private_key = self.private_key();
        let signing_key = SigningKey::from(private_key);
        let sig: Signature = signing_key.sign(&message);
        let to_der = sig.to_der();
        let signature = to_der.as_bytes();

        let cert = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                // ecdsa-with-SHA256(2) http://www.oid-info.com/get/1.2.840.10045.4.3.2
                oid: AttributeType::new_unwrap("1.2.840.10045.4.3.2"),
                parameters: None,
            },
            signature: BitString::from_bytes(signature).unwrap(),
        };
        let out = cert.to_der().unwrap();
        let a = &mut out_csr[0..out.len()];
        a.copy_from_slice(&out);

        a
    }
    fn get_public_key(&self, pub_key: &mut [u8]) -> usize {
        let point = self.public_key_point().to_encoded_point(false);
        let bytes = point.as_bytes();
        let len = bytes.len();
        pub_key[..len].copy_from_slice(bytes);
        len
    }
    fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> usize {
        let encoded_point = EncodedPoint::from_bytes(peer_pub_key).unwrap();
        let peer_pubkey = PublicKey::from_encoded_point(&encoded_point).unwrap();
        let private_key = self.private_key();
        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            private_key.to_nonzero_scalar(),
            peer_pubkey.as_affine(),
        );
        let bytes = shared_secret.raw_secret_bytes();
        let bytes = bytes.as_slice();
        let len = bytes.len();
        assert_eq!(secret.len(), len);
        secret.copy_from_slice(bytes);

        len
    }
    fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> usize {
        use p256::ecdsa::signature::Signer;

        if signature.len() < EC_SIGNATURE_LEN_BYTES {
            panic!("No space");
        }

        match &self.key {
            KeyType::Private(k) => {
                let signing_key = SigningKey::from(k);
                let sig: Signature = signing_key.sign(msg);
                let bytes = sig.to_bytes().to_vec();
                let len = bytes.len();
                signature[..len].copy_from_slice(&bytes);
                len
            }
            KeyType::Public(_) => todo!(),
        }
    }
    fn verify_msg(&self, msg: &[u8], signature: &[u8]) {
        use p256::ecdsa::signature::Verifier;

        let verifying_key = VerifyingKey::from_affine(self.public_key_point()).unwrap();
        let signature = Signature::try_from(signature).unwrap();

        verifying_key.verify(msg, &signature).unwrap();
    }
}
