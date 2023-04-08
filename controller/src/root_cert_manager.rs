use matter::crypto::KeyPair;



pub(crate) struct RootCertificateManager {
    root_cert_id: u64,
    root_keypair: KeyPair,
    root_key_identifier: [u8; 20],
    root_cert: [u8; 64], // TODO
    next_cert_id: u64,
}

impl RootCertificateManager {


    fn generate_root_cert() -> [u8; 64] {
        panic!()
    }

    pub fn generate_noc(&self, public_key: &[u8], fabric_id: i64, node_id: i64) -> &[u8] {
        panic!()
    }

    pub fn get_root_cert(&self) -> &[u8] {
        &self.root_cert
    }
}