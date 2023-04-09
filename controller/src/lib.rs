use matter::{
    crypto::{CryptoKeyPair, KeyPair},
    fabric::Fabric,
};
use serde_json::{json, Value};

#[macro_use]
extern crate num_derive;
extern crate alloc;

/// Cluster definitions, servers and clients
pub mod cluster;
pub mod data_model;
pub mod interaction_model;
pub mod message;
pub mod root_cert_manager;
pub mod secure_channel;
pub mod transport;

pub type TlvAnyData = heapless::Vec<u8, 1024>;

// TODO: rename to something more appropriate
pub struct MatterController {
    fabric: Fabric,
    nodes: Vec<()>,
    last_node_id: i64,
}

impl MatterController {
    pub fn start_controller() -> Self {
        // let keypair = Self::get_or_generate_keypair().unwrap();
        // let fabric = Fabric::new(
        //     keypair, (), None, (), &[], 1
        // ).unwrap();

        // Session Manager
        // Channel Manager creates channels to nodes and caches them
        // Exchange Manager mostly receives messages from channels
        // PaseClient initiates pairing
        // CaseClient does same
        Self {
            fabric: Fabric::dummy().unwrap(),
            nodes: vec![],
            last_node_id: 0,
        }
    }

    pub fn commission_with_pin(
        &self,
        commissioning_address: &str,
        commissioning_port: i16,
        discriminator: u8,
        pin: i64,
    ) {
        // Open PASE channel
        // PASE pairing to get a secured channel
        // Start commissioning
        // Interaction client
        // Basic cluster client
        // Perform commissioning with a GeneralCommissioningClusterClient
        // - arm failsafe
        // - regulatory info
        // OperationalCredentialsClusterClient
    }

    fn get_or_generate_keypair() -> Result<KeyPair, ()> {
        let path = "fabric_keypair.json";
        let exists = std::fs::metadata(path).is_ok();
        if exists {
            let keypair_file = std::fs::File::open(path).unwrap();
            let data: KeyPairStorage = serde_json::from_reader(keypair_file).unwrap();
            let keypair = KeyPair::new_from_components(&data.public, &data.private).unwrap();
            Ok(keypair)
        } else {
            let keypair = KeyPair::new().map_err(|e| {
                eprintln!("Unable to generate keypair: {e:?}");
            })?;
            // Persist it
            let mut private_key = [0u8; 64];
            let mut public_key = [0u8; 32];
            let keypair_file = std::fs::File::create(path).unwrap();
            let len = keypair.get_private_key(&mut private_key).unwrap();
            assert_eq!(len, private_key.len());
            let len = keypair.get_public_key(&mut public_key).unwrap();
            assert_eq!(len, public_key.len());
            serde_json::to_writer(
                keypair_file,
                &KeyPairStorage {
                    private: private_key.to_vec(),
                    public: public_key.to_vec(),
                },
            )
            .unwrap();
            Ok(keypair)
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyPairStorage {
    private: Vec<u8>,
    public: Vec<u8>,
}
