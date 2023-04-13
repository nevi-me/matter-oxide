use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use exchange::ExchangeManager;
use matter::{
    crypto::{CryptoKeyPair, KeyPair},
    fabric::Fabric,
};
use message::{Message, SessionType};
use secure_channel::pake::{PAKEInteraction, PBKDFParamResponse, PBKDFParams, Pake2};
use tokio::{
    sync::{mpsc::Sender, RwLock},
    task::JoinHandle,
};
use transport::udp::UdpInterface;

#[macro_use]
extern crate num_derive;
extern crate alloc;

/// Cluster definitions, servers and clients
pub mod cluster;
pub mod constants;
mod crypto;
pub mod data_model;
pub mod exchange;
pub mod interaction_model;
pub mod message;
pub mod root_cert_manager;
pub mod secure_channel;
pub mod session_context;
mod tlv;
pub mod transport;
pub mod util;

pub type TlvAnyData = heapless::Vec<u8, 1024>;

// TODO: rename to something more appropriate
pub struct MatterController {
    fabric: Fabric,
    nodes: Vec<()>,
    last_node_id: i64,
    pake_session_ids: HashSet<u16>,
    exchange_manager: ExchangeManager,
    message_sender: Sender<Message>,
    udp: UdpInterface,
    message_store: Arc<RwLock<HashMap<(u16, SessionType), Message>>>,
}

impl MatterController {
    pub async fn new() -> Self {
        // let keypair = Self::get_or_generate_keypair().unwrap();
        // let fabric = Fabric::new(
        //     keypair, (), None, (), &[], 1
        // ).unwrap();

        // Session Manager
        // Channel Manager creates channels to nodes and caches them
        // Exchange Manager mostly receives messages from channels
        // PaseClient initiates pairing
        // CaseClient does same

        /*
        What if the matter controller owns the message channel, hands off the receiver
        to the exchange, and then polls at its level, sending messages appropriately?
        That isolates running the loop in one place, here.
         */
        let (sender, receiver) = tokio::sync::mpsc::channel::<Message>(32);
        let local_address = "[::]:0".parse().unwrap();
        let udp = UdpInterface::new(local_address).await;
        let controller = Self {
            fabric: Fabric::dummy().unwrap(),
            nodes: vec![],
            last_node_id: 0,
            pake_session_ids: HashSet::with_capacity(32),
            exchange_manager: ExchangeManager::new(receiver),
            message_sender: sender,
            udp,
            message_store: Arc::new(RwLock::new(HashMap::with_capacity(64))),
        };
        // TODO: this compiles, we should return the handle
        controller.start().await;
        controller
    }

    pub async fn start(&self) -> JoinHandle<()> {
        let recv_socket = self.udp.socket();
        let message_store = self.message_store.clone();

        // Spawn a task to receive messages and process them
        tokio::spawn(async move {
            loop {
                // TODO: reset and reuse
                let mut buf = [0u8; 1024];
                let (len, peer) = recv_socket.recv_from(&mut buf).await.unwrap();
                // Decode the message but not decrypt it
                let message = Message::decode(&buf[..len]);
                let key = (
                    message.message_header.session_id,
                    message.message_header.session_type,
                );
                let mut writer = message_store.write().await;
                writer.insert(key, message);
                drop(writer);
                // tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
        })
    }

    /// Commission a device with a PIN, creating a new session and interacting with
    /// the remote node until the process is completed or fails
    pub async fn commission_with_pin(
        &mut self,
        remote_address: SocketAddr,
        discriminator: u8,
        pin: u64,
    ) {
        /*
        How do we send and receive simultaneously? We want MRP built in, so for each stage of commissioning,
        we would want to be able to retry sending until we get an ack. Then after processing, move to the
        next stage of the process. This would require running 2 tasks, one to receive and update state, and
        another to send. Let's try it and fix as we go along.
         */
        // TODO: Use a simple RNG
        let mut buf = [0; 2];
        crate::crypto::fill_random(&mut buf);
        // TODO: move obtaining session IDs to the exchange manager.
        //       if there are multiple fabrics, we have to scope this to individual fabrics.
        let mut session_id = u16::from_le_bytes(buf);
        while self.pake_session_ids.contains(&session_id) {
            session_id += 1;
        }
        let session_type = SessionType::UnsecuredSession;
        let mut pake_interaction = PAKEInteraction::initiator(session_id);
        // TODO: set pbkdf params if known

        let exchange_id = self.exchange_manager.new_exchange(session_id);

        // Send param request
        let request_message = {
            let exchange = self.exchange_manager.find_exchange(exchange_id);
            pake_interaction.pbkdf_param_request(exchange.unsecured_session_context_mut())
        };
        self.message_sender.send(request_message).await.unwrap();
        let mut response_message = self.wait_for_message(session_id, session_type).await;
        response_message.decrypt(None);
        let pbkdf_param_response = PBKDFParamResponse::from_tlv(&response_message.payload);
        let pake1_message = {
            let exchange = self.exchange_manager.find_exchange(exchange_id);
            pake_interaction.pake1(
                exchange.unsecured_session_context_mut(),
                &pbkdf_param_response,
            )
        };
        self.message_sender.send(pake1_message).await.unwrap();
        let mut pake2_message = self.wait_for_message(session_id, session_type).await;
        pake2_message.decrypt(None);
        let pake2 = Pake2::from_tlv(&pake2_message.payload);
        let pake3_message = pake_interaction.pake3(&pake2);
        self.message_sender.send(pake3_message).await.unwrap();
        let pake_finished_message = self.wait_for_message(session_id, session_type).await;

        // Compute session encryption keys
        let (encryption_key, rest) = [0u8; 32 * 3].split_at(32);
        let (decryption_key, attestation_challenge) = rest.split_at(32);

        /*
        How do we know when we've received a message that's moved the processing forward?
        Whatever can be mutated by the exchange should probably be owned by it, right?
        The PAKE interaction is a good candidate.
        As there are 4 kinds of sessions, is it possible to have the exchange own them?
         */

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

    async fn wait_for_message(&mut self, session_id: u16, session_type: SessionType) -> Message {
        let key = (session_id, session_type);
        loop {
            // Check if there is a message
            let has_key = {
                let reader = self.message_store.read().await;
                reader.contains_key(&key)
            };
            if has_key {
                let mut writer = self.message_store.write().await;
                let message = writer.remove(&key).unwrap();
                return message;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_commissioning() {
        let mut controller = MatterController::new().await;
        let remote_address = "[fdf5:c816:9a31:0:14de:f8f3:b5aa:f677]:5540"
            .parse()
            .unwrap();
        controller
            .commission_with_pin(remote_address, 250, 123456)
            .await;
    }
}
