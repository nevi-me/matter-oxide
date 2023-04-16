#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// #![cfg_attr(no_std, allow(unused))]
#![allow(unused)]
#![allow(clippy::all)]
#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use bytes::BytesMut;
use exchange::ExchangeManager;
use message::{Message, SessionType};
use secure_channel::pake::{PAKEInteraction, Pake2};
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use transport::udp::{SocketAddress, UdpInterface};

use crate::{
    crypto::fill_random,
    message::status_report::{GeneralCode, StatusReport},
    session_context::{SecureChannelProtocolID, SecureSessionContext},
};

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
    fabric: (),
    nodes: Vec<()>,
    last_node_id: i64,
    pake_session_ids: HashSet<u16>,
    exchange_manager: ExchangeManager,
    message_sender: Sender<(Message, SocketAddress)>,
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
        let (sender, receiver) = tokio::sync::mpsc::channel::<(Message, SocketAddress)>(32);
        let local_address: std::net::SocketAddr = "[::]:0".parse().unwrap();
        let local_address = SocketAddress::from_std(&local_address);
        let udp = UdpInterface::new(local_address).await;
        let controller = Self {
            fabric: (),
            nodes: vec![],
            last_node_id: 0,
            pake_session_ids: HashSet::with_capacity(32),
            exchange_manager: ExchangeManager::new(),
            message_sender: sender,
            udp,
            message_store: Arc::new(RwLock::new(HashMap::with_capacity(64))),
        };
        // TODO: this compiles, we should return the handle
        controller.start(receiver).await;
        // println!("Controller started");
        controller
    }

    pub async fn start(&self, receiver: Receiver<(Message, SocketAddress)>) -> JoinHandle<()> {
        let recv_socket = self.udp.socket();
        let message_store = self.message_store.clone();

        let udp = self.udp.clone();

        tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some((message, recipient)) = receiver.recv().await {
                let mut buf = BytesMut::with_capacity(1024);
                message.encode(&mut buf, None);
                let buf = buf.to_vec();
                // println!("Sending message to {recipient}");
                udp.send_to(&buf, recipient).await;
            }
            // println!("Receiver stopped receiving messages")
        });

        // Spawn a task to receive messages and process them
        tokio::spawn(async move {
            loop {
                // TODO: reset and reuse
                let mut buf = [0u8; 1024];
                let (len, peer) = recv_socket.recv_from(&mut buf).await.unwrap();
                // Decode the message but not decrypt it
                // println!("Received from {peer} {}", hex::encode(&buf[..len]));
                let mut message = Message::decode(&buf[..len]);
                // TODO don't decrypt here, using it to test
                message.decrypt(None);
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
        remote_address: SocketAddress,
        discriminator: u8,
        pin: u32,
    ) {
        // println!("Commission with PIN");
        /*
        How do we send and receive simultaneously? We want MRP built in, so for each stage of commissioning,
        we would want to be able to retry sending until we get an ack. Then after processing, move to the
        next stage of the process. This would require running 2 tasks, one to receive and update state, and
        another to send. Let's try it and fix as we go along.
         */
        // TODO: Use a simple RNG
        let mut buf = [0; 2];
        fill_random(&mut buf);

        let mut message_counter = [0; 4];
        fill_random(&mut message_counter);
        let message_counter = u32::from_le_bytes(message_counter);

        // TODO: move obtaining session IDs to the exchange manager.
        //       if there are multiple fabrics, we have to scope this to individual fabrics.
        let mut session_id = u16::from_le_bytes(buf);
        while self.pake_session_ids.contains(&session_id) {
            session_id += 1;
        }
        let session_type = SessionType::UnsecuredSession;
        let exchange_id = self.exchange_manager.new_exchange_unsecured(session_id);
        let mut pake_interaction =
            PAKEInteraction::initiator(pin, session_id, exchange_id, message_counter);
        // TODO: set pbkdf params if known

        // Send param request
        let request_message = {
            let exchange = self.exchange_manager.find_exchange(exchange_id);
            pake_interaction.pbkdf_param_request(exchange.unsecured_session_context_mut())
        };
        self.message_sender
            .send((request_message, remote_address.clone()))
            .await
            .unwrap();
        let response_message = self.wait_for_message(0, session_type).await;
        // response_message.decrypt(None);
        let next_ack = response_message.next_ack();

        let peer_session_id = response_message.message_header.session_id;
        pake_interaction.set_pbkdf_param_response(
            heapless::Vec::from_slice(response_message.payload.as_slice()).unwrap(),
        );
        let mut pake1_message = {
            let exchange = self.exchange_manager.find_exchange(exchange_id);
            pake_interaction.pake1(exchange.unsecured_session_context_mut())
        };
        // Acknowledge previous response
        pake1_message.with_ack(next_ack);
        self.message_sender
            .send((pake1_message, remote_address.clone()))
            .await
            .unwrap();
        let mut pake2_message = self.wait_for_message(0, session_type).await;
        // pake2_message.decrypt(None);
        let next_ack = pake2_message.next_ack();
        let pake2 = Pake2::from_tlv(&pake2_message.payload);
        let mut pake3_message = pake_interaction.pake3(&pake2);
        pake3_message.with_ack(next_ack);
        self.message_sender
            .send((pake3_message, remote_address.clone()))
            .await
            .unwrap();
        let pake_finished_message = self.wait_for_message(0, session_type).await;
        let next_ack = pake_finished_message.next_ack();

        // Check that commissioning is successful
        let payload_header = pake_finished_message.payload_header.as_ref().unwrap();
        assert_eq!(
            payload_header.protocol_opcode,
            SecureChannelProtocolID::StatusReport as u8
        );
        let status_report = StatusReport::from_payload(&pake_finished_message.payload);
        assert_eq!(status_report.general_code, GeneralCode::Success);

        // Get secrets
        let (k_e, c_a, c_b) = pake_interaction.get_secrets();

        // Create a new secured session
        let mut secured_session =
            SecureSessionContext::new_pase(true, false, session_id, peer_session_id, k_e, &[]);
        drop(pake_interaction);

        // Send standalone ack for now, then work on the interaction client
        // ack();

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
            // println!("Checking for message with key {key:?}");
            let has_key = {
                let reader = self.message_store.read().await;
                // println!("There are {} messages", reader.len());
                // println!("{:?}", reader.keys());
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

    // fn get_or_generate_keypair() -> Result<KeyPair, ()> {
    //     let path = "fabric_keypair.json";
    //     let exists = std::fs::metadata(path).is_ok();
    //     if exists {
    //         let keypair_file = std::fs::File::open(path).unwrap();
    //         let data: KeyPairStorage = serde_json::from_reader(keypair_file).unwrap();
    //         let keypair = KeyPair::new_from_components(&data.public, &data.private).unwrap();
    //         Ok(keypair)
    //     } else {
    //         let keypair = KeyPair::new().map_err(|e| {
    //             e// println!("Unable to generate keypair: {e:?}");
    //         })?;
    //         // Persist it
    //         let mut private_key = [0u8; 64];
    //         let mut public_key = [0u8; 32];
    //         let keypair_file = std::fs::File::create(path).unwrap();
    //         let len = keypair.get_private_key(&mut private_key).unwrap();
    //         assert_eq!(len, private_key.len());
    //         let len = keypair.get_public_key(&mut public_key).unwrap();
    //         assert_eq!(len, public_key.len());
    //         serde_json::to_writer(
    //             keypair_file,
    //             &KeyPairStorage {
    //                 private: private_key.to_vec(),
    //                 public: public_key.to_vec(),
    //             },
    //         )
    //         .unwrap();
    //         Ok(keypair)
    //     }
    // }
}

// #[derive(serde::Serialize, serde::Deserialize)]
// struct KeyPairStorage {
//     private: Vec<u8>,
//     public: Vec<u8>,
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "used for manual testing only"]
    async fn test_commissioning() {
        let mut controller = MatterController::new().await;
        let remote_address = "[::ffff:192.168.101.172]:5540"
            .parse::<std::net::SocketAddr>()
            .unwrap();
        controller
            .commission_with_pin(SocketAddress::from_std(&remote_address), 250, 123456)
            .await;
    }
}
