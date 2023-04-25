use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use bytes::BytesMut;
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};

use crate::{
    cluster::utility::{
        basic_information::DeviceInformation, general_commissioning::GeneralCommissioningCluster,
    },
    crypto::fill_random,
    data_model::{
        device::{Device, Endpoint, Node},
        device_type::root_node::DEVICE_TYPE_ROOT_NODE,
        endpoint::root_endpoint,
    },
    exchange::ExchangeManager,
    message::status_report::{GeneralCode, StatusReport},
    message::{Message, SessionType},
    secure_channel::pake::{PASEManager, Pake2},
    session_context::{
        SecureChannelProtocolCode, SecureChannelProtocolID, SecureSessionContext, SessionContext,
        SessionManager,
    },
    transport::{udp::UdpInterface, SocketAddress},
};

pub type TlvAnyData = heapless::Vec<u8, 1024>;

pub struct Controller<'a, H> {
    fabric: (),
    device: Device<'a, H>,
    last_node_id: i64,
    pase_session_ids: HashSet<u16>,
    exchange_manager: ExchangeManager,
    // session_manager: SessionManager,
    message_sender: Sender<(Message, SocketAddress)>,
    udp: UdpInterface,
    // TODO: This should probably be in the exchange manager
    message_store: Arc<RwLock<HashMap<(u16, SessionType), Message>>>,
}

impl<'a, H> Controller<'a, H> {
    pub async fn new(node: &'a Node<'a>, handler: H) -> Controller<'a, H> {
        /*
        What if the matter controller owns the message channel, hands off the receiver
        to the exchange, and then polls at its level, sending messages appropriately?
        That isolates running the loop in one place, here.
         */
        let (sender, receiver) = tokio::sync::mpsc::channel::<(Message, SocketAddress)>(32);
        let local_address: std::net::SocketAddr = "0.0.0.0:5541".parse().unwrap();
        let local_address = SocketAddress::from_std(&local_address);
        let udp = UdpInterface::new(local_address).await;
        // Temporary
        udp.socket()
            .connect("127.0.0.1:5540".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let device = Device::new(node, handler);
        let controller = Controller {
            fabric: (),
            device,
            last_node_id: 0,
            pase_session_ids: HashSet::with_capacity(32),
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
                // self.exchange_manager.receive_message(&mut message);
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
        /*
        How do we send and receive simultaneously? We want MRP built in, so for each stage of commissioning,
        we would want to be able to retry sending until we get an ack. Then after processing, move to the
        next stage of the process. This would require running 2 tasks, one to receive and update state, and
        another to send. Let's try it and fix as we go along.
         */

        let mut message_counter = [0; 4];
        fill_random(&mut message_counter);
        let message_counter = u32::from_le_bytes(message_counter);

        let session_type = SessionType::UnsecuredSession;
        let (exchange_id, session_id) = self.exchange_manager.new_initiator_exchange_unsecured();
        let mut pake_interaction =
            PASEManager::initiator(pin, session_id, exchange_id, message_counter);

        // Send param request
        let request_message = {
            let session = self
                .exchange_manager
                .unsecured_session_context_mut(session_id);
            pake_interaction.pbkdf_param_request(session)
        };
        self.send_message(request_message, remote_address.clone())
            .await;
        let response_message = self.wait_for_message(0, session_type).await;
        let next_ack = response_message.next_ack();

        let peer_session_id = response_message.message_header.session_id;
        pake_interaction.set_pbkdf_param_response(
            heapless::Vec::from_slice(response_message.payload.as_slice()).unwrap(),
        );
        let mut pake1_message = {
            let session = self
                .exchange_manager
                .unsecured_session_context_mut(session_id);
            pake_interaction.pake1(session)
        };
        // Acknowledge previous response
        pake1_message.with_ack(next_ack);
        self.send_message(pake1_message, remote_address.clone())
            .await;
        let mut pake2_message = self.wait_for_message(0, session_type).await;
        // pake2_message.decrypt(None);
        let next_ack = pake2_message.next_ack();
        let pake2 = Pake2::from_tlv(&pake2_message.payload);
        let mut pake3_message = pake_interaction.pake3(&pake2);
        pake3_message.with_ack(next_ack);
        self.send_message(pake3_message, remote_address.clone())
            .await;
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
        assert_eq!(
            status_report.protocol_code,
            SecureChannelProtocolCode::SessionEstablishmentSuccess as u16
        );

        // Get secrets
        let (k_e, c_a, c_b) = pake_interaction.get_secrets();

        // Create a new secured session
        let mut secured_session =
            SecureSessionContext::new_pase(true, false, session_id, peer_session_id, k_e, &[]);
        drop(pake_interaction);

        // Send standalone ack for now, then work on the interaction client
        // ack();

        // Add session to session manager
        self.exchange_manager
            .add_session(SessionContext::Secure(secured_session));

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

    /// Wait for a message, decrypting it when found (if part of an encrypted session)
    async fn wait_for_message(&mut self, session_id: u16, session_type: SessionType) -> Message {
        let lookup_key = (session_id, session_type);
        loop {
            // Check if there is a message
            // println!("Checking for message with key {key:?}");
            let has_key = {
                let reader = self.message_store.read().await;
                // println!("There are {} messages", reader.len());
                // println!("{:?}", reader.keys());
                reader.contains_key(&lookup_key)
            };
            if has_key {
                let mut writer = self.message_store.write().await;
                let mut message = writer.remove(&lookup_key).unwrap();
                // Decrypt the message if it is secure
                match session_type {
                    SessionType::SecureUnicast(_) | SessionType::SecureGroup(_) => {
                        let SessionContext::Secure(session) = self.exchange_manager.session_context(session_id) else {
                            panic!("Session in context not a SecureSession");
                        };
                        message.decrypt(Some(&session.decryption_key));
                    }
                    _ => {}
                }
                return message;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Send a message, encrypting it if required
    async fn send_message(&mut self, mut message: Message, peer: SocketAddress) {
        // let session_context = self
        //     .exchange_manager
        //     .session_context(message.message_header.session_id);
        // match &session_context {
        //     SessionContext::MCSP => {}
        //     SessionContext::Secure(session) => {
        //         message.encrypt(&session.encryption_key);
        //     }
        //     SessionContext::Unsecured(_) => todo!(),
        // }

        // Send message
        self.message_sender.send((message, peer)).await.unwrap();
    }
}

pub type CommissioningController<'a> = Controller<'a, root_endpoint::RootEndpointHandler<'a>>;

pub async fn commission_with_pin<'a>(
    controller: &mut CommissioningController<'a>,
    remote_address: SocketAddress,
    discriminator: u8,
    pin: u32,
) -> () {
    /*
    The flaw here is that we're not using the inner layers to send responses, we want to do that.
    How do we get there?
    Let's create a commissioning client first.
     */
    let mut message_counter = [0; 4];
    fill_random(&mut message_counter);
    let message_counter = u32::from_le_bytes(message_counter);

    let session_type = SessionType::UnsecuredSession;
    let (exchange_id, session_id) = controller
        .exchange_manager
        .new_initiator_exchange_unsecured();
    let mut pake_interaction =
        PASEManager::initiator(pin, session_id, exchange_id, message_counter);

    // Send param request
    let request_message = {
        let session = controller
            .exchange_manager
            .unsecured_session_context_mut(session_id);
        pake_interaction.pbkdf_param_request(session)
    };
    controller
        .send_message(request_message, remote_address.clone())
        .await;
    let response_message = controller.wait_for_message(0, session_type).await;
    let next_ack = response_message.next_ack();

    let peer_session_id = response_message.message_header.session_id;
    pake_interaction.set_pbkdf_param_response(
        heapless::Vec::from_slice(response_message.payload.as_slice()).unwrap(),
    );
    let mut pake1_message = {
        let session = controller
            .exchange_manager
            .unsecured_session_context_mut(session_id);
        pake_interaction.pake1(session)
    };
    // Acknowledge previous response
    pake1_message.with_ack(next_ack);
    controller
        .send_message(pake1_message, remote_address.clone())
        .await;
    let mut pake2_message = controller.wait_for_message(0, session_type).await;
    // pake2_message.decrypt(None);
    let next_ack = pake2_message.next_ack();
    let pake2 = Pake2::from_tlv(&pake2_message.payload);
    let mut pake3_message = pake_interaction.pake3(&pake2);
    pake3_message.with_ack(next_ack);
    controller
        .send_message(pake3_message, remote_address.clone())
        .await;
    let pake_finished_message = controller.wait_for_message(0, session_type).await;
    let next_ack = pake_finished_message.next_ack();

    // Check that commissioning is successful
    let payload_header = pake_finished_message.payload_header.as_ref().unwrap();
    assert_eq!(
        payload_header.protocol_opcode,
        SecureChannelProtocolID::StatusReport as u8
    );
    let status_report = StatusReport::from_payload(&pake_finished_message.payload);
    assert_eq!(status_report.general_code, GeneralCode::Success);
    assert_eq!(
        status_report.protocol_code,
        SecureChannelProtocolCode::SessionEstablishmentSuccess as u16
    );

    // Get secrets
    let (k_e, c_a, c_b) = pake_interaction.get_secrets();

    // Create a new secured session
    let mut secured_session =
        SecureSessionContext::new_pase(true, false, session_id, peer_session_id, k_e, &[]);
    drop(pake_interaction);

    // Send standalone ack for now, then work on the interaction client
    // ack();

    // Add session to session manager
    controller
        .exchange_manager
        .add_session(SessionContext::Secure(secured_session));

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
