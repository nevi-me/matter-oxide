use std::collections::HashMap;

use tokio::sync::mpsc::Receiver;

use crate::{
    message::{ExchangeFlags, Message, MessageFlags, SecurityFlags, SessionID, SessionType},
    session_context::{
        SecureSessionContext, SecureSessionType, SessionContext, SessionManager, SessionRole,
        UnsecuredSessionContext,
    },
};

pub struct ExchangeManager {
    exchanges: HashMap<u16, Exchange>,
    session_manager: SessionManager,
}

#[derive(Debug)]
pub struct Exchange {
    exchange_id: u16,
    exchange_role: ExchangeRole,
    session_id: u16,
    /// Message Counters (4.5.5)
    message_counter: MessageCounter,
    acknowledgements: (),
    retransmissions: (),
}

#[derive(PartialEq, Eq, Debug)]
pub enum ExchangeRole {
    Initiator,
    Responder,
}

/*
We move encryption and decryption down to another level,
where messages get ecrypted and decrypted before they're sent up
to the exchange layer. That means that the exchange also can't handle
networking, unless the encryption layer just returns bytes in exchange
for messages, and the inverse.

TCP messages will always come as bytes, so those can come through a polled IP
interface.

This still doesn't address how messages will be sent back to the messaging layer.
But then what if the messaging layer isn't a separate layer?
Each exchange could handle its messages
 */

impl ExchangeManager {
    pub fn new() -> Self {
        Self {
            exchanges: HashMap::with_capacity(32),
            session_manager: SessionManager::new(),
        }
    }

    /// Create a new exchange and return its Exchange ID and Session ID
    pub fn new_initiator_exchange_unsecured(&mut self) -> (u16, SessionID) {
        let session_id = self.session_manager.next_session_id();
        let session_context = SessionContext::Unsecured(UnsecuredSessionContext {
            session_role: SessionRole::Initiator,
            local_session_id: session_id,
            peer_session_id: 0,
            ephemeral_initiator_node_id: 0,
            message_reception_state: (),
            // local_message_counter: 10001,
            // message_reception_state: (),
            // local_fabric_index: 1,
            // peer_node_id: 1,
            // resumption_id: 1,
            // session_timestamp: 0,
            // active_timestamp: 0,
        });
        self.session_manager.add_session(session_context, false);

        // TODO: replace this with a single call to create an initiator exchange
        let exchange = Exchange::initiator(session_id);
        let exchange_id = exchange.exchange_id;
        self.exchanges.insert(exchange_id, exchange);
        (exchange_id, session_id)
    }

    pub fn new_responder_exchange_unsecured(&mut self, message: &Message) -> (u16, SessionID) {
        let session_id = message.message_header.session_id;
        let session_context = SessionContext::Unsecured(UnsecuredSessionContext {
            session_role: SessionRole::Responder,
            local_session_id: session_id,
            peer_session_id: message.message_header.session_id,
            ephemeral_initiator_node_id: message.message_header.source_node_id.unwrap(),
            message_reception_state: (),
            // local_message_counter: 10001,
            // message_reception_state: (),
            // local_fabric_index: 1,
            // peer_node_id: 1,
            // resumption_id: 1,
            // session_timestamp: 0,
            // active_timestamp: 0,
        });
        self.session_manager.add_session(session_context, false);

        let exchange = Exchange::responder(message);
        let exchange_id = exchange.exchange_id;
        // TODO: we use the exchange ID from the intiator, this is unsafe
        self.exchanges.insert(exchange_id, exchange);
        (exchange_id, session_id)
    }

    pub fn add_session(&mut self, session_context: SessionContext) {
        self.session_manager.add_session(session_context, false);
    }

    pub fn session_context(&self, session_id: u16) -> &SessionContext {
        &self.session_manager.get_session(session_id)
    }

    pub fn unsecured_session_context_mut(
        &mut self,
        session_id: SessionID,
    ) -> &mut UnsecuredSessionContext {
        match self.session_manager.get_session_mut(session_id) {
            SessionContext::Unsecured(context) => context,
            _ => panic!("Incorrect session type"),
        }
    }

    /// Find an exchange
    pub fn find_exchange(&mut self, exchange_id: u16) -> &mut Exchange {
        self.exchanges.get_mut(&exchange_id).unwrap()
    }

    /// Message Reception (4.6.2)
    // TODO: we need to know the type of transport the message came in,
    // as UDP would follow MRP
    pub fn receive_message(&mut self, message: &mut Message) {
        // TODO: validation checks
        let header = &message.message_header;
        if !header.message_flags.contains(MessageFlags::FORMAT_V1) {
            panic!("Invalid format");
        }
        let session_id = match &header.session_type {
            SessionType::UnsecuredSession => None,
            SessionType::SecureUnicast(session_id) => {
                if header
                    .message_flags
                    .contains(MessageFlags::DSIZ_16_BIT_GROUP_ID)
                {
                    panic!("Can't have a group ID for a unicast message");
                }
                Some(session_id)
            }
            SessionType::SecureGroup(session_id) => {
                // TODO: DSIZ shouldn't be 0 for neither group nor session
                if !header
                    .message_flags
                    .contains(MessageFlags::SOURCE_NODE_ID_PRESENT)
                {
                    panic!("Source Node ID should be present");
                }
                Some(session_id)
            }
        };
        // TODO: There can be > 1 key for group messages
        if let Some(session_id) = session_id {
            let SessionContext::Secure(session) = self.session_manager.get_session(*session_id) else {
                unreachable!();
            };
            if header.security_flags.contains(SecurityFlags::PRIVACY) {
                // TODO: privacy processing
            }
            message.decrypt(Some(&session.decryption_key[..]));
        } else {
            message.decrypt(None);
        }
        // TODO: message counter processing
        // TODO: update session timestamps

        // Message can now be processed by the next layer
        self.process_message(message);
    }

    /// Exchange Message PRocessing (4.9.5)
    /// Process a message that has already been decrypted and verified
    fn process_message(&mut self, message: &Message) {
        // Exchange Message Matching (4.9.5.1)
        /*
        Attempt to match the messge to an existing message
        Use the exchange ID of the message
        Initiator matches opposite of the exchange
            Else it's an unsolicited message, handle as such

        */
        let payload_header = message.payload_header.as_ref().unwrap();
        let exchange = self.exchanges.get(&payload_header.exchange_id);
        match exchange {
            Some(exchange) => {
                assert_eq!(exchange.session_id, message.message_header.session_id);
                let check = payload_header
                    .exchange_flags
                    .contains(ExchangeFlags::INITIATOR) as u8
                    + (exchange.exchange_role != ExchangeRole::Responder) as u8;
                assert_eq!(check, 1);
            }
            None if payload_header
                .exchange_flags
                .contains(ExchangeFlags::INITIATOR) =>
            {
                // Unsolicited message (4.9.5.2)
                // TODO: Should not have a duplicate counter
                // TODO: has to have a registered protocol ID
                assert!(payload_header.protocol_id < 0x0005);

                let (_exchange_id, _session_id) = self.new_responder_exchange_unsecured(message);
            }
            None => {
                // TODO: Create an ephemeral exchange, acknowledge the message and don't process further
            }
        }
    }
}

impl Exchange {
    pub fn initiator(session_id: u16) -> Self {
        let mut exchange_id = [0u8; 2];
        crate::crypto::fill_random(&mut exchange_id);
        let exchange_id = u16::from_le_bytes(exchange_id);

        Self {
            exchange_id,
            exchange_role: ExchangeRole::Initiator,
            session_id,
            message_counter: MessageCounter::new(),
            acknowledgements: (),
            retransmissions: (),
            // receiver: todo!(),
        }
    }

    pub fn responder(message: &Message) -> Self {
        Self {
            exchange_id: message.payload_header.as_ref().unwrap().exchange_id,
            exchange_role: ExchangeRole::Responder,
            session_id: message.message_header.session_id,
            message_counter: MessageCounter::new(),
            acknowledgements: (),
            retransmissions: (),
        }
    }
}

pub struct RetransmissionTable {
    message: Vec<u8>,
    message_counter: u32,
    send_count: usize,
    retrans_timeout_counter: usize,
}

pub struct AcknowledgementTable {
    message_counter: u32,
    standalone_ack_sent: bool,
}

#[derive(Debug)]
pub struct MessageCounter {
    unsecured_session: u32,
    secure_unicast_session: u32,
    group_data_counter: u32,
    group_control_counter: u32,
}

impl MessageCounter {
    pub fn new() -> Self {
        Self {
            unsecured_session: 1,
            secure_unicast_session: 1,
            group_data_counter: 1,
            group_control_counter: 1,
        }
    }
}
