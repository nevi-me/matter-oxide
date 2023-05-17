use std::collections::HashMap;

use tokio::sync::mpsc::Receiver;

use crate::{
    crypto::fill_random,
    message::{ExchangeFlags, Message, MessageFlags, SecurityFlags, SessionID, SessionType},
    secure_channel::MSG_COUNTER_WINDOW_SIZE,
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
    message_counter: u32,
    peer_message_counter: MessageCounter,
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
        let exchange_id = self.new_responder_exchange(message);
        self.session_manager.add_session(session_context, false);

        (exchange_id, session_id)
    }

    pub fn new_responder_exchange(&mut self, message: &Message) -> u16 {
        let exchange = Exchange::responder(message);
        let exchange_id = exchange.exchange_id;
        // TODO: we use the exchange ID from the intiator, this is unsafe
        self.exchanges.insert(exchange_id, exchange);
        exchange_id
    }

    pub fn add_session(&mut self, session_context: SessionContext) {
        self.session_manager.add_session(session_context, false);
        self.session_manager.last_session_id += 10;
    }

    pub fn session_context(&self, session_id: u16) -> Option<&SessionContext> {
        self.session_manager.get_session(session_id)
    }

    pub fn session_context_mut(&mut self, session_id: SessionID) -> &mut SessionContext {
        self.session_manager.get_session_mut(session_id)
    }

    /// Find an exchange
    pub fn find_exchange(&mut self, exchange_id: u16) -> &mut Exchange {
        println!("Looking for exchange with ID {exchange_id}");
        self.exchanges.get_mut(&exchange_id).unwrap()
    }

    /// Message Reception (4.6.2)
    // TODO: we need to know the type of transport the message came in,
    // as UDP would follow MRP
    pub fn receive_message(&mut self, message: &mut Message) -> ExchangeMessageAction {
        // TODO: validation checks
        let header = &message.message_header;
        if !header.message_flags.contains(MessageFlags::FORMAT_V1) {
            panic!("Invalid format");
        }
        match &header.session_type {
            SessionType::UnsecuredSession => {}
            SessionType::SecureUnicast(session_id) => {
                if header
                    .message_flags
                    .contains(MessageFlags::DSIZ_16_BIT_GROUP_ID)
                {
                    panic!("Can't have a group ID for a unicast message");
                }
            }
            SessionType::SecureGroup(session_id) => {
                // TODO: DSIZ shouldn't be 0 for neither group nor session
                if !header
                    .message_flags
                    .contains(MessageFlags::SOURCE_NODE_ID_PRESENT)
                {
                    panic!("Source Node ID should be present");
                }
            }
        };
        let session_id = message.message_header.session_id;
        self.session_context(session_id);
        // TODO: There can be > 1 key for group messages
        match self.session_manager.get_session(session_id) {
            Some(SessionContext::MCSP) => todo!("MCSP sessions not supported"),
            Some(SessionContext::Secure(session)) => {
                if header.security_flags.contains(SecurityFlags::PRIVACY) {
                    // TODO: privacy processing
                }
                message.decrypt(Some(&session.decryption_key[..]));
            }
            Some(SessionContext::Unsecured(_)) | None => {
                message.decrypt(None);
            }
        }

        // if let Some(session_id) = session_id {
        //     let SessionContext::Secure(session) = self.session_manager.get_session(*session_id) else {
        //         unreachable!();
        //     };

        //     message.decrypt(Some(&session.decryption_key[..]));
        // } else {
        // }
        // TODO: update session timestamps

        // Message can now be processed by the next layer
        self.process_message(message)
    }

    /// Exchange Message PRocessing (4.9.5)
    /// Process a message that has already been decrypted and verified.
    /// Return a boolean indicating whether to contine prucessing or to ignore
    /// the message.
    fn process_message(&mut self, message: &Message) -> ExchangeMessageAction {
        // Exchange Message Matching (4.9.5.1)
        /*
        Attempt to match the messge to an existing message
        Use the exchange ID of the message
        Initiator matches opposite of the exchange
            Else it's an unsolicited message, handle as such

        */
        let payload_header = message.payload_header.as_ref().unwrap();
        // dbg!((&message.message_header, payload_header));
        let exchange = self.exchanges.get_mut(&payload_header.exchange_id);
        match exchange {
            Some(exchange) => {
                assert_eq!(exchange.session_id, message.message_header.session_id);
                let check = payload_header
                    .exchange_flags
                    .contains(ExchangeFlags::INITIATOR) as u8
                    + (exchange.exchange_role != ExchangeRole::Responder) as u8;
                assert_eq!(check, 1);
                if exchange.deduplicate_message(message) {
                    ExchangeMessageAction::Drop
                } else {
                    ExchangeMessageAction::Process
                }
            }
            None if payload_header
                .exchange_flags
                .contains(ExchangeFlags::INITIATOR) =>
            {
                // Unsolicited message (4.9.5.2)
                // TODO: Should not have a duplicate counter
                // TODO: has to have a registered protocol ID
                assert!(payload_header.protocol_id < 0x0005);
                println!("Processing unsolicited message {:#?}", message);
                // A session ID might already exist, find one first
                // TODO: validate this before creating a new session (e.g. can't hijack existing session)
                match self.session_context(message.message_header.session_id) {
                    Some(_) => {
                        // Create a new exchange with the session
                        self.new_responder_exchange(message);
                    }
                    None => {
                        let (_exchange_id, _session_id) =
                            self.new_responder_exchange_unsecured(message);
                    }
                }
                // TODO: depends on the above conditions
                ExchangeMessageAction::Process
            }
            None => {
                // TODO: Create an ephemeral exchange, acknowledge the message and don't process further
                println!("Did not find exchange ID {}", payload_header.exchange_id);
                ExchangeMessageAction::AckAndDrop
            }
        }
    }
}

impl Exchange {
    pub fn initiator(session_id: u16) -> Self {
        // TODO: add a number generator util
        let mut exchange_id = [0u8; 2];
        fill_random(&mut exchange_id);
        let exchange_id = u16::from_le_bytes(exchange_id);
        let mut message_counter = [0u8; 4];
        fill_random(&mut message_counter);
        let message_counter = u32::from_le_bytes(message_counter);

        Self {
            exchange_id,
            exchange_role: ExchangeRole::Initiator,
            session_id,
            message_counter,
            peer_message_counter: MessageCounter::new(0),
            acknowledgements: (),
            retransmissions: (),
            // receiver: todo!(),
        }
    }

    pub fn responder(message: &Message) -> Self {
        let mut message_counter = [0u8; 4];
        fill_random(&mut message_counter);
        let message_counter = u32::from_le_bytes(message_counter);
        Self {
            exchange_id: message.payload_header.as_ref().unwrap().exchange_id,
            exchange_role: ExchangeRole::Responder,
            session_id: message.message_header.session_id,
            message_counter,
            peer_message_counter: MessageCounter::new(message.message_header.message_counter),
            acknowledgements: (),
            retransmissions: (),
        }
    }

    /// Generate a message counter
    // TODO: This is to make progress for now, needs to be spec compliant
    pub fn next_message_counter(&mut self) -> u32 {
        self.message_counter += 1;
        self.message_counter
    }

    /// Check for duplicates using the message counter and type of session
    pub fn deduplicate_message(&mut self, message: &Message) -> bool {
        self.peer_message_counter.process_message_counter(
            message.message_header.message_counter,
            &message.message_header.session_type,
        )
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
    max_counter: u32,
    bitmap: u32,
}

impl MessageCounter {
    pub fn new(max_counter: u32) -> Self {
        Self {
            max_counter,
            bitmap: u32::MAX,
        }
    }

    /// Process this message counter, updating the state and returning whether
    /// the message is a duplicate.
    pub fn process_message_counter(&mut self, counter: u32, session_type: &SessionType) -> bool {
        if self.max_counter == counter {
            // Duplicate, return very early
            return true;
        }
        let delta = (counter as i64 - self.max_counter as i64).abs() as u32;
        let delta_bitmap = 1u32 << delta;
        match (session_type, counter > self.max_counter) {
            // Secured messages don't allow rolling over, so the max is always higher
            (SessionType::SecureUnicast(_), false) => {
                // Check if the bitmap contains the message
                let is_duplicate = self.contains(delta_bitmap);
                if !is_duplicate {
                    self.insert(delta_bitmap);
                }
                is_duplicate
            }
            (_, true) => {
                self.max_counter = counter;
                if delta < MSG_COUNTER_WINDOW_SIZE {
                    self.bitmap <<= delta;
                    self.insert(1 << (delta - 1));
                } else {
                    self.bitmap = u32::MAX;
                }
                false
            }
            (SessionType::UnsecuredSession | SessionType::SecureGroup(_), false) => {
                self.max_counter = counter;
                self.bitmap = u32::MAX;
                false
            }
        }
    }

    fn contains(&self, delta_bitmap: u32) -> bool {
        self.bitmap & delta_bitmap != 0
    }

    fn insert(&mut self, delta_bitmap: u32) {
        self.bitmap |= delta_bitmap
    }
}

/// Helper that indicates what should be done with a message after exchange processing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExchangeMessageAction {
    /// Continue processing the message
    Process,
    /// Drop the message, either duplicate or unknown
    Drop,
    /// Acknowledge message and drop it
    AckAndDrop,
}
