use std::collections::HashMap;

use tokio::sync::mpsc::Receiver;

use crate::{
    message::Message,
    session_context::{
        SecureSessionContext, SecureSessionType, SessionContext, SessionRole,
        UnsecuredSessionContext,
    },
};

pub struct ExchangeManager {
    exchanges: HashMap<u16, Exchange>,
}

pub struct Exchange {
    exchange_id: u16,
    exchange_role: ExchangeRole,
    session_context: SessionContext,
    /// Message Counters (4.5.5)
    message_counter: MessageCounter,
    acknowledgements: (),
    retransmissions: (),
    sender: (),
    /*
    What if instead of owning the receiver, the exchange manager gets fed
    messages by the controller, such that it only mutates its state at that
    point and then returns a response of what needs to be done, which the
    controller then handles? That could work.
     */
    // receiver: tokio::sync::mpsc::Receiver<Message>,
}

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
        }
    }

    /// Create a new exchange and return its Exchange ID
    pub fn new_exchange_unsecured(&mut self, session_id: u16) -> u16 {
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
        let exchange = Exchange::initiator(session_id, session_context);
        let exchange_id = exchange.exchange_id;
        self.exchanges.insert(exchange_id, exchange);
        exchange_id
    }

    /// Find an exchange
    pub fn find_exchange(&mut self, exchange_id: u16) -> &mut Exchange {
        self.exchanges.get_mut(&exchange_id).unwrap()
    }

    // TODO: where do encryption and decryption take place?
    pub fn process_message(&mut self, message: Message) {
        // Exchange Message Matching (4.9.5.1)
        /*
        Attempt to match the messge to an existing message
        Use the exchange ID of the message
        Initiator matches opposite of the exchange
            Else it's an unsolicited message, handle as such

        */
    }
}

impl Exchange {
    pub fn initiator(session_id: u16, session_context: SessionContext) -> Self {
        let mut exchange_id = [0u8; 2];
        crate::crypto::fill_random(&mut exchange_id);
        let exchange_id = u16::from_le_bytes(exchange_id);

        Self {
            exchange_id,
            exchange_role: ExchangeRole::Initiator,
            session_context,
            message_counter: MessageCounter::new(),
            acknowledgements: (),
            retransmissions: (),
            sender: (),
            // receiver: todo!(),
        }
    }

    pub fn session_context(&self) -> &SessionContext {
        &self.session_context
    }

    pub fn unsecured_session_context_mut(&mut self) -> &mut UnsecuredSessionContext {
        match &mut self.session_context {
            SessionContext::Unsecured(context) => context,
            _ => panic!("Incorrect session type"),
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
