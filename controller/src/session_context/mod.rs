use std::collections::HashMap;

pub mod message_counter_sync;
pub mod secure;
/// Unsecured Session Context (4.12.1.1)
pub mod unsecured;

pub use secure::*;
pub use unsecured::*;

use crate::{crypto::fill_random, message::SessionID};

pub struct SessionManager {
    // TODO: can I make this take only secure sessions?
    //       what about MCSP? Insecure is prob fine as I shouldn't have > 1
    sessions: HashMap<SessionID, SessionContext>,
    last_session_id: SessionID,
    resumption_records: HashMap<u64, ()>, // u64 -> node ID
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            // these capacity values are arbitrary, not enforced
            sessions: HashMap::with_capacity(10),
            last_session_id: 0,
            resumption_records: HashMap::with_capacity(4),
        }
    }

    /// Convenience to add a session that's manually created outside
    pub fn add_session(&mut self, session_context: SessionContext, assign_id: bool) -> SessionID {
        let mut session_context = session_context;
        let session_id = match &mut session_context {
            SessionContext::MCSP => todo!(),
            SessionContext::Secure(secure) => {
                if !assign_id {
                    secure.local_session_id
                } else {
                    let id = self.next_session_id();
                    self.last_session_id = id;
                    secure.local_session_id = id;
                    id
                }
            }
            SessionContext::Unsecured(unsecured) => {
                // Unsecured sessions have ID = 0
                // assert_eq!(unsecured.local_session_id, 0);
                // assert_eq!(unsecured.peer_session_id, 0);
                unsecured.local_session_id
            }
        };
        self.sessions.insert(session_id, session_context);
        session_id
    }

    /// Create a new session and assign it a session ID
    pub fn new_session(&mut self, role: SessionRole) -> SessionID {
        panic!()
    }

    pub fn get_session(&self, id: SessionID) -> Option<&SessionContext> {
        self.sessions.get(&id)
    }

    pub fn get_session_mut(&mut self, id: SessionID) -> &mut SessionContext {
        self.sessions.get_mut(&id).unwrap()
    }

    pub fn remove_session(&mut self, id: SessionID) {}

    pub fn next_session_id(&self) -> SessionID {
        // let mut buf = [0; 2];
        // fill_random(&mut buf);
        // let mut session_id = u16::from_le_bytes(buf);
        // while self.pase_session_ids.contains(&session_id) {
        //     session_id += 1;
        // }
        self.last_session_id + 1
    }
}

#[derive(Debug)]
pub enum SessionContext {
    MCSP,
    Secure(SecureSessionContext),
    Unsecured(UnsecuredSessionContext),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}
