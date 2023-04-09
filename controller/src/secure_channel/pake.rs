use crate::message::Message;

use super::{SessionContext, SessionRole};

pub const CRYPTO_PBKDF_ITERATIONS_MIN: i32 = 1000;
pub const CRYPTO_GROUP_SIZE_BYTES: usize = 32;
pub const CRYPTO_PUBLIC_KEY_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES * 2 + 1;
pub const CRYPTO_HASH_LEN_BYTES: usize = 0;

pub struct PAKEInteraction {
    session_context: SessionContext,
    current_state: (),
    initiator_session_id: u16,
    responder_session_id: u16,
}

impl PAKEInteraction {
    pub fn initiator() -> Self {
        Self {
            session_context: SessionContext {
                session_type: super::SessionType::Pase,
                session_role: SessionRole::Initiator,
                local_session_id: todo!(),
                peer_session_id: todo!(),
                i2r_key: todo!(),
                r2i_key: todo!(),
                shared_secret: todo!(),
                local_message_counter: todo!(),
                message_reception_state: todo!(),
                local_fabric_index: todo!(),
                peer_node_id: todo!(),
                resumption_id: todo!(),
                session_timestamp: todo!(),
                active_timestamp: todo!(),
            },
            current_state: (),
            initiator_session_id: 0,
            responder_session_id: 0,
        }
    }

    pub fn responder() -> Self {
        Self {
            session_context: SessionContext {
                session_type: super::SessionType::Pase,
                session_role: SessionRole::Responder,
                local_session_id: todo!(),
                peer_session_id: todo!(),
                i2r_key: todo!(),
                r2i_key: todo!(),
                shared_secret: todo!(),
                local_message_counter: todo!(),
                message_reception_state: todo!(),
                local_fabric_index: todo!(),
                peer_node_id: todo!(),
                resumption_id: todo!(),
                session_timestamp: todo!(),
                active_timestamp: todo!(),
            },
            current_state: (),
            initiator_session_id: 0,
            responder_session_id: 0,
        }
    }

    pub fn pbkdf_param_request(&mut self) -> Message {
        assert_eq!(self.session_context.session_role, SessionRole::Initiator);
        let initiator_random = [1; 32];
        let initiator_session_id = 1;
        let passcode_id = 0;
        // TODO: get pbkdf params from QR code if any
        let has_pbkdf_params = false;

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn pbkdf_param_response(&mut self, request: &PBKDFParamRequest) -> Message {
        assert_eq!(self.session_context.session_role, SessionRole::Responder);
        assert_eq!(request.passcode_id, 0);
        let responder_random = [2; 32];
        self.session_context.peer_session_id = request.initiator_session_id;

        // TODO: create params (set iterations, salt)

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn pake1(&mut self, request: &PBKDFParamResponse) -> Message {
        self.session_context.peer_session_id = request.responder_session_id;
        // Generate Crypto_PAKEValues_Initiator
        // Generate pA

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn pake2(&mut self, request: &Pake1) -> Message {
        // Compute pB
        // Compute TT
        // Compute (cA, cB, Ke)

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn pake3(&mut self, request: &Pake2) -> Message {
        // Compute TT
        // Compute (cA, cB, Ke)
        // Verify Pake2.cB against cB

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn pake_finished(&mut self, pake3: &Pake3) -> Message {
        // Verify Pake3.cA against cA
        // Set SessionTimestamp

        // Refer to PakeFinished for more instructions

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
}

/*
Each interaction above returns a message, which is sent to the peer.
I would like to separate the generation of messages from its transmission
so that if necessary peers can send messages out of band to each other.

In each of the above interactions, I'll mutate state, then return a response.
So let's start by returning a message or an error.
 */

pub struct PBKDFParams {
    pub iterations: i32,
    pub salt: Vec<u8>, // 16..32 length
}

pub struct PBKDFParamRequest {
    pub initiator_random: [u8; 32],
    pub initiator_session_id: u16,
    pub passcode_id: u16,
    pub has_pbkdf_params: bool,
    pub initiator_sed_params: Option<SedParameters>,
}

pub struct PBKDFParamResponse {
    pub initiator_random: [u8; 32],
    pub responder_random: [u8; 32],
    pub responder_session_id: u16,
    pub pbkdf_params: Option<()>,
    pub responder_sed_params: Option<SedParameters>,
}

pub struct SedParameters {
    pub sleepy_idle_interval: Option<u32>,
    pub sleepy_active_interval: Option<u32>,
}

pub struct Pake1 {
    pub p_a: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
}

pub struct Pake2 {
    pub p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub c_b: [u8; CRYPTO_HASH_LEN_BYTES],
}

pub struct Pake3 {
    pub c_a: [u8; CRYPTO_HASH_LEN_BYTES],
}
