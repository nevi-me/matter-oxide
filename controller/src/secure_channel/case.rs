use crate::message::Message;

use super::{pake::SedParameters, SessionContext};

pub struct CaseInteraction {
    session_context: SessionContext,
}

impl CaseInteraction {
    pub fn sigma1(&mut self) -> Message {
        // Generate random number
        // Generate session ID
        // Generate destination ID
        // Generate ephemeral keypair
        // May encode MRP params
        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn sigma1_with_resumption(&mut self) -> Message {
        // Same as above
        // Generate s1rk
        // Generate initiator reume NIC using shared secret
        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn sigma2(&mut self, request: &Sigma1) -> Message {
        // Check if resumption id and initiator resume NIC are both set or both not
        self.session_context.peer_session_id = request.initiator_session_id;
        // Search for existing session if resumtion fields present
        // Validate sigma1 destination ID

        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn sigma2_resume(&mut self) -> Message {
        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn sigma3(&mut self) -> Message {
        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
    pub fn sigma_finished(&mut self) -> Message {
        Message {
            session_type: todo!(),
            header: todo!(),
            integrity_check: todo!(),
        }
    }
}

pub struct Sigma1 {
    pub initiator_random: [u8; 32],
    pub initiator_session_id: u16,
    pub destination_id: (),
    pub initiator_eph_pubkey: [u8; 32],
    pub initiator_sed_params: Option<SedParameters>,
    pub resumption_id: Option<[u8; 16]>,
    pub initiator_resume_mic: Option<[u8; 0]>, // TODO: CRYPTO_AEAD_MIC_LENGTH_BYTES
}
pub struct Sigma2 {}
pub struct Sigma2Resume {}
pub struct Sigma3 {}
