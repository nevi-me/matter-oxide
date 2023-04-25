use crate::{
    constants::{SESSION_KEYS_INFO, SESSION_RESUMPTION_KEYS_INFO},
    crypto::hkdf_sha256,
    util::time::current_timestamp,
};

use super::SessionRole;

// TODO: find a more appropriate place for this
/// Session Context (4.12.2.1)
pub struct SecureSessionContext {
    pub session_type: SecureSessionType,
    pub session_role: SessionRole,
    pub local_session_id: u16,
    pub peer_session_id: u16,
    pub encryption_key: [u8; 16],
    pub decryption_key: [u8; 16],
    pub attestation_key: [u8; 16],
    pub shared_secret: [u8; 16],
    pub local_message_counter: i64,
    // TODO: (4.5.4)
    pub message_reception_state: (),
    pub local_fabric_index: usize,
    pub peer_node_id: i64,
    pub resumption_id: i8, // TODO
    pub session_timestamp: i64,
    pub active_timestamp: i64,
    // TODO: sleepy parameters
    // TODO: CASE authenticated tags (max 3 can be stored)
}

impl SecureSessionContext {
    pub fn new_pase(
        is_initiator: bool,
        is_resumption: bool,
        local_session_id: u16,
        peer_session_id: u16,
        shared_secret: &[u8],
        salt: &[u8],
    ) -> Self {
        let timestamp = current_timestamp();
        let info = if is_resumption {
            &SESSION_RESUMPTION_KEYS_INFO[..]
        } else {
            &SESSION_KEYS_INFO[..]
        };

        let mut key = [0; 16 * 3];
        hkdf_sha256(salt, shared_secret, info, &mut key);
        let (a, o) = key.split_at(16);
        let (b, attestation_key) = o.split_at(16);

        let (encryption_key, decryption_key) = if is_initiator { (a, b) } else { (b, a) };

        Self {
            session_type: SecureSessionType::Pase,
            session_role: if is_initiator {
                SessionRole::Initiator
            } else {
                SessionRole::Responder
            },
            local_session_id,
            peer_session_id,
            encryption_key: encryption_key.try_into().unwrap(),
            decryption_key: decryption_key.try_into().unwrap(),
            attestation_key: attestation_key.try_into().unwrap(),
            shared_secret: shared_secret.try_into().unwrap(),
            local_message_counter: 0,
            message_reception_state: (),
            local_fabric_index: 0,
            peer_node_id: 0,
            resumption_id: 0,
            session_timestamp: timestamp,
            active_timestamp: timestamp,
        }
    }
}

pub enum SecureSessionType {
    Case,
    Pase,
}

#[repr(u8)]
#[derive(FromPrimitive)]
pub enum SecureChannelProtocolID {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncRsp = 0x01,
    MRPStandaloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
}

#[repr(u16)]
pub enum SecureChannelProtocolCode {
    SessionEstablishmentSuccess = 0x0000,
    NoSharedTrustRoots = 0x0001,
    InvalidParameter = 0x0002,
    CloseSession = 0x0003,
    Busy = 0x0004,
}
