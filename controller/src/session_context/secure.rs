use super::SessionRole;

// TODO: find a more appropriate place for this
/// Session Context (4.12.2.1)
pub struct SecureSessionContext {
    pub session_type: SecureSessionType,
    pub session_role: SessionRole,
    pub local_session_id: u16,
    pub peer_session_id: u16,
    pub i2r_key: (),
    pub r2i_key: (),
    pub shared_secret: (),
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

pub enum SecureSessionType {
    Case,
    Pase,
}

#[repr(u8)]
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
