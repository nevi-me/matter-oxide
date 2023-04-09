use super::SessionRole;

pub struct UnsecuredSessionContext {
    pub session_role: SessionRole,
    pub ephem_initiator_role_id: u64,
    pub message_reception_state: (),
}

// 4.2.1.1 details the state machinery to follow
