use bytes::{Buf, BufMut};
use num::FromPrimitive;

/// Status Report Message (Appendix D)
#[derive(Debug)]
pub struct StatusReport {
    pub general_code: GeneralCode,
    pub protocol_id: u32,
    pub protocol_code: u16,
    pub protocol_data: Vec<u8>,
}

impl StatusReport {
    pub fn from_payload(mut payload: &[u8]) -> Self {
        // TODO: do implementations send 6 bytes?
        assert!(payload.len() >= 8);

        let general_code = payload.get_u16_le();
        let general_code = GeneralCode::from_u16(general_code).unwrap();
        let protocol_id = payload.get_u32_le();
        let protocol_code = if payload.remaining() >= 2 {
            payload.get_u16_le()
        } else {
            0
        };

        // TODO: any validation

        Self {
            general_code,
            protocol_id,
            protocol_code,
            protocol_data: payload.to_vec(),
        }
    }

    pub fn to_payload(&self, mut payload: &mut [u8]) {
        payload.put_u16_le(self.general_code as u16);
        payload.put_u32_le(self.protocol_id);
        // TODO: should this be conditional?
        if self.protocol_code > 0 {
            payload.put_u16_le(self.protocol_code);
        }

        payload.put_slice(&self.protocol_data);
    }
}

#[repr(u16)]
#[derive(FromPrimitive, PartialEq, Eq, Debug, Clone, Copy)]
pub enum GeneralCode {
    Success = 0,
    Failure,
    BadPrecondition,
    OutOfRange,
    BadRequest,
    Unsupported,
    Unexpected,
    ResourceExhausted,
    Busy,
    Timeout,
    Continue,
    Aborted,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    DataLoss,
}
