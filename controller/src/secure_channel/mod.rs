use num::FromPrimitive;

use crate::{
    message::{Message, ProtocolID},
    secure_channel::pake::{PBKDFParamRequest, PBKDFParams, Pake1, Pake3},
    session_context::{SecureChannelProtocolID, SecureSessionContext, UnsecuredSessionContext},
};

use self::{case::CASEManager, pake::PASEManager};

pub mod case;
pub mod pake;
pub mod unsecured;

pub const MSG_COUNTER_WINDOW_SIZE: usize = 32;
pub const MSG_COUNTER_SYNC_REQ_JITTER: usize = 500;
pub const MSG_COUNTER_SYNC_TIMEOUT: usize = 400;

pub struct SecureChannelManager {
    case: Option<CASEManager>,
    pase: Option<PASEManager>,
}

impl SecureChannelManager {
    pub fn new() -> Self {
        Self {
            case: None,
            pase: None,
        }
    }

    /// Handle a new message and send a response with a response message
    ///
    /// TODO: This would have to handle MRP acks, unless we send specific messages here
    ///
    /// TODO: check what constraints/conditions are required before establishing either sessoin
    pub fn on_message(
        &mut self,
        session_context: &mut UnsecuredSessionContext,
        message: &Message,
    ) -> Message {
        let payload_header = message.payload_header.as_ref().unwrap();
        assert_eq!(payload_header.protocol_id, ProtocolID::SecureChannel as u16);
        let opcode: SecureChannelProtocolID =
            SecureChannelProtocolID::from_u8(payload_header.protocol_opcode).unwrap();
        match opcode {
            SecureChannelProtocolID::PBKDFParamRequest => {
                // TODO: validate whether a new PASE session can be created
                let passcode = 123456;
                let session_id = 0;
                let exchange_id = 0;
                let message_counter = 0;
                // TODO: these should be known beforehand
                let params = Some(PBKDFParams {
                    iterations: 1000,
                    salt: vec![0; 16],
                });
                let mut pase = PASEManager::responder(
                    passcode,
                    session_id,
                    exchange_id,
                    message_counter,
                    params,
                );
                let request = PBKDFParamRequest::from_tlv(&message.payload);
                pase.set_pbkdf_param_request(
                    heapless::Vec::from_slice(message.payload.as_slice()).unwrap()
                );
                self.pase = Some(pase);
                return self
                    .pase
                    .as_mut()
                    .unwrap()
                    .pbkdf_param_response(session_context, &request);
            }
            SecureChannelProtocolID::PBKDFParamResponse => todo!(),
            SecureChannelProtocolID::PASEPake1 => {
                // TODO: send acks
                let request = Pake1::from_tlv(&message.payload);
                return self.pase.as_mut().unwrap().pake2(
                    &request
                )
            }
            SecureChannelProtocolID::PASEPake2 => todo!(),
            SecureChannelProtocolID::PASEPake3 => {
                let request = Pake3::from_tlv(&message.payload);
                return self.pase.as_mut().unwrap().pake_finished(
                    &request
                )
            }
            SecureChannelProtocolID::MRPStandaloneAck => todo!(),
            SecureChannelProtocolID::MsgCounterSyncReq => todo!(),
            SecureChannelProtocolID::MsgCounterSyncRsp => todo!(),
            SecureChannelProtocolID::CASESigma1 => todo!(),
            SecureChannelProtocolID::CASESigma2 => todo!(),
            SecureChannelProtocolID::CASESigma3 => todo!(),
            SecureChannelProtocolID::CASESigma2Resume => todo!(),
            SecureChannelProtocolID::StatusReport => todo!(),
        }
        todo!()
    }
}
