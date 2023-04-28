use num::FromPrimitive;

use crate::{
    crypto::fill_random,
    message::{
        status_report::StatusReport, ExchangeFlags, Message, MessageFlags, ProtocolID,
        SecurityFlags,
    },
    secure_channel::pake::{PBKDFParamRequest, PBKDFParams, Pake1, Pake3},
    session_context::{
        SecureChannelProtocolID, SecureSessionContext, SessionContext, UnsecuredSessionContext,
    },
};

use self::{case::CASEManager, pake::PASEManager};

pub mod case;
pub mod pake;
pub mod unsecured;

/// The message counter maximum window size
pub const MSG_COUNTER_WINDOW_SIZE: u32 = 32;
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
    /// TODO: check what constraints/conditions are required before establishing either session
    ///
    /// TODO: this is a hacky way of returning a maybe-session, don't want to take a ref to the handler
    /// though. We might have to merge UnsecuredSessionContext with SecureSessionContext.
    pub fn on_message(
        &mut self,
        session_context: &mut SessionContext,
        message: &Message,
    ) -> (Option<Message>, Option<SecureSessionContext>) {
        let payload_header = message.payload_header.as_ref().unwrap();
        assert_eq!(payload_header.protocol_id, ProtocolID::SecureChannel as u16);
        let opcode: SecureChannelProtocolID =
            SecureChannelProtocolID::from_u8(payload_header.protocol_opcode).unwrap();
        // TODO: validate that the correct stage of session establishment is being used.
        match opcode {
            SecureChannelProtocolID::PBKDFParamRequest => {
                let SessionContext::Unsecured(session_context) = session_context else {
                    panic!();
                };
                let mut node_id = [0; 8];
                fill_random(&mut node_id);
                let node_id = u64::from_le_bytes(node_id);
                // TODO: validate whether a new PASE session can be created
                let passcode = 123456;
                // This gets set at a different layer
                let message_counter = 0;
                // TODO: these should be known beforehand
                let params = Some(PBKDFParams {
                    iterations: 1000,
                    salt: vec![0; 16],
                });
                let mut pase = PASEManager::responder(
                    passcode,
                    message.message_header.session_id,
                    message.message_header.session_id,
                    payload_header.exchange_id,
                    node_id,
                    message
                        .message_header
                        .source_node_id
                        .expect("Should be present"),
                    message_counter,
                    params,
                );
                let request = PBKDFParamRequest::from_tlv(&message.payload);
                pase.set_pbkdf_param_request(
                    heapless::Vec::from_slice(message.payload.as_slice()).unwrap(),
                );
                self.pase = Some(pase);
                return (
                    Some(
                        self.pase
                            .as_mut()
                            .unwrap()
                            .pbkdf_param_response(session_context, &request),
                    ),
                    None,
                );
            }
            SecureChannelProtocolID::PBKDFParamResponse => todo!(),
            SecureChannelProtocolID::PASEPake1 => {
                // TODO: send acks
                let request = Pake1::from_tlv(&message.payload);
                return (Some(self.pase.as_mut().unwrap().pake2(&request)), None);
            }
            SecureChannelProtocolID::PASEPake2 => todo!(),
            SecureChannelProtocolID::PASEPake3 => {
                let request = Pake3::from_tlv(&message.payload);
                let SessionContext::Unsecured(session_context) = session_context else {
                    panic!();
                };

                // Create a secure session
                let (k_e, c_a, c_b) = self.pase.as_ref().unwrap().get_secrets();
                let mut secured_session = SecureSessionContext::new_pase(
                    false,
                    false,
                    session_context.local_session_id,
                    session_context.peer_session_id,
                    k_e,
                    &[],
                );

                return (
                    Some(self.pase.as_mut().unwrap().pake_finished(&request)),
                    Some(secured_session),
                );
            }
            SecureChannelProtocolID::MRPStandaloneAck => {
                // TODO: update for standard ack
                (None, None)
            }
            SecureChannelProtocolID::MsgCounterSyncReq => todo!(),
            SecureChannelProtocolID::MsgCounterSyncRsp => todo!(),
            SecureChannelProtocolID::CASESigma1 => todo!(),
            SecureChannelProtocolID::CASESigma2 => todo!(),
            SecureChannelProtocolID::CASESigma3 => todo!(),
            SecureChannelProtocolID::CASESigma2Resume => todo!(),
            SecureChannelProtocolID::StatusReport => {
                /*
                Receiving a status report at a random stage of interaction is going to be interesting,
                because without explicitly tracking state, we might not know
                if for example a PASE interaction has failed.
                 */
                // TODO: handle when tracking state per channel
                let status_report = StatusReport::from_payload(&message.payload);
                dbg!(status_report);
                (None, None)
            }
        }
    }
}
