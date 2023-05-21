use num::FromPrimitive;

use crate::{
    data_model::handler::{AttrDataEncoder, Handler},
    exchange::Exchange,
    interaction_model::InteractionModelProtocolOpCode,
    message::{ExchangeFlags, Message, MessageFlags, MessageHeader, ProtocolHeader, ProtocolID},
    session_context::SessionContext,
    tlv::Encoder,
};

use super::{AttributeStatusIB, ReadRequestMessage, ReportDataMessage};

/*
How do we know when there is a new transaction?
How about using opcodes? That could work.
*/
pub struct Transaction {
    // state: TransactionState,
    // action: TransactionType,
    // exchange: &'a Exchange,
}

pub enum TransactionState {
    Active,
    Completed,
}

impl Transaction {
    pub fn on_message(
        &mut self,
        session_context: &mut SessionContext,
        handler: &impl Handler,
        message: &Message,
    ) -> Option<Message> {
        let SessionContext::Secure(session) = session_context else {
            panic!()
        };
        let payload_header = message.payload_header.as_ref().unwrap();
        assert_eq!(
            payload_header.protocol_id,
            ProtocolID::InteractionModel as u16
        );
        let opcode: InteractionModelProtocolOpCode =
            InteractionModelProtocolOpCode::from_u8(payload_header.protocol_opcode).unwrap();
        let mut response_opcode = InteractionModelProtocolOpCode::StatusResponse;
        // TODO: validate that the correct stage of session establishment is being used.
        let encoder = match opcode {
            InteractionModelProtocolOpCode::StatusResponse => {
                todo!()
            }
            // First in a transaction
            InteractionModelProtocolOpCode::ReadRequest => {
                response_opcode = InteractionModelProtocolOpCode::ReportData;
                self.read_request(message, handler)
            }
            InteractionModelProtocolOpCode::SubscribeRequest => todo!(),
            InteractionModelProtocolOpCode::SubscribeResponse => todo!(),
            InteractionModelProtocolOpCode::ReportData => todo!(),
            InteractionModelProtocolOpCode::WriteRequest => todo!(),
            InteractionModelProtocolOpCode::WriteResponse => todo!(),
            InteractionModelProtocolOpCode::InvokeRequest => {
                // got here, next is to support arming fail-safe
                panic!()
            }
            InteractionModelProtocolOpCode::InvokeResponse => todo!(),
            InteractionModelProtocolOpCode::TimedRequest => todo!(),
        };

        let message_header = &message.message_header;
        let payload_header = message.payload_header.as_ref().unwrap();

        // TODO: some responses can be split into multiple messages,
        // so we shouldn't return only 1 message
        let response_message = Message {
            message_header: MessageHeader {
                session_type: message_header.session_type.clone(),
                // session_type: crate::message::SessionType::SecureUnicast(message_header.session_id),
                message_flags: message_header.message_flags.clone(),
                session_id: message_header.session_id,
                security_flags: message_header.security_flags.clone(),
                message_counter: 0,
                source_node_id: Some(0), // TODO
                dest_node_id: Some(crate::message::NodeID::Unique(session.peer_node_id)),
                message_extensions: (),
            },
            payload_header: Some(ProtocolHeader {
                exchange_flags: ExchangeFlags::default(),
                protocol_opcode: response_opcode as u8,
                exchange_id: payload_header.exchange_id,
                protocol_id: payload_header.protocol_id,
                protocol_vendor_id: payload_header.protocol_vendor_id,
                // Not handled here
                ack_message_counter: None,
                secured_extensions: (),
            }),
            payload: encoder.inner(),
            integrity_check: None,
        };

        dbg!(&message.message_header);
        dbg!(&response_message.message_header);

        Some(response_message)
    }

    fn read_request(&mut self, message: &Message, handler: &impl Handler) -> Encoder {
        let read_request_message = ReadRequestMessage::from_tlv(&message.payload);
        // dbg!(&read_request_message);
        // TODO: how do we handle multiple attribute reads?
        let mut writer = Encoder::default();
        let mut encoder = AttrDataEncoder {
            writer: &mut writer,
        };
        // Create a response message
        let mut response = ReportDataMessage {
            subscription_id: None,
            attribute_reports: None,
            event_reports: None,
            more_chunked_messages: false,
            suppressed_response: false,
            interaction_model_revision: 1,
        };
        // TODO: Surely we can't send attr twice?
        if let Some(attrs) = &read_request_message.attribute_requests {
            let mut attribute_reports = vec![];
            for attr in attrs.as_slice() {
                attribute_reports.push(super::AttributeReportIB {
                    attribute_status: super::AttributeStatusIB {
                        path: attr.clone(),
                        status: super::StatusIB {
                            status: 0,
                            cluster_status: 0,
                        },
                    },
                    attribute_data: handler.handle_read2(&attr),
                });
            }
            response.attribute_reports = Some(attribute_reports);
        }

        response.to_tlv(&mut writer);
        writer
    }
}

/*
What information do we need in a transaction?
- its state
- common data attributes
*/
pub enum TransactionType {
    Read,
    Subscribe,
    Report,
    Write,
    Invoke,
}
