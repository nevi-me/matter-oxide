use bitflags::bitflags;
// TODO: ideal to use a version of buf that doesn't panic
use bytes::{Buf, BufMut, BytesMut};

use crate::crypto::encrypt_in_place;

pub const UDP_MESSAGE_LIMIT: usize = 1280;

pub type SessionID = u16;

/// Message format (4.4)
///
/// Message Header
/// - 02 Length [opt]
/// - 01 Flag
/// - 02 Session ID
/// - 01 Security Flags
/// - 04 Message Counter
/// - 00/08 Source Node ID [opt]
/// - 00/02/08 - Destination Node ID [opt]
/// - vr Message Extensions [opt]
///
/// Message Payload
/// - vr Payload [opt] (encrypted)
///
/// Message Footer
/// - vr Message Integrity Check [opt]
///
/// Message Payload contains
/// Proto Header
/// - 01 Exchange Flags
/// - 01 Protocol OpCode
/// - 02 Exchange ID
/// - 02 Protocol ID
/// - 02 Protocol Vendoer ID [opt]
/// - 04 Ack Message Counter [opt]
/// - vr Secured Extensions [opt]
/// Applicayion Payload
/// - vr Application Payload [opt]
enum X {}

#[derive(Debug)]
pub struct Message {
    pub message_header: MessageHeader,
    pub payload_header: Option<ProtocolHeader>,
    pub payload: Vec<u8>,
    pub integrity_check: Option<Vec<u8>>,
}

impl Message {
    pub fn decode(mut buf: &[u8]) -> Self {
        // Perform validity checks
        let message_flags = MessageFlags::from_bits(buf.get_u8()).unwrap();
        // dbg!(message_flags);
        if (message_flags & MessageFlags::FORMAT_INVALID).bits() > 0 {
            panic!("Invalid version")
        }

        let session_id = buf.get_u16_le();
        // dbg!(session_id);

        let security_flags = SecurityFlags::from_bits(buf.get_u8()).unwrap();
        // dbg!(security_flags);
        if security_flags.contains(SecurityFlags::SESSION_UNICAST)
            && message_flags.contains(MessageFlags::DSIZ_16_BIT_GROUP_ID)
        {
            panic!("4.6.2 1.b")
        }
        // TODO 1.c
        // 2. If message is not of unsecured session type
        let session_type = SessionType::new(security_flags, session_id);
        // dbg!(&session_type);

        // Message counter
        let message_counter = buf.get_u32_le();
        // dbg!(message_counter);

        // Source and destination node ID
        let source_node_id = if message_flags.contains(MessageFlags::SOURCE_NODE_ID_PRESENT) {
            Some(buf.get_u64_le())
        } else {
            None
        };
        // dbg!(source_node_id);

        let dest_node_id = if message_flags.contains(MessageFlags::DSIZ_64_BIT_NODE_ID) {
            Some(NodeID::Unique(buf.get_u64_le()))
        } else if message_flags.contains(MessageFlags::DSIZ_16_BIT_GROUP_ID) {
            Some(NodeID::Group(buf.get_u16_le()))
        } else if message_flags.contains(MessageFlags::DSIZ_RESERVED) {
            panic!("Should drop message without ack (4.4.1.2)")
        } else {
            None
        };
        // dbg!(dest_node_id);

        // Message extensions (4.4.1.8)
        if security_flags.contains(SecurityFlags::MESSAGE_EXT) {
            todo!("Message extensions not yet implemented")
        }

        Self {
            message_header: dbg!(MessageHeader {
                session_type,
                message_flags,
                session_id,
                security_flags,
                message_counter,
                source_node_id,
                dest_node_id,
                message_extensions: (),
            }),
            payload_header: None,
            payload: buf.to_vec(),
            integrity_check: None,
        }
    }
    pub fn decrypt(&mut self, decryption_key: Option<&[u8]>) {
        // Protocol Header Field Descriptions (4.4.3)
        let mut buf = BytesMut::from(&self.payload[..]);
        let flag = buf.get_u8() & 0b00011111;
        // println!("{:08b} {flag}", flag);
        let exchange_flags = ExchangeFlags::from_bits(flag).unwrap();
        // dbg!(exchange_flags);
        let protocol_opcode = buf.get_u8();
        // dbg!(protocol_opcode); // TODO: convert to an enum
        let exchange_id = buf.get_u16_le();
        let protocol_id = buf.get_u16_le();
        let protocol_vendor_id = if exchange_flags.contains(ExchangeFlags::VENDOR) {
            Some(buf.get_u16_le())
        } else {
            None
        };
        let ack_message_counter = if exchange_flags.contains(ExchangeFlags::ACKNOWLDEGE) {
            Some(buf.get_u32_le())
        } else {
            None
        };
        if exchange_flags.contains(ExchangeFlags::SECURED_EXT) {
            todo!("Secured extensions not yet implemented");
        }

        self.payload_header = Some(dbg!(ProtocolHeader {
            exchange_flags,
            protocol_opcode,
            exchange_id,
            protocol_id,
            protocol_vendor_id,
            ack_message_counter,
            secured_extensions: (),
        }));

        self.payload = buf.to_vec();
    }

    pub fn encode(&self, out: &mut BytesMut, encryption_key: Option<&[u8]>) {
        self.message_header.encode(out);
        if let Some(_) = encryption_key {
            encrypt_in_place()
        }
        // If there is an encryption key, encrypt the payload
        self.payload_header.as_ref().unwrap().encode(out);
        out.put_slice(&self.payload);
    }
}

#[derive(Default, Debug)] // For testing only
pub struct MessageHeader {
    pub session_type: SessionType,
    pub message_flags: MessageFlags,
    pub session_id: u16,
    pub security_flags: SecurityFlags,
    pub message_counter: u32,
    pub source_node_id: Option<u64>,
    pub dest_node_id: Option<NodeID>,
    pub message_extensions: (),
}

impl MessageHeader {
    pub fn new(session_id: u16) -> Self {
        Self {
            session_id,
            ..Default::default()
        }
    }
    pub fn encode(&self, target: &mut BytesMut) -> usize {
        // The message length is prepended outside of this function for TCP
        target.put_u8(self.message_flags.bits());
        target.put_u16_le(self.session_id);
        target.put_u8(self.security_flags.bits());
        target.put_u32_le(self.message_counter);
        if let Some(val) = self.source_node_id {
            target.put_u64_le(val);
        }
        match self.dest_node_id {
            Some(NodeID::Group(val)) => target.put_u16_le(val),
            Some(NodeID::Unique(val)) => target.put_u64_le(val),
            None => {}
        }
        // Message extensions
        target.len()
    }
}

#[derive(Debug, Default)]
pub struct ProtocolHeader {
    pub exchange_flags: ExchangeFlags,
    pub protocol_opcode: u8,
    pub exchange_id: u16,
    pub protocol_id: u16,
    pub protocol_vendor_id: Option<u16>,
    pub ack_message_counter: Option<u32>,
    pub secured_extensions: (),
}

impl ProtocolHeader {
    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u8(self.exchange_flags.bits());
        out.put_u8(self.protocol_opcode);
        out.put_u16_le(self.exchange_id);
        out.put_u16_le(self.protocol_id);
        if let Some(vendor_id) = self.protocol_vendor_id {
            out.put_u16_le(vendor_id);
        }
        if let Some(ack) = self.ack_message_counter {
            out.put_u32_le(ack);
        }
        // Secured extensions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionType {
    UnsecuredSession,
    SecureUnicast(SessionID),
    SecureGroup(SessionID),
}

impl Default for SessionType {
    fn default() -> Self {
        Self::UnsecuredSession
    }
}

impl SessionType {
    const fn new(flag: SecurityFlags, session_id: SessionID) -> Self {
        // Unicast is 0b00, care should be taken here
        match (
            session_id,
            flag.contains(SecurityFlags::SESSION_GROUP),
            flag.contains(SecurityFlags::SESSION_UNICAST),
        ) {
            (0, true, _) => panic!("Invalid message"),
            (0, false, true) => SessionType::UnsecuredSession,
            (_, false, true) => SessionType::SecureUnicast(session_id),
            (_, true, false) => SessionType::SecureGroup(session_id),
            (_, true, true) | (_, false, false) => {
                unreachable!()
            }
        }
    }

    pub const fn session_id(&self) -> Option<u16> {
        match self {
            SessionType::UnsecuredSession => None,
            SessionType::SecureUnicast(id) => Some(*id),
            SessionType::SecureGroup(id) => Some(*id),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NodeID {
    Unique(u64),
    Group(u16),
}

// Messages are either control or data messages

bitflags! {
    #[derive(Copy, Clone, Default, Debug)]
    pub struct MessageFlags: u8 {
        const FORMAT_V1 = 0b00000000;
        const SOURCE_NODE_ID_PRESENT = 0b00000100;
        const DSIZ_64_BIT_NODE_ID = 0b00000001;
        const DSIZ_16_BIT_GROUP_ID = 0b00000010;
        /// Messages with this flag shall be dropped without an ack
        const DSIZ_RESERVED = 0b00000011;

        // Validation
        const FORMAT_INVALID = 0b11100000;
    }
}

bitflags! {
    #[derive(Copy, Clone, Default, Debug)]
    pub struct SecurityFlags: u8 {
        const PRIVACY = 0b10000000;
        const CONTROL = 0b01000000;
        const MESSAGE_EXT = 0b00100000;
        const SESSION_UNICAST = 0b00000000;
        const SESSION_GROUP = 0b00000001;
        const SESSION_RESERVED = 0b00000011;
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, Default)]
    pub struct ExchangeFlags: u8 {
        const INITIATOR = 0b0000001;
        const ACKNOWLDEGE = 0b00000010;
        const RELIABILITY = 0b00000100;
        const SECURED_EXT = 0b00001000;
        const VENDOR = 0b00010000;
    }
}

#[repr(u16)]
#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum ProtocolID {
    SecureChannel = 0x0000,
    InteractionModel = 0x0001,
    BDX = 0x0002,
    UserDirectedComm = 0x0003,
    ForTesting = 0x0004,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        let buf = hex_literal::hex!("01000000e30ba008e8030000000000000621000000000000000015300120c3bf6a81dda5b85c626a582fdaf855cb7085ee308c8976954544afe814cca1a3300220b7b386219f54d57c39273a93b91a16a9232f209c4a0c8b7ff14ccb73434a24bf24030135042501d007300220f84523aa2486f48877a672c8146dafbdf531360ac8d8915d6027da1abc83193c1818");
        let mut message = Message::decode(&buf);
        message.decrypt(None);
        dbg!(message);
    }

    #[test]
    fn test_decode_2() {
        // light on payload
        let buf = hex_literal::hex!(
            "01000000138ada02e8030000000000000621000000000000000015300120c3bf6a81dda5b85c626a582fdaf855cb7085ee308c8976954544afe814cca1a33002201a6497bc785ac87d2004d9fa61bf8e2adb412ae4b475a7362e07db43ad1b6db324030135042501d007300220ee1c5b288f0abb63f9602e0cd72e256a002e71ead3e4188096e86986b9b5d5c01818"
        );
        let message = Message::decode(&buf);
        dbg!(message);
    }

    #[test]
    fn test_decode_3() {
        // light on payload
        let buf = hex_literal::hex!("00010000ebed3e005cf46a92ce31fbf54a3fb90eef5a8f5549250c84df73619aba1e45648d966af5f8bd9be8aee5b3d660fe2acce629bc73874437");
        let message = Message::decode(&buf);
        dbg!(message);
    }
}
