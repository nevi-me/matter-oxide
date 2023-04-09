use bitflags::bitflags;

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

pub struct Message {
    pub session_type: SessionType,
    pub header: MessageHeader,
    pub integrity_check: Option<Vec<u8>>,
}

impl Message {
    pub fn decode(packet: &[u8], is_udp: bool) -> Self {
        // UDP messages don't carry their length as a prefix
        // Perform validity checks
        let mut position = 0;
        let message_len = if is_udp {
            packet.len() as u16
        } else {
            position += 2;
            u16::from_le_bytes(packet[position - 2..position].try_into().unwrap())
        };
        let message_flags = MessageFlags::from_bits(packet[position]).unwrap();
        position += 1;
        if (message_flags & MessageFlags::FORMAT_INVALID).bits() > 0 {
            panic!("Invalid version")
        }

        let session_id = u16::from_le_bytes(packet[position..position + 2].try_into().unwrap());
        position += 2;

        let security_flags = SecurityFlags::from_bits(packet[position]).unwrap();
        position += 1;
        if security_flags.contains(SecurityFlags::SESSION_UNICAST)
            && message_flags.contains(MessageFlags::DSIZ_16_BIT_GROUP_ID)
        {
            panic!("4.6.2 1.b")
        }
        // TODO 1.c
        // 2. If message is not of unsecured session type
        let session_type = SessionType::new(security_flags, session_id);

        Self {
            session_type: todo!(),
            header: todo!(),
            integrity_check: None,
        };
        panic!()
    }
}

pub struct MessageHeader {
    pub message_len: u16,
    pub message_flags: MessageFlags,
    pub session_id: u16,
    pub security_flags: SecurityFlags,
    pub message_counter: u64,
    pub node_source_id: Option<u64>,
    pub dest_node_source_id: Option<()>,
    pub message_extensions: (),
}

impl MessageHeader {
    pub fn encode(&self, target: &mut [u8]) {}
}

pub struct MessagePayload {
    pub protocol_header: ProtocolHeader,
    pub application_payload: Vec<u8>,
}

pub struct ProtocolHeader {
    pub exchange_flags: u8,
    pub protocol_opcode: u8,
    pub exchange_id: u16,
    pub protocol_id: u16,
    pub protocol_vendor_id: Option<u16>,
    pub ack_message_counter: Option<u32>,
    pub secured_extensions: (),
}

#[derive(Clone, Copy)]
pub enum SessionType {
    UnsecuredSession,
    SecureUnicast(SessionID),
    SecureGroup(SessionID),
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

// Messages are either control or data messages

bitflags! {
    #[derive(Copy, Clone)]
    pub struct MessageFlags: u8 {
        const FORMAT_V1 = 0b00000000;
        const SOURCE_NODE_ID_PRESENT = 0b00000100;
        const DSIZ_64_BIT_NODE_ID = 0b00000001;
        const DSIZ_16_BIT_GROUP_ID = 0b00000010;
        /// Messages with this flag shall be dropped without an ack
        const DSIZ_RESERVEC = 0b00000011;

        // Validation
        const FORMAT_INVALID = 0b11100000;
    }
}

bitflags! {
    #[derive(Copy, Clone)]
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
    #[derive(Copy, Clone)]
    pub struct ExchangeFlags: u8 {
        const INITIATOR = 0b0000001;
        const ACKNOWLDEGE = 0b00000010;
        const RELIABILITY = 0b00000100;
        const SECURED_EXT = 0b00001000;
        const VENDOR = 0b00010000;
    }
}

#[repr(u8)]
pub enum ProtocolID {
    SecureChannel = 0x0000,
    InteractionModel = 0x0001,
    BDX = 0x0002,
    UserDirectedComm = 0x0003,
    ForTesting = 0x0004,
}
