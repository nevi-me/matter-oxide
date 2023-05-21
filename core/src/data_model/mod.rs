//! Defines core types in the data model

pub mod device;
pub mod device_type;
pub mod endpoint;
pub mod handler;

/// Data Model Specification (7.1)
pub const DATA_MODEL_REVISION: u8 = 16;

/// Command fields (7.11.1)
pub struct Command {
    pub id: i64,
    pub name: String,
    pub data_type: (),
    pub constraint: (),
    pub quality: (),
    pub default: (),
    pub conformance: (),
}

pub struct Event<T> {
    pub event_id: (),
    /// The number is monotonically increasing per node, and is persisted (7.14.2.1).
    pub event_number: i64,
    pub priority: EventPriority,
    pub timestamp: i64, // TODO: create a struct for Matter Timestamp
    pub data: T,
}

pub struct Attribute {
    pub id: u16,
    pub quality: (),
    pub access: (),
}

pub enum AttributeValue {
    Boolean(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Utf8(String),
    Composite,
}

pub enum EventPriority {
    Debug,
    Info,
    Critical,
}

pub enum DeviceTypeClassification {
    Utility,
    Application(ApplicationDeviceClassification),
}

pub enum ApplicationDeviceClassification {
    Simple,
    Dynamic,
}
