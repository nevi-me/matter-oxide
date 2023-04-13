//! Common data types used by the WebSockets client and server

use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u8 = 2;

/// A WebSocket message's expected text payload
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WsMessage {
    pub message_id: String,
    pub command: ApiCommand,
    pub args: Value,
}

/// Events sent from server to client
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    NodeAdded,
    NodeUpdated,
    NodeDeleted,
    NodeEvent,
    AttributeUpdated,
    ServerShutdown,
}

/// Known API commands
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiCommand {
    StartListening,
    // named as ServerDiagnostics
    Diagnostics,
    ServerInfo,
    GetNodes,
    GetNode,
    CommissionWithCode,
    CommissionOnNetwork,
    SetWifiCredentials,
    SetThreadDataset,
    OpenCommissioningWindow,
    Discover,
    InterviewNode,
    DeviceCommand,
    RemoveNode,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MessageType {
    CommandMessage(CommandMessage),
    EventMessage(EventMessage),
    SuccessResultMessage(SuccessResultMessage),
    ErrorResultMessage(ErrorResultMessage),
    ServerInfoMessage(ServerInfoMessage),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatterNodeData {
    pub node_id: i64,
    /// Unix epoch in milliseconds
    pub date_commissioned: i64,
    pub last_interview: i64,
    pub interview_version: i32,
    pub available: bool,
    /// Attributes are stored in form of AttributePath: ENDPOINT/CLUSTER_ID/ATTRIBUTE_ID
    pub attributes: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerDiagnostics {
    pub info: ServerInfoMessage,
    pub nodes: Vec<MatterNodeData>,
    pub events: Vec<Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerInfoMessage {
    pub fabric_id: i64,
    pub compressed_fabric_id: i32,
    pub schema_version: u8,
    pub min_supported_schema_version: u8,
    pub sdk_version: String,
    pub wifi_credentials_set: bool,
    pub thread_credentials_set: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommandMessage {
    pub message_id: String,
    pub command: String,
    pub args: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SuccessResultMessage {
    pub message_id: String,
    pub result: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ErrorResultMessage {
    pub message_id: String,
    pub error_code: i32,
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EventMessage {
    pub event: EventType,
    pub data: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommissionableNode {
    pub instance_name: String,
    pub host_name: String,
    pub port: u16,
    pub long_discriminator: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub commissioning_mode: u8, // TODO make an enum
    pub device_type: u16,
    pub device_name: Option<String>,
    pub pairing_instruction: Option<String>,
    pub pairing_hint: u8,
    pub mrp_retry_interval_idle: Option<u16>,
    pub mrp_retry_interval_active: Option<u16>,
    pub supports_tcp: bool,
    pub addresses: Vec<IpAddr>,
    pub rotating_id: Option<i64>,
}
