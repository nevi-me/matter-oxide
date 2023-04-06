//! The Matter server and its commands

use common::ServerInfoMessage;
use serde_json::Value;

use crate::{device_controller::{self, MatterDeviceController}, storage_controller::StorageController};


#[derive(Clone)]
pub struct MatterServer {
    // storage_path: String,
    vendor_id: i32,
    fabric_id: i32,
    port: i16,
    device_controller: MatterDeviceController,
    storage: StorageController,
    /// Command handlers are registered dynamically
    command_handlers: (),
    subscribers: ()
}

impl MatterServer {
    pub fn new() -> Self {
        panic!()
    }

    // Should return an unsub callable
    pub fn subscribe(&self) {}

    pub fn get_info(&self) -> ServerInfoMessage {
        todo!()
    }

    pub fn get_diagnostics(&self) -> common::ServerDiagnostics {
        todo!()
    }

    pub fn signal_event(&self, event: common::EventType, data: Option<Value>) {
        todo!()
    }

    pub fn register_api_command(&self, command: &str, handler: ()) {
        todo!()
    }
}