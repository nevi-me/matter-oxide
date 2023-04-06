use std::collections::HashMap;

use common::MatterNodeData;
use serde_json::Value;



#[derive(Clone)]
pub struct MatterDeviceController {
    controller: (),
    event_history: (),
    nodes: (),
    wifi_credentials_set: bool,
    thread_credentials_set: bool,
    compressed_fabric_id: Option<i32>,
    // Interview task?
}

impl MatterDeviceController {
    pub async fn initialize() -> Self {
        // Fetch certificates
        // Start a controller
        todo!()
    }

    pub async fn start(&self) {}

    pub async fn stop(&self) {}

    /// ws handle: [common::ApiCommand::GetNodes]
    pub async fn get_nodes(&self, only_available: bool) -> Vec<MatterNodeData> {
        vec![]
    }

    pub async fn get_node(&self, node_id: i32) -> Option<MatterNodeData> {
        None
    }

    pub async fn commission_with_code(&self, code: &str) -> Option<MatterNodeData> {
        None
    }

    pub async fn commission_on_network(&self, setup_pin_code: i32, filter_type: i32, filter: Value) -> Option<MatterNodeData> {
        None
    }

    pub async fn set_wifi_credentials(&mut self, ssid: &str, credentials: &str) {}

    pub async fn set_thread_operational_dataset(&mut self, dataset: &str) {}

    pub async fn open_commissioning_window(
        &self,
        node_id: i32,
        timeout: i32,
        iteration: i32,
        option: i32,
        discriminator: Option<i32>,
    ) -> i32 {
        0
    }

    // Returns a CommisionableNode, which is a type from CHIP
    pub async fn discover_commisionable_nodes(
        &self
    ) -> Vec<()> {
        vec![]
    }

    pub async fn interview_node(
        &self,
        node_id: i32
    ) {}

    pub async fn send_device_command(
        &self,
        node_id: i32,
        endpoint_id: i32,
        cluster_id: i32,
        command_name: &str,
        payload: HashMap<String, Value>,
        response_type: Option<Value>,
        timed_request_timeout_ms: Option<i32>,
        interaction_timeout_ms: Option<i32>,
    ) -> Value {
        panic!()
    }

    pub async fn remove_node(&self, node_id: i32) {}

    pub async fn subscribe_node(&self, node_id: i32) {}



}