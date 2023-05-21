use crate::{data_model::Attribute, interaction_model::CommandRequest};

use self::{level::LevelCluster, on_off::OnOffCluster};

pub mod boolean_state;
pub mod level;
pub mod on_off;
pub mod utility;

pub struct Cluster<'a> {
    pub id: u16,
    pub classification: ClusterClassification,
    pub revision: u8,
    pub features: u32,
    pub attributes: &'a [Attribute],
    // commands
}

/// Revision History
/// Classification
/// Cluster Identifiers
/// Attributes
/// Data Types
pub trait X {}

/// Requirements:
/// - should be able to get attributes, e.g. get_vendor_id()
/// - should be able to set attributes that are writable
/// - should be able to subscribe to attributes (should subs be per attribute?)
pub trait ClusterClient {
    fn read_attribute(&self);
    fn write_attribute(&self);
    fn subscribe_attribute(&self);
    fn send_command(&self, command: CommandRequest);
}

// A cluster server needs to be able to handle commands, how do I represent that?
// Let's take a simple cluster and use it as a starting point
pub trait ClusterServer {
    fn read_attribute(&self);
    fn write_attribute(&mut self);
    fn subscribe_attribute(&self, attribute_value: u16);
    // TODO: should return a status
    /// Handle a command and update internal state
    fn handle_command(&mut self, command: CommandRequest);
}

/// The classification of the cluster (7.10.8)
pub enum ClusterClassification {
    /// Used for the primary operation of the endpoint.
    /// Supports one or more persistent application interactions between a client and server.
    Application,
    /// Used for configuration, discovery, addressing, diagnosing, monitoring, etc.
    Utility,
}
