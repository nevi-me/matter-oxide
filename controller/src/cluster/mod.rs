use crate::{data_model::Attribute, interaction_model::CommandRequest};

pub mod boolean_state;
pub mod level;
// pub mod on_off;
// pub mod utility;

/// Revision History
/// Classification
/// Cluster Identifiers
/// Attributes
/// Data Types
trait Cluster<'a> {
    fn base(&'a self) -> &ClusterBase<'a>;
    fn base_mut(&mut self) -> &mut ClusterBase<'a>;
    fn try_attribute_default(attribute_value: u16) -> Option<Attribute>;
}

/// Requirements:
/// - should be able to get attributes, e.g. get_vendor_id()
/// - should be able to set attributes that are writable
/// - should be able to subscribe to attributes (should subs be per attribute?)
trait ClusterClient {
    fn read_attribute(&self);
    fn write_attribute(&self);
    fn subscribe_attribute(&self);
    fn send_command(&self, command: CommandRequest);
}

// A cluster server needs to be able to handle commands, how do I represent that?
// Let's take a simple cluster and use it as a starting point
trait ClusterServer {
    fn read_attribute(&self);
    fn write_attribute(&mut self);
    fn subscribe_attribute(&self, attribute_value: u16);
    // TODO: should return a status
    /// Handle a command and update internal state
    fn handle_command(&mut self, command: CommandRequest);
}

pub struct ClusterBase<'a> {
    pub id: u16,
    pub classification: ClusterClassification,
    pub revision: u8,
    pub features: (), // big flags for FeatureMap
    pub attributes: &'a [Attribute],
    // pub _phantom: core::marker::PhantomData<&'a ()>,
}

pub struct BasicInformationCluster {
    // Server
}

/// The classification of the cluster (7.10.8)
pub enum ClusterClassification {
    /// Used for the primary operation of the endpoint.
    /// Supports one or more persistent application interactions between a client and server.
    Application,
    /// Used for configuration, discovery, addressing, diagnosing, monitoring, etc.
    Utility,
}
