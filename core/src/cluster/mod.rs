use num::FromPrimitive;

use crate::{
    data_model::Attribute,
    interaction_model::{AttributeDataIB, AttributePathIB, CommandRequest},
    tlv::Encoder,
};

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

impl<'a> Cluster<'a> {
    pub const fn new(
        id: u16,
        classification: ClusterClassification,
        revision: u8,
        features: u32,
        attributes: &'a [Attribute],
    ) -> Self {
        Self {
            id,
            classification,
            revision,
            features,
            attributes,
        }
    }

    pub fn read(&self, attribute: &AttributePathIB) -> AttributeDataIB {
        let path = attribute.attribute.unwrap();
        let path: GlobalAttributes = GlobalAttributes::from_u32(path).unwrap();
        let mut encoder = Encoder::default();
        match path {
            GlobalAttributes::ClusterRevision => todo!(),
            GlobalAttributes::FeatureMap => encoder.write(
                crate::tlv::TlvType::UnsignedInt(crate::tlv::ElementSize::Byte4),
                crate::tlv::TagControl::ContextSpecific(0),
                crate::tlv::TagLengthValue::Unsigned32(self.features),
            ),
            GlobalAttributes::AttributeList => todo!(),
            GlobalAttributes::EventList => todo!(),
            GlobalAttributes::AcceptedCommandList => todo!(),
            GlobalAttributes::GeneratedCommandList => todo!(),
            GlobalAttributes::FabricIndex => todo!(),
        }
        AttributeDataIB {
            data_version: 1,
            path: attribute.clone(),
            data: encoder.inner(),
            interaction_model_revision: self.revision,
        }
    }
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum GlobalAttributes {
    ClusterRevision = 0xFFFD,
    FeatureMap = 0xFFFC,
    AttributeList = 0xFFFB,
    EventList = 0xFFFA,
    AcceptedCommandList = 0xFFF9,
    GeneratedCommandList = 0xFFF8,
    FabricIndex = 0xFE,
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

// Global attributes
pub const ATTR_CLUSTER_REVISION: Attribute = Attribute {
    id: GlobalAttributes::ClusterRevision as _,
    quality: (),
    access: (),
};
pub const ATTR_FEATURE_MAP: Attribute = Attribute {
    id: 0xFFFC,
    quality: (),
    access: (),
};
pub const ATTR_ATTRIBUTE_LIST: Attribute = Attribute {
    id: 0xFFFB,
    quality: (),
    access: (),
};
pub const ATTR_EVENT_LIST: Attribute = Attribute {
    id: 0xFFFA,
    quality: (),
    access: (),
};
pub const ATTR_ACCEPTED_COMMAND_LIST: Attribute = Attribute {
    id: 0xFFF9,
    quality: (),
    access: (),
};
pub const ATTR_GENERATED_COMMAND_LIST: Attribute = Attribute {
    id: 0xFFF8,
    quality: (),
    access: (),
};
pub const ATTR_FABRIC_INDEX: Attribute = Attribute {
    id: 0xFE,
    quality: (),
    access: (),
};
