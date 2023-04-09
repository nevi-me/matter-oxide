use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use super::{Cluster, ClusterBase, ClusterServer};

pub const CLUSTER_ID_ON_OFF: u16 = 0x0006;

pub struct OnOffCluster {
    pub base: ClusterBase,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    OnOff = 0x0000,
    GlobalSceneControl = 0x4000,
    OnTime = 0x4001,
    OffWaitTime = 0x4002,
    StartUpOnOff = 0x4003,
}

#[repr(u8)]
pub enum StartUpOnOff {
    Off = 0,
    On = 1,
    Toggle = 2,
}

#[repr(u8)]
pub enum Commands {
    Off = 0x00,
    On = 0x01,
    Toggle = 0x02,
    OnWithEffect = 0x40,
    OnWithRecallGlobalScene = 0x41,
    OWithTimedOff = 0x42,
}

// TODO(spec): make it conformant
/// A default on/off cluster that complies with mandatory requirements
impl Default for OnOffCluster {
    fn default() -> Self {
        let base = ClusterBase {
            id: CLUSTER_ID_ON_OFF,
            classification: ClusterClassification::Application,
            revision: 4,
            features: (),
            attributes: vec![
                Self::attribute_default(Attributes::OnOff),
                Self::attribute_default(Attributes::GlobalSceneControl),
            ],
        };

        Self { base }
    }
}

impl Cluster for OnOffCluster {
    fn base(&self) -> &ClusterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ClusterBase {
        &mut self.base
    }

    fn try_attribute_default(attribute_value: u16) -> Option<Attribute> {
        let attribute = Attributes::from_u16(attribute_value).unwrap();
        Some(Self::attribute_default(attribute))
    }
}

impl OnOffCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::OnOff => Attribute {
                id: Attributes::OnOff as _,
                value: AttributeValue::Boolean(false),
                quality: (),
                access: (),
            },
            Attributes::GlobalSceneControl => Attribute {
                id: attribute as _,
                value: AttributeValue::Boolean(true),
                quality: (),
                access: (),
            },
            Attributes::OnTime => Attribute {
                id: attribute as _,
                value: AttributeValue::U16(0),
                quality: (),
                access: (),
            },
            Attributes::OffWaitTime => Attribute {
                id: attribute as _,
                value: AttributeValue::U16(0),
                quality: (),
                access: (),
            },
            Attributes::StartUpOnOff => Attribute {
                id: attribute as _,
                // TODO: encode StartUpOnOff enum
                value: AttributeValue::Composite,
                quality: (),
                access: (),
            },
        }
    }
}

pub struct OnOffClusterServer {
    cluster: OnOffCluster,
}

impl ClusterServer for OnOffClusterServer {
    fn read_attribute(&self) {
        todo!()
    }

    fn write_attribute(&mut self) {
        todo!()
    }

    fn subscribe_attribute(&self, attribute_value: u16) {
        todo!()
    }

    fn handle_command(&mut self, command: crate::interaction_model::CommandRequest) {
        todo!()
    }
}
