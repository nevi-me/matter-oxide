use num::FromPrimitive;

use crate::{data_model::{Attribute, AttributeValue}, cluster::ClusterClassification};

use super::{ClusterBase, Cluster};

pub const CLUSTER_ID_LEVEL: u16 = 0x0008;
pub const CLUSTER_ID_LEVEL_LIGHT: u16 = CLUSTER_ID_LEVEL;
pub const CLUSTER_ID_LEVEL_PWM: u16 = 0x001C;

pub struct LevelCluster {
    pub base: ClusterBase,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    CurrentLevel = 0x0000,
    RemainingTime = 0x0001,
    MinLevel = 0x0002,
    MaxLevel = 0x0003,
    CurrentFrequency = 0x0004,
    // ...
}

// #[repr(u8)]
// pub enum StartUpOnOff {
//     Off = 0,
//     On = 1,
//     Toggle = 2,
// }

#[repr(u8)]
pub enum Commands {
    MoveToLevel = 0x00,
    Move = 0x01,
    Step = 0x02,
    Stop = 0x03,
    // ...
}

// TODO(spec): make it conformant
/// A default level cluster that complies with mandatory requirements
impl Default for LevelCluster {
    fn default() -> Self {
        let base = ClusterBase {
            id: CLUSTER_ID_LEVEL,
            classification: ClusterClassification::Application,
            revision: 5,
            features: (), // TODO
            attributes: vec![
                Self::attribute_default(Attributes::CurrentLevel),
                Self::attribute_default(Attributes::RemainingTime),
            ],
        };

        Self {
            base,
        }
    }
}

impl Cluster for LevelCluster {
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

impl LevelCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::CurrentLevel => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(0), // TODO: should be nullable
                quality: (),
                access: (),
            },
            Attributes::RemainingTime => Attribute {
                id: attribute as _,
                value: AttributeValue::U16(0),
                quality: (),
                access: (),
            },
            Attributes::MinLevel => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(1),
                quality: (),
                access: (),
            },
            Attributes::MaxLevel => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(254),
                quality: (),
                access: (),
            },
            Attributes::CurrentFrequency => Attribute {
                id: attribute as _,
                value: AttributeValue::U16(0),
                quality: (),
                access: (),
            },
        }
    }
}