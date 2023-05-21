use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

pub const CLUSTER_ID_LEVEL: u16 = 0x0008;
pub const CLUSTER_ID_LEVEL_LIGHT: u16 = CLUSTER_ID_LEVEL;
pub const CLUSTER_ID_LEVEL_PWM: u16 = 0x001C;

pub struct LevelCluster<'a> {
    data_version: &'a u32,
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

impl<'a> LevelCluster<'a> {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::CurrentLevel => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            Attributes::RemainingTime => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            Attributes::MinLevel => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            Attributes::MaxLevel => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            Attributes::CurrentFrequency => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
        }
    }
}
