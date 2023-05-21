use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

pub const CLUSTER_ID_BOOLEAN_STATE: u16 = 0x0045;

pub struct BooleanStateCluster<'a> {
    data_version: &'a u32,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    StateValue = 0x0000,
    // ...
}

#[repr(u8)]
pub enum Commands {
    _NONE = 0x00,
}

pub enum Event {
    StateChange(bool),
}

impl<'a> BooleanStateCluster<'a> {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::StateValue => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
        }
    }
}
