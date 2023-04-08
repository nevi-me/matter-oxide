use num::FromPrimitive;

use crate::{data_model::{Attribute, AttributeValue}, cluster::ClusterClassification};

use super::{ClusterBase, Cluster};

pub const CLUSTER_ID_BOOLEAN_STATE: u16 = 0x0045;

pub struct BooleanStateCluster {
    pub base: ClusterBase,
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
    StateChange(bool)
}

// TODO(spec): make it conformant
/// A default XXXX cluster that complies with mandatory requirements
impl Default for BooleanStateCluster {
    fn default() -> Self {
        let base = ClusterBase {
            id: CLUSTER_ID_BOOLEAN_STATE,
            classification: ClusterClassification::Application,
            revision: 1,
            features: (), // TODO
            attributes: vec![
                Self::attribute_default(Attributes::StateValue),
            ],
        };

        Self {
            base,
        }
    }
}

impl Cluster for BooleanStateCluster {
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

impl BooleanStateCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::StateValue => Attribute {
                id: attribute as _,
                value: AttributeValue::Boolean(false),
                quality: (),
                access: (),
            },
        }
    }
}