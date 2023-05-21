use num::FromPrimitive;

use crate::{data_model::{Attribute, AttributeValue}, cluster::ClusterClassification};

use super::{ClusterBase, Cluster};

pub const CLUSTER_ID_AAAA: u16 = 0x0000;

pub struct XXXXCluster {
    pub base: ClusterBase,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    YYYY = 0x0000,
    // ...
}

#[repr(u8)]
pub enum Commands {
    ZZZZ = 0x00,
    // ...
}

// TODO(spec): make it conformant
/// A default XXXX cluster that complies with mandatory requirements
impl Default for XXXXCluster {
    fn default() -> Self {
        let base = ClusterBase {
            id: CLUSTER_ID_AAAA,
            classification: ClusterClassification::Application,
            revision: -1,
            features: (), // TODO
            attributes: vec![
                Self::attribute_default(Attributes::YYYY),
            ],
        };

        Self {
            base,
        }
    }
}

impl Cluster for XXXXCluster {
    fn base(&self) -> &ClusterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ClusterBase {
        &mut self.base
    }

    fn try_attribute_default(&self, attribute_value: u16) -> Option<Attribute> {
        let attribute = Attributes::from_u16(attribute_value).unwrap();
        Some(Self::attribute_default(attribute))
    }
}

impl XXXXCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::YYYY => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(0), // TODO: should be nullable
                quality: (),
                access: (),
            },
        }
    }
}