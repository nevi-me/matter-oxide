use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use super::{Cluster, ClusterBase};

pub const CLUSTER_ID_BOOLEAN_STATE: u16 = 0x0045;

pub struct BooleanStateCluster<'a> {
    pub base: ClusterBase<'a>,
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

// // TODO(spec): make it conformant
// /// A default XXXX cluster that complies with mandatory requirements
// impl<'a> Default for BooleanStateCluster<'a> {
//     fn default() -> Self {
//         let base = ClusterBase {
//             id: CLUSTER_ID_BOOLEAN_STATE,
//             classification: ClusterClassification::Application,
//             revision: 1,
//             features: (), // TODO
//             attributes: &[Self::attribute_default(Attributes::StateValue)],
//             _phantom: core::marker::PhantomData::default(),
//         };

//         Self { base }
//     }
// }

impl<'a> Cluster<'a> for BooleanStateCluster<'a> {
    fn base(&self) -> &ClusterBase<'a> {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ClusterBase<'a> {
        &mut self.base
    }

    fn try_attribute_default(attribute_value: u16) -> Option<Attribute> {
        let attribute = Attributes::from_u16(attribute_value).unwrap();
        Some(Self::attribute_default(attribute))
    }
}

impl<'a> BooleanStateCluster<'a> {
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
