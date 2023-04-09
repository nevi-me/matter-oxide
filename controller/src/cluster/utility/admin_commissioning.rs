use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use crate::cluster::{Cluster, ClusterBase};

pub const CLUSTER_ID_ADMIN_COMMISSIONING: u16 = 0x003C;

pub struct AdminCommissioningCluster {
    pub base: ClusterBase,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    WindowStatus = 0x0000,
    AdminFabricIndex = 0x0001,
    AdminVendorId = 0x0002,
    // ...
}

#[repr(u8)]
pub enum Commands {
    OpenCommissioningWindow = 0x00,
    OpenBasicCommissioningWindow = 0x01,
    RevokeCommissioning = 0x02,
    // ...
}

#[repr(u8)]
pub enum CommissioningWindowStatus {
    WindowNotOpen = 0,
    EnhancedWindowOpen = 1,
    BasicWindowOpen = 2,
}

pub enum AdminCommissioningStatus {
    Busy = 2,
    PAKEParameterError = 3,
    WindowNotOpen = 4,
}

// TODO(spec): make it conformant
/// A default XXXX cluster that complies with mandatory requirements
impl Default for AdminCommissioningCluster {
    fn default() -> Self {
        let base = ClusterBase {
            id: CLUSTER_ID_ADMIN_COMMISSIONING,
            classification: ClusterClassification::Utility,
            revision: 1,
            features: (), // TODO
            attributes: vec![],
        };

        Self { base }
    }
}

impl Cluster for AdminCommissioningCluster {
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

impl AdminCommissioningCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::WindowStatus => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(0), // TODO: should be nullable
                quality: (),
                access: (),
            },
            _ => todo!(),
        }
    }
}
