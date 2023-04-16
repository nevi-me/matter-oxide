use num::FromPrimitive;

use crate::cluster::{Cluster, ClusterBase};
use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

pub const CLUSTER_ID_GENERAL_COMMISSIONING: u16 = 0x0030;

pub struct GeneralCommissioningCluster<'a> {
    pub base: ClusterBase<'a>,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    Breadcrumb = 0,
    BasicCommissioningInfo,
    RegulatoryConfig,
    LocationCapability,
    SupportsConcurrentConnection, // ...
}

#[repr(u8)]
pub enum AttributeCommissioningError {
    Ok = 0,
    ValueOutsideRange = 1,
    InvalidAuthentication = 2,
    NoFailSafe = 3,
    BusyWithOtherAdmin = 4,
}

pub struct AttributeBasicCommissioningInfo {
    pub fail_safe_expiry_len_seconds: u16,
    pub max_cum_fail_safe_seconds: u16,
}

pub enum RegulatoryLocationType {
    Indoor = 0,
    Outdoor = 1,
    IndoorOutdoor = 2,
}

#[repr(u8)]
pub enum Commands {
    ArmFailSafe = 0x00,
    ArmFailSafeResponse = 0x01,
    SetRegulatoryConfig = 0x02,
    SetRegulatoryConfigResponse = 0x03,
    CommissioningComplete = 0x04,
    CommissioningCompleteResponse = 0x05,
    // ...
}

// // TODO(spec): make it conformant
// /// A default XXXX cluster that complies with mandatory requirements
// impl<'a> Default for GeneralCommissioningCluster<'a> {
//     fn default() -> Self {
//         let base = ClusterBase {
//             id: CLUSTER_ID_GENERAL_COMMISSIONING,
//             classification: ClusterClassification::Utility,
//             revision: 1,
//             features: (), // TODO
//             attributes: &[Self::attribute_default(Attributes::Breadcrumb)],
//             _phantom: core::marker::PhantomData::default(),
//         };

//         Self { base }
//     }
// }

impl<'a> Cluster for GeneralCommissioningCluster<'a> {
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

impl<'a> GeneralCommissioningCluster<'a> {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::Breadcrumb => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(0), // TODO: should be nullable
                quality: (),
                access: (),
            },
            _ => panic!(),
        }
    }
}
