use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use crate::cluster::{Cluster, ClusterBase};

pub const CLUSTER_ID_NODE_OPERATIONAL_CRED: u16 = 0x003E;

pub const CLUSTER_NOC_RESP_MAX: usize = 900;

pub struct NodeOperationalCredCluster<'a> {
    pub base: ClusterBase<'a>,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    Nocs = 0x0000,
    Fabrics = 0x0001,
    SupportedFabrics = 0x0002,
    CommissionedFabrics = 0x003,
    TrustedRootCertificates = 0x0004,
    CurrentFabricIndex = 0x0005,
}

#[repr(u8)]
pub enum Commands {
    AttestationRequest = 0x00,
    AttestationResponse = 0x01,
    CertificateChainRequest = 0x02,
    CertificateChainResponse = 0x03,
    CsrRequest = 0x04,
    CsrResponse = 0x05,
    AddNoc = 0x06,
    UpdateNoc = 0x07,
    NocResponse = 0x08,
    UpdateFabricLabel = 0x09,
    RemoveFabric = 0x0a,
    AddTrustedRootCertificate = 0x0b,
    // ...
}

pub struct NodeOperationalCredentials {
    pub noc: Vec<u8>,
    pub icac: Option<Vec<u8>>,
}

// TODO: FabricDescriptor (11.17.5.3)

pub enum NodeOperationalCredStatus {
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNoc = 3,
    MissingCsr = 4,
    TableFull = 5,
    InvalidAdminSubject = 6,
    // 7 and 8 are reserved
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}

// // TODO(spec): make it conformant
// /// A default XXXX cluster that complies with mandatory requirements
// impl<'a> Default for NodeOperationalCredCluster<'a> {
//     fn default() -> Self {
//         let base = ClusterBase {
//             id: CLUSTER_ID_NODE_OPERATIONAL_CRED,
//             classification: ClusterClassification::Utility,
//             revision: 1,
//             features: (), // TODO
//             attributes: &'a [Self::attribute_default(Attributes::Nocs)],
//             _phantom: core::marker::PhantomData::default(),
//         };

//         Self { base }
//     }
// }

impl<'a> Cluster for NodeOperationalCredCluster<'a> {
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

impl<'a> NodeOperationalCredCluster<'a> {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::Nocs => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(0), // TODO: should be nullable
                quality: (),
                access: (),
            },
            _ => todo!(),
        }
    }
}
