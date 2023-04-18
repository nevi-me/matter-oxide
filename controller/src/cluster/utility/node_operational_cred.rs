use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use crate::cluster::Cluster;

pub const CLUSTER_ID_NODE_OPERATIONAL_CRED: u16 = 0x003E;

pub const CLUSTER_NOC_RESP_MAX: usize = 900;

pub struct NodeOperationalCredCluster<'a> {
    data_version: &'a u32,
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

impl<'a> NodeOperationalCredCluster<'a> {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::Nocs => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            _ => todo!(),
        }
    }
}
