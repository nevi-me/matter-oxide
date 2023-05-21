use num::FromPrimitive;

use crate::cluster::Cluster;
use crate::data_model::handler::{AttrDataEncoder, CmdDetails, Handler};
use crate::interaction_model::transaction::Transaction;
use crate::interaction_model::{AttributeDataIB, AttributePathIB};
use crate::session_context::SecureSessionContext;
use crate::tlv::Encoder;
use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

pub const CLUSTER_ID: u16 = 0x0030;

pub const CLUSTER: Cluster<'static> = Cluster {
    id: CLUSTER_ID,
    classification: ClusterClassification::Utility,
    revision: 1,
    features: 0,
    attributes: &[
        Attribute {
            id: Attributes::Breadcrumb as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::BasicCommissioningInfo as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::RegulatoryConfig as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::LocationCapability as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::SupportsConcurrentConnection as _,
            quality: (),
            access: (),
        },
    ],
};

pub struct GeneralCommissioningCluster {
    data_version: u32,
    fail_safe: AttributeBasicCommissioningInfo,
}

impl GeneralCommissioningCluster {
    pub fn new() -> Self {
        Self {
            data_version: 1,
            fail_safe: AttributeBasicCommissioningInfo {
                fail_safe_expiry_len_seconds: 60,
                max_cum_fail_safe_seconds: 0,
            },
        }
    }

    pub fn fail_safe(&self) -> &AttributeBasicCommissioningInfo {
        &self.fail_safe
    }

    pub fn handle_read(&self, attr: AttributePathIB, encoder: &mut Encoder) {
        todo!()
    }

    pub fn handle_invoke(
        &mut self,
        session: &mut SecureSessionContext,
        cmd: &CmdDetails,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_arm_fail_safe(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_set_regulatory_config(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_commissioning_complete(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }
}

impl Handler for GeneralCommissioningCluster {
    fn handle_read(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        todo!()
    }

    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        panic!("handle_read2 not implemented")
    }

    fn handle_write(
        &mut self,
        _attr: &AttributePathIB,
        _data: &crate::data_model::handler::TLVElement,
    ) {
        panic!("Attribute not found")
    }

    fn handle_invoke(
        &mut self,
        _transaction: &mut Transaction,
        _cmd: &CmdDetails,
        _data: &crate::data_model::handler::TLVElement,
        _encoder: crate::data_model::handler::CmdDataEncoder,
    ) {
        panic!("Command not found")
    }
}

/*
If we assume a property that clients are stateless, we could generate a client
that has no data, and then use it to interact with the server.
*/
pub struct GeneralCommissioningClient;

impl GeneralCommissioningClient {
    pub fn arm_fail_safe() {}
    pub fn set_regulatory_config() {}
    pub fn commissioning_complete() {}
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    Breadcrumb = 0,
    BasicCommissioningInfo,
    RegulatoryConfig,
    LocationCapability,
    SupportsConcurrentConnection,
    // ...
}

#[repr(u8)]
pub enum AttributeCommissioningError {
    Ok = 0,
    ValueOutsideRange = 1,
    InvalidAuthentication = 2,
    NoFailSafe = 3,
    BusyWithOtherAdmin = 4,
}

/// (11.9.5.2
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

impl GeneralCommissioningCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::Breadcrumb => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            _ => panic!(),
        }
    }
}
