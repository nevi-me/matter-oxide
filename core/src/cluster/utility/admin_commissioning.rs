use num::FromPrimitive;

use crate::{
    cluster::{Cluster, ClusterClassification},
    data_model::{
        handler::{AttrDataEncoder, CmdDetails, Handler},
        Attribute, AttributeValue,
    },
    interaction_model::{transaction::Transaction, AttributeDataIB, AttributePathIB},
    secure_channel::pake::PASEManager,
    session_context::SecureSessionContext,
    tlv::Encoder,
};

pub const CLUSTER_ID: u16 = 0x003C;

pub const CLUSTER: Cluster<'static> = Cluster {
    id: CLUSTER_ID,
    classification: ClusterClassification::Utility,
    revision: 0,
    features: 0,
    attributes: &[
        Attribute {
            id: Attributes::WindowStatus as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::AdminFabricIndex as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::AdminVendorId as _,
            quality: (),
            access: (),
        },
    ],
};

pub struct AdminCommissioningCluster {
    cluster_revision: u32,
    pase_manager: Option<PASEManager>,
}

impl AdminCommissioningCluster {
    pub fn new() -> Self {
        Self {
            cluster_revision: 1,
            pase_manager: None,
        }
    }

    pub fn read(&self, attr: AttributePathIB, encoder: &mut Encoder) {
        todo!()
    }

    pub fn invoke(
        &mut self,
        session: &mut SecureSessionContext,
        cmd: &CmdDetails,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_open_commissioning_window(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_open_basic_commissioning_window(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_revoke_commissioning(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }
}

impl Handler for AdminCommissioningCluster {
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
