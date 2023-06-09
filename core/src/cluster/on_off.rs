use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{
        handler::{AttrDataEncoder, CmdDetails, Handler},
        Attribute, AttributeValue,
    },
    interaction_model::{transaction::Transaction, AttributeDataIB, AttributePathIB},
    session_context::SecureSessionContext,
    tlv::Encoder,
};

use super::{Cluster, ClusterServer};

pub const CLUSTER_ID: u16 = 0x0006;

pub const CLUSTER: Cluster<'static> = Cluster {
    id: CLUSTER_ID,
    classification: ClusterClassification::Application,
    revision: 4,
    features: 0, // Supports code LT
    attributes: &[
        Attribute {
            id: Attributes::OnOff as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::GlobalSceneControl as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::OnTime as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::OffWaitTime as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::StartUpOnOff as _,
            // TODO: encode StartUpOnOff enum
            quality: (),
            access: (),
        },
    ],
};

pub struct OnOffCluster {
    cluster_revision: u32,
    on: bool,
    global_scene_control: bool,
    on_time: u16,
    off_wait_time: u16,
    startup_on_off: StartUpOnOff,
}

impl OnOffCluster {
    pub fn new() -> Self {
        Self {
            cluster_revision: 4,
            on: false,
            global_scene_control: false,
            on_time: 0,
            off_wait_time: 0,
            startup_on_off: StartUpOnOff::Off,
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

    fn cmd_on_off_toggle(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_on_with_effect(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_on_with_recall_global_scene(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }

    fn cmd_on_with_timed_off(
        &mut self,
        session: &mut SecureSessionContext,
        data: &[u8],
        encoder: &mut Encoder,
    ) {
        todo!()
    }
}

impl Handler for OnOffCluster {
    fn handle_read(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        todo!()
    }

    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        panic!("handle_read2 not supported");
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
        _cmd: &crate::data_model::handler::CmdDetails,
        _data: &crate::data_model::handler::TLVElement,
        _encoder: crate::data_model::handler::CmdDataEncoder,
    ) {
        panic!("Command not found")
    }
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    OnOff = 0x0000,
    GlobalSceneControl = 0x4000,
    OnTime = 0x4001,
    OffWaitTime = 0x4002,
    StartUpOnOff = 0x4003,
}

#[repr(u8)]
pub enum StartUpOnOff {
    Off = 0,
    On = 1,
    Toggle = 2,
}

#[repr(u8)]
pub enum Commands {
    Off = 0x00,
    On = 0x01,
    Toggle = 0x02,
    OnWithEffect = 0x40,
    OnWithRecallGlobalScene = 0x41,
    OWithTimedOff = 0x42,
}
