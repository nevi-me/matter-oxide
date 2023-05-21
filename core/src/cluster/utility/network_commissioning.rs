use num::FromPrimitive;

use crate::{
    cluster::*,
    data_model::{
        handler::{AttrDataEncoder, Handler},
        Attribute, AttributeValue,
    },
    interaction_model::{AttributeDataIB, AttributePathIB},
    tlv::Encoder,
};

use crate::cluster::Cluster;

pub const CLUSTER_ID: u16 = 0x0031;

pub const CLUSTER: Cluster<'static> = Cluster {
    id: CLUSTER_ID,
    classification: ClusterClassification::Utility,
    revision: 1,
    features: 0,
    attributes: &[
        // TODO: use a macro for this
        ATTR_CLUSTER_REVISION,
        ATTR_FEATURE_MAP,
        ATTR_ATTRIBUTE_LIST,
        ATTR_FABRIC_INDEX,
        // ...
        Attribute {
            id: Attributes::MaxNetworks as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::Networks as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::ScanMaxtimeSeconds as _,
            quality: (),
            access: (),
        },
    ],
};

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    MaxNetworks = 0x0000,
    Networks = 0x0001,
    ScanMaxtimeSeconds = 0x0002,
    ConnectMaxTimeSeconds = 0x0003,
    InterfaceEnabled = 0x0004,
    LastNetworkingStatus = 0x0005,
    // ...
}

pub struct NetworkCommissioningCluster {
    data_version: u32,
}

#[repr(u8)]
pub enum Commands {
    ScanNetworks = 0x00,
    ScanNetworksResponse = 0x01,
    AddOrUpdateWifiNetwork = 0x02,
    AddOrUpdateThreadNetwork = 0x03,
    RemoveNetwork = 0x04,
    NetworkConfigResponse = 0x05,
    ConnectNetwork = 0x06,
    ConnectNetworkResponse = 0x07,
    ReorderNetwork = 0x08,
    // ...
}

#[repr(u8)]
pub enum WifiSecurity {
    Unencrypted = 0,
    Wep = 1,
    WpaPersonal = 2,
    Wpa2Personal = 3,
    Wpa3Personal = 4,
}

// TODO: wifi band

pub struct NetworkInfo {
    pub network_id: String,
    pub connected: bool,
}

pub struct WifiInterfaceScanResult {
    pub security: WifiSecurity,
    pub ssid: String,
    pub bssid: String,
    pub channel: u16,
    pub wifi_band: (), // TODO wifi band
    pub rssi: i8,
}

pub enum NetworkCommissioningStatus {
    Success = 0,
    OutOfRange = 1,
    BoundsExceeded = 2,
    NetworkIDNotFound = 3,
    DuplicateNetworkID = 4,
    NetworkNotFound = 5,
    RegulatoryError = 6,
    AuthFailure = 7,
    UnsupportedSecurity = 8,
    OtherConnectionFailure = 9,
    IPV6Failed = 10,
    IPBindFailed = 11,
    UnknownError = 12,
}

impl NetworkCommissioningCluster {
    pub fn new() -> Self {
        Self { data_version: 0 }
    }
    pub fn read(&self, attribute: &AttributePathIB) -> AttributeDataIB {
        if let Some(path) = attribute.attribute {
            // TODO: return error if attribute is unsupported
            if Attribute::is_system_attr(path as u16) {
                return CLUSTER.read(attribute);
            }
            let path: Attributes = Attributes::from_u32(path).unwrap();
            let mut encoder = Encoder::default();
            match path {
                Attributes::MaxNetworks => todo!(),
                Attributes::Networks => todo!(),
                Attributes::ScanMaxtimeSeconds => todo!(),
                Attributes::ConnectMaxTimeSeconds => {
                    encoder.write(
                        crate::tlv::TlvType::UnsignedInt(crate::tlv::ElementSize::Byte1),
                        crate::tlv::TagControl::ContextSpecific(0),
                        crate::tlv::TagLengthValue::Unsigned8(120),
                    );
                }
                Attributes::InterfaceEnabled => todo!(),
                Attributes::LastNetworkingStatus => todo!(),
            };
            AttributeDataIB {
                data_version: self.data_version,
                path: attribute.clone(),
                data: encoder.inner(),
                interaction_model_revision: 1,
            }
        } else {
            panic!()
        }
    }
}

impl Handler for NetworkCommissioningCluster {
    fn handle_read(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        // self.read(attr, encoder.writer)
        panic!()
    }
    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        self.read(attr)
    }
}
