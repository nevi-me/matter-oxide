use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use crate::cluster::{Cluster, ClusterBase};

pub const CLUSTER_ID_AAAA: u16 = 0x0031;

pub struct XXXXCluster {
    pub base: ClusterBase,
}

#[repr(u16)]
#[derive(FromPrimitive)]
pub enum Attributes {
    MaxNetworks = 0x0000,
    Networks = 0x0001,
    ScanMaxtimeSeconds = 0x0002,
    // ...
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

// TODO(spec): make it conformant
/// A default XXXX cluster that complies with mandatory requirements
impl Default for XXXXCluster {
    fn default() -> Self {
        let base = ClusterBase {
            id: CLUSTER_ID_AAAA,
            classification: ClusterClassification::Utility,
            revision: 1,
            features: (), // TODO
            attributes: vec![Self::attribute_default(Attributes::MaxNetworks)],
        };

        Self { base }
    }
}

impl Cluster for XXXXCluster {
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

impl XXXXCluster {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::MaxNetworks => Attribute {
                id: attribute as _,
                value: AttributeValue::U8(0), // TODO: should be nullable
                quality: (),
                access: (),
            },
            _ => todo!(),
        }
    }
}
