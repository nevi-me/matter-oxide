use num::FromPrimitive;

use crate::{
    cluster::ClusterClassification,
    data_model::{Attribute, AttributeValue},
};

use crate::cluster::Cluster;

pub const CLUSTER_ID_AAAA: u16 = 0x0031;

pub struct XXXXCluster<'a> {
    data_version: &'a u32,
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

impl<'a> XXXXCluster<'a> {
    pub const fn attribute_default(attribute: Attributes) -> Attribute {
        match attribute {
            Attributes::MaxNetworks => Attribute {
                id: attribute as _,
                quality: (),
                access: (),
            },
            _ => todo!(),
        }
    }
}
