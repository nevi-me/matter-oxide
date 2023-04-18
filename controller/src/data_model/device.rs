use core::marker::PhantomData;

use crate::cluster::{
    self,
    utility::{
        basic_information::DeviceInformation, general_commissioning::GeneralCommissioningCluster,
    },
    Cluster, ClusterClassification,
};

use super::{device_type::root_node::DEVICE_TYPE_ROOT_NODE, endpoint::root_endpoint};

pub struct Device<'a, H> {
    pub node: &'a Node<'a>,
    // ACL
    pub handler: H,
}

impl<'a, H> Device<'a, H> {
    pub const fn new(node: &'a Node<'a>, handler: H) -> Self {
        Self { node, handler }
    }
}

/// Node (7.8)
pub struct Node<'a> {
    pub id: u64,
    pub endpoints: &'a [Endpoint<'a>],
}

pub struct Endpoint<'a> {
    pub id: u16,
    pub device_type: DeviceType,
    pub clusters: &'a [Cluster<'a>],
}

/// Device Type (7.15)
pub struct DeviceType {
    pub device_type: u16,
    pub device_revision: u16,
}

#[test]
fn test_create_device() {
    let device_info = DeviceInformation {
        vendor_id: 0xfff1,
        product_id: 0x8000,
        vendor_name: "Test vendor",
        product_name: "Empty Matter Device",
        hardware_version: 0x0001,
        software_version: 0x1001,
        hardware_version_str: "EXX-64-A1",
        software_version_str: "2023.04.01",
    };
    let node = Node {
        id: 0xf345843f,
        endpoints: &[Endpoint {
            id: 0,
            // Root endpoint
            device_type: DEVICE_TYPE_ROOT_NODE,
            clusters: &root_endpoint::CLUSTERS,
        }],
    };
    let mut device = Device::new(&node, root_endpoint::handler(0, device_info));
}
