//! Attribution: see other instances of ivmarkov/matter-rs::b::experiments for reference

use crate::{
    cluster::{
        utility::{admin_commissioning, basic_information, general_commissioning},
        Cluster,
    },
    data_model::handler::EmptyHandler,
    handler_chain_type,
};

pub type RootEndpointHandler<'a> = handler_chain_type!(
    // AccessControlCluster<'a>,
    // NocCluster<'a>,
    admin_commissioning::AdminCommissioningCluster,
    // NwCommCluster,
    general_commissioning::GeneralCommissioningCluster,
    basic_information::BasicInformationCluster<'a>
);

pub const CLUSTERS: [Cluster<'static>; 3] = [
    admin_commissioning::CLUSTER,
    general_commissioning::CLUSTER,
    basic_information::CLUSTER,
];

pub fn handler<'a>(
    endpoint_id: u16,
    basic_info: basic_information::DeviceInformation<'a>,
) -> RootEndpointHandler<'a> {
    wrap(endpoint_id, basic_info)
}

pub fn wrap<'a>(
    endpoint_id: u16,
    basic_info: basic_information::DeviceInformation<'a>,
) -> RootEndpointHandler<'a> {
    EmptyHandler
        .chain(
            endpoint_id,
            basic_information::CLUSTER.id,
            basic_information::BasicInformationCluster::new(basic_info),
        )
        .chain(
            endpoint_id,
            general_commissioning::CLUSTER.id,
            general_commissioning::GeneralCommissioningCluster::new(),
        )
        .chain(
            endpoint_id,
            admin_commissioning::CLUSTER.id,
            admin_commissioning::AdminCommissioningCluster::new(),
        )
    // .chain(
    //     endpoint_id,
    //     nw_commissioning::CLUSTER.id,
    //     NwCommCluster::new(rand),
    // )

    // .chain(
    //     endpoint_id,
    //     noc::CLUSTER.id,
    //     NocCluster::new(dev_att, fabric, acl, failsafe, epoch, rand),
    // )
    // .chain(
    //     endpoint_id,
    //     access_control::CLUSTER.id,
    //     AccessControlCluster::new(acl, rand),
    // )
}
