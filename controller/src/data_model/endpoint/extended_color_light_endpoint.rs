//! Attribution: see other instances of ivmarkov/matter-rs::b::experiments for reference

use crate::{
    cluster::{on_off, Cluster},
    data_model::handler::EmptyHandler,
    handler_chain_type,
};

pub type ExtendedColorLightEndpointHandler<'a> = handler_chain_type!(
    // Identify
    // Groups
    // Scenes
    on_off::OnOffCluster // Level Control
                         // Color Control
);

pub const CLUSTERS: [Cluster<'static>; 1] = [on_off::CLUSTER];

pub fn handler<'a>(endpoint_id: u16) -> ExtendedColorLightEndpointHandler<'a> {
    wrap(endpoint_id)
}

pub fn wrap<'a>(endpoint_id: u16) -> ExtendedColorLightEndpointHandler<'a> {
    EmptyHandler.chain(endpoint_id, on_off::CLUSTER.id, on_off::OnOffCluster::new())
    // .chain(
    //     endpoint_id,
    //     basic_information::CLUSTER.id,
    //     basic_information::BasicInformationCluster::new(basic_info),
    // )
}
