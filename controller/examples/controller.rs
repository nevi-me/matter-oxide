use matter_controller::{
    cluster::utility::basic_information::DeviceInformation,
    controller::Controller,
    data_model::{
        device::{Endpoint, Node},
        device_type::root_node::DEVICE_TYPE_ROOT_NODE,
        endpoint::root_endpoint,
    },
    transport::SocketAddress,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let device_info = DeviceInformation {
        vendor_id: 0xfff1,
        product_id: 0x8001,
        vendor_name: "Test vendor",
        product_name: "Test Matter Controller",
        hardware_version: 0x0001,
        software_version: 0x1001,
        hardware_version_str: "EXX-64-B1",
        software_version_str: "2023.04.01",
    };
    let node = Node {
        id: 0xfedefede,
        endpoints: &[Endpoint {
            id: 0,
            // Root endpoint
            device_type: DEVICE_TYPE_ROOT_NODE,
            clusters: &root_endpoint::CLUSTERS,
        }],
    };
    let controller_handler = root_endpoint::handler(0, device_info);
    let mut controller = Controller::new(&node, controller_handler).await;
    // let remote_address = "[::ffff:192.168.86.197]:5540"
    let remote_address = "100.71.123.113:5540"
        // let remote_address = "[fdf5:c816:9a31:0:14de:f8f3:b5aa:f677]:5540"
        .parse::<std::net::SocketAddr>()
        .unwrap();
    matter_controller::controller::commission_with_pin(
        &mut controller,
        SocketAddress::from_std(&remote_address),
        250,
        123456,
    )
    .await;
    println!("Commissioning PASE step completed");
}
