use crate::{
    data_model::device::{Device, Node},
    exchange::ExchangeManager,
    message::Message,
    transport::udp::{SocketAddress, UdpInterface},
};

pub struct EndDevice<'a, DEVICE> {
    fabrics: heapless::Vec<(), 5>,
    device: Device<'a, DEVICE>,
    exchange_manager: ExchangeManager,
    /// Using a queue here limits the types of devices that can implement and end_device.
    /// See relevant documentation for unsupported architectures
    /// (basically whatever that doesn't support nor emulate emulate atomics)
    message_sender: heapless::spsc::Queue<(Message, SocketAddress), 8>,
    // TODO: can support different network interfaces, maybe abstract this out
    // TODO: need a UDP interface that's embedded friendly
    // udp: UdpInterface,
    // TODO: want to move message store to the exchange manager
}

impl<'a, DEVICE> EndDevice<'a, DEVICE> {
    /// Create a new end device
    pub const fn new(node: &'a Node<'a>, handler: DEVICE) -> Self {
        Self {
            fabrics: heapless::Vec::new(),
            device: Device::new(node, handler),
            exchange_manager: todo!(),
            message_sender: heapless::spsc::Queue::new(),
        }
    }

    /// Start the device,
    /// - Start network interfaces (BLE/Wifi/Thread)
    /// - Determine commissioning status
    /// - Broadcast on networks
    /// - Listen for new messages
    pub fn start(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        cluster::utility::basic_information::DeviceInformation,
        data_model::{
            device::Endpoint,
            device_type::{root_node::DEVICE_TYPE_ROOT_NODE, DEVICE_TYPE_EXTENDED_COLOR_LIGHT},
            endpoint::{extended_color_light_endpoint, root_endpoint},
        },
    };

    #[tokio::test]
    async fn test_end_device() {
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
            endpoints: &[
                Endpoint {
                    id: 0,
                    // Root endpoint
                    device_type: DEVICE_TYPE_ROOT_NODE,
                    clusters: &root_endpoint::CLUSTERS,
                },
                Endpoint {
                    id: 1,
                    device_type: DEVICE_TYPE_EXTENDED_COLOR_LIGHT,
                    clusters: &extended_color_light_endpoint::CLUSTERS,
                },
            ],
        };
        let device_handler = root_endpoint::handler(0, device_info).chain(
            1,
            0,
            extended_color_light_endpoint::handler(1),
        );
        let end_device = EndDevice::new(&node, device_handler);

        /*
        The device listens on port 5540. What happens when a message comes in?

        Say the device is a lighbulb, how will the lights be turned on and off?
        - Let's see with general commissioning as a start
        */
    }
}
