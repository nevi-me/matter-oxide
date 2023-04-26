use core::cell::RefCell;

use bytes::{Buf, BytesMut};
use num::FromPrimitive;
use thingbuf::mpsc::{StaticChannel, StaticSender};

use crate::{
    data_model::device::{Device, Node},
    exchange::ExchangeManager,
    message::Message,
    secure_channel::SecureChannelManager,
    transport::{udp::UdpInterface, Packet, SocketAddr},
};

pub struct EndDevice<'a, DEVICE> {
    fabrics: heapless::Vec<(), 5>,
    device: Device<'a, DEVICE>,
    pub exchange_manager: ExchangeManager,
    pub secure_channel: SecureChannelManager,
    /// Using a queue here limits the types of devices that can implement and end_device.
    /// See relevant documentation for unsupported architectures
    /// (basically whatever that doesn't support nor emulate atomics)
    pub message_sender: StaticSender<Packet>,
    // TODO: can support different network interfaces, maybe abstract this out
    // TODO: need a UDP interface that's embedded friendly
    /*
    If we abstract out the transport, how would we receive messages?
    Imagine the transport layer drives a reactor, or continuously polls.
    The transport layer would send messages to the device, and it should be
    able to receive messages back. How would that happen? The sending part
    is easy, but the receiving one I'm unsure about.
    Imagine there is a channel to send messages back to the driver, then the device
    would have to take an interface of a driver as an input. That sounds doable.

     */
}

impl<'a, 'b, DEVICE> EndDevice<'a, DEVICE> {
    /// Create a new end device
    pub async fn new(
        node: &'a Node<'a>,
        handler: DEVICE,
        message_sender: StaticSender<Packet>,
    ) -> EndDevice<'a, DEVICE> {
        Self {
            fabrics: heapless::Vec::new(),
            device: Device::new(node, handler),
            secure_channel: SecureChannelManager::new(),
            exchange_manager: ExchangeManager::new(),
            message_sender,
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
    use bytes::BytesMut;

    use super::*;

    use crate::{
        cluster::utility::basic_information::DeviceInformation,
        data_model::{
            device::Endpoint,
            device_type::{root_node::DEVICE_TYPE_ROOT_NODE, DEVICE_TYPE_EXTENDED_COLOR_LIGHT},
            endpoint::{extended_color_light_endpoint, root_endpoint},
        },
        message::ProtocolID,
        session_context::SecureChannelProtocolID,
    };
}
