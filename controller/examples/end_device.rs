use bytes::BytesMut;
use matter_controller::{
    cluster::utility::basic_information::DeviceInformation,
    data_model::{
        device::{Endpoint, Node},
        device_type::{root_node::DEVICE_TYPE_ROOT_NODE, DEVICE_TYPE_EXTENDED_COLOR_LIGHT},
        endpoint::{extended_color_light_endpoint, root_endpoint},
    },
    end_device::EndDevice,
    message::{Message, ProtocolID},
    transport::{
        mdns::{DnsServiceMode, MdnsHandler},
        udp::UdpInterface,
        Packet,
    },
};
use num::FromPrimitive;
use thingbuf::mpsc::StaticChannel;

static MESSAGE_CHANNEL: StaticChannel<Packet, 16> = StaticChannel::new();

#[tokio::main(flavor = "multi_thread")]
async fn main() {
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
    let device_handler = root_endpoint::handler(0, device_info.clone()).chain(
        1,
        0,
        extended_color_light_endpoint::handler(1),
    );
    let (message_sender, message_receiver) = MESSAGE_CHANNEL.split();
    let mut end_device = EndDevice::new(&node, device_handler, message_sender.clone()).await;

    // let local_address: std::net::SocketAddr = "192.168.86.197:5540".parse().unwrap();
    let local_address: std::net::SocketAddr = "[::]:5540".parse().unwrap();

    /*
    The above is async, so we can spawn separate tasks for
    - receiving messages from the networking layer
    - sending messages back to the networking layer
    - managing subscriptions and sending events?

    Next is to wire up the networking layer so that the device can listen to incoming messages.
    I don't have to worry about discovery for now, as I'll use the IP address directly.
     */

    /*
    The device listens on port 5540. What happens when a message comes in?

    Say the device is a lighbulb, how will the lights be turned on and off?
    - Let's see with general commissioning as a start.
      A message comes in, we should determine if an exchange exists for it,
      else create one.
    */
    let udp = UdpInterface::new(local_address).await;
    let socket = udp.socket();
    // TODO: Temp
    // socket
    //     .connect("[::]:5550".parse::<std::net::SocketAddr>().unwrap())
    //     .await
    //     .unwrap();
    // Publish mDNS service
    let mut i = 0;
    while i < 3 {
        MdnsHandler::publish_service(
            "304763D1FA4BA463",
            DnsServiceMode::Commissionable(1),
            &device_info,
        );
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        i += 1;
    }
    let send_socket = udp.socket();
    let send_future = tokio::task::spawn(async move {
        let mut bytes = BytesMut::with_capacity(1024);
        while let Some(message) = message_receiver.recv_ref().await {
            println!("Received message from channel buffer, sending to peer");
            // Send the message to destination
            let address = message.recipient.as_ref().unwrap();
            dbg!(&address);
            send_socket
                // .send(message.bytes.to_vec().as_slice())
                .send_to(message.bytes.to_vec().as_slice(), address)
                .await
                .unwrap();
            bytes.clear();
        }
    });
    let recv_future = tokio::task::spawn(async move {
        loop {
            let mut buf = [0u8; 1024];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut message = Message::decode(&buf[..len]);
            // The message could be encrypted, it could be a new exchange etc.
            // Send it to the exchange manager to take action on it
            end_device.exchange_manager.receive_message(&mut message);
            let payload_header = message.payload_header.as_ref().unwrap();
            let protocol_id: ProtocolID = ProtocolID::from_u16(payload_header.protocol_id).unwrap();
            match protocol_id {
                ProtocolID::SecureChannel => {
                    // Send the message to the secure channel manager
                    let session_context = end_device
                        .exchange_manager
                        .unsecured_session_context_mut(message.message_header.session_id);
                    let (response_message, maybe_session) = end_device
                        .secure_channel
                        .on_message(session_context, &message);

                    if let Some(session) = maybe_session {
                        end_device.exchange_manager.add_session(
                            matter_controller::session_context::SessionContext::Secure(session),
                        );
                    }

                    {
                        // Send a message by writing it directly to the channel buffer
                        let mut sender = end_device.message_sender.send_ref().await.unwrap();
                        dbg!(&peer);
                        sender.recipient = Some(peer);
                        response_message.encode(&mut sender.bytes, None);
                    }
                    println!("Sent message to channel buffer");
                    // let opcode: SecureChannelProtocolID =
                    //     SecureChannelProtocolID::from_u8(payload_header.protocol_opcode)
                    //         .unwrap();
                    // match opcode {
                    //     SecureChannelProtocolID::MRPStandaloneAck => todo!(),
                    //     SecureChannelProtocolID::MsgCounterSyncReq => todo!(),
                    //     SecureChannelProtocolID::MsgCounterSyncRsp => todo!(),
                    //     SecureChannelProtocolID::CASESigma1 => todo!(),
                    //     SecureChannelProtocolID::CASESigma2 => todo!(),
                    //     SecureChannelProtocolID::CASESigma3 => todo!(),
                    //     SecureChannelProtocolID::CASESigma2Resume => todo!(),
                    //     SecureChannelProtocolID::StatusReport => todo!(),
                    // }
                }
                ProtocolID::InteractionModel => {
                    todo!("Interaction Model")
                }
                ProtocolID::UserDirectedComm => {
                    todo!()
                }
                ProtocolID::BDX => {
                    todo!()
                }
                ProtocolID::ForTesting => {
                    todo!()
                }
            }
        }
    });
    // TODO: add a third task that terminates the 2 tasks
    let (send, recv) = tokio::join!(send_future, recv_future);
    send.unwrap();
    recv.unwrap();
}
