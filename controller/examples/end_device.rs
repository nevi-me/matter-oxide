use bytes::BytesMut;
use matter_controller::{
    cluster::utility::basic_information::DeviceInformation,
    data_model::{
        device::{Endpoint, Node},
        device_type::{root_node::DEVICE_TYPE_ROOT_NODE, DEVICE_TYPE_EXTENDED_COLOR_LIGHT},
        endpoint::{extended_color_light_endpoint, root_endpoint},
        handler::{AttrDataEncoder, Handler},
    },
    end_device::EndDevice,
    exchange::ExchangeMessageAction,
    interaction_model::{
        transaction::Transaction, InteractionModelProtocolOpCode, ReadRequestMessage,
        ReportDataMessage,
    },
    message::{Message, ProtocolID, SessionType},
    tlv::Encoder,
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
    let device_info_clone = device_info.clone();
    let device_handler = handler(&device_info_clone);
    let (message_sender, message_receiver) = MESSAGE_CHANNEL.split();
    let mut end_device = EndDevice::new(&node, device_handler, message_sender.clone()).await;

    // let local_address: std::net::SocketAddr = "192.168.86.197:5541".parse().unwrap();
    let local_address: std::net::SocketAddr = "[::]:5541".parse().unwrap();

    /*
    The above is async, so we can spawn separate tasks for
    - receiving messages from the networking layer
    - sending messages back to the networking layer
    - managing subscriptions and sending events?

    Next is to wire up the networking layer so that the device can listen to incoming messages.
    I don't have to worry about discovery for now, as I'll use the IP address directly.
     */

    /*
    The device listens on port 5541. What happens when a message comes in?

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
    let device_info_clone = device_info.clone();
    let mdns_future = tokio::task::spawn(async move {
        let mut i = 0;
        while i < 5 {
            MdnsHandler::publish_service(
                "304763D1FA4BA463",
                DnsServiceMode::Commissionable(1),
                &device_info_clone,
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            i += 1;
        }
    });
    let send_socket = udp.socket();
    let send_future = tokio::task::spawn(async move {
        let mut bytes = BytesMut::with_capacity(1024);
        while let Some(message) = message_receiver.recv_ref().await {
            println!("Received message from channel buffer, sending to peer");
            println!("Sending message: {:?}", hex::encode(&message.bytes));
            // Send the message to destination
            let address = message.recipient.as_ref().unwrap();
            send_socket
                .send_to(message.bytes.to_vec().as_slice(), address)
                .await
                .unwrap();
            bytes.clear();
        }
    });
    let recv_future = tokio::task::spawn(async move {
        loop {
            // TODO: use a buffer that we can allocate once
            let mut buf = [0u8; 1024];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            println!("Received message {:?}", hex::encode(&buf[..len]));
            let mut message = Message::decode(&buf[..len]);
            // println!("Decoded message: {:?}", message);
            // The message could be encrypted, it could be a new exchange etc.
            // Send it to the exchange manager to take action on it
            let action = end_device.exchange_manager.receive_message(&mut message);
            match action {
                ExchangeMessageAction::Drop => {
                    // Ignore message
                    println!(
                        "Ignoring duplicate message {}",
                        message.message_header.message_counter
                    );
                    continue;
                }
                ExchangeMessageAction::AckAndDrop => {
                    if let Some(ack) = message.next_ack() {
                        let exchange_id = message.payload_header.as_ref().unwrap().exchange_id;
                        let next_message_counter = {
                            let exchange = end_device.exchange_manager.find_exchange(exchange_id);
                            exchange.next_message_counter()
                        };
                        let ack_message = message.standalone_ack(ack, next_message_counter);
                        {
                            // Send a message by writing it directly to the channel buffer
                            let mut sender = end_device.message_sender.send_ref().await.unwrap();
                            println!("Sender bytes: {}", hex::encode(&sender.bytes));
                            sender.recipient = Some(peer);
                            let encryption_key = if message.message_header.session_type
                                == SessionType::UnsecuredSession
                            {
                                None
                            } else {
                                end_device
                                    .exchange_manager
                                    .session_context(message.message_header.session_id)
                                    .map(|s| s.encryption_key())
                                    .flatten()
                            };
                            ack_message.encode(&mut sender.bytes, encryption_key);
                        }
                    }
                }
                ExchangeMessageAction::Process => {}
            }
            let payload_header = message.payload_header.as_ref().unwrap();
            let protocol_id: ProtocolID = ProtocolID::from_u16(payload_header.protocol_id).unwrap();
            let next_ack = message.next_ack();
            // TODO: update our ack counter
            let exchange_id = payload_header.exchange_id;
            let next_message_counter = {
                if exchange_id == 0 {
                    111111
                } else {
                    let exchange = end_device.exchange_manager.find_exchange(exchange_id);
                    exchange.next_message_counter()
                }
            };
            let mut response_message = match protocol_id {
                ProtocolID::SecureChannel => {
                    // Send the message to the secure channel manager
                    let session_context = end_device
                        .exchange_manager
                        .session_context_mut(message.message_header.session_id);
                    let (response_message, maybe_session) = end_device
                        .secure_channel
                        .on_message(session_context, &message);

                    // If no message, don't do anything further
                    let Some(response_message) = response_message else {
                        continue;
                    };

                    if let Some(session) = maybe_session {
                        end_device.exchange_manager.add_session(
                            matter_controller::session_context::SessionContext::Secure(session),
                        );
                    }

                    response_message
                }
                ProtocolID::InteractionModel => {
                    // dbg!((&message.message_header, &payload_header));
                    // The Matter common vendor ID
                    // assert_eq!(payload_header.protocol_vendor_id, 0x0000);
                    let session_context = end_device
                        .exchange_manager
                        .session_context_mut(message.message_header.session_id);
                    let mut transaction = Transaction {};
                    let response_message =
                        transaction.on_message(session_context, &handler(&device_info), &message);

                    // If no message, don't do anything further
                    let Some(response_message) = response_message else {
                        continue;
                    };

                    response_message
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
            };

            // Add acknowledgement
            response_message.with_ack(next_ack);
            response_message.message_header.message_counter = next_message_counter;

            {
                // Send a message by writing it directly to the channel buffer
                let mut sender = end_device.message_sender.send_ref().await.unwrap();
                sender.recipient = Some(peer);
                // TODO: re-enable encryption once it's clear when it's used & when not
                let encryption_key =
                    if message.message_header.session_type == SessionType::UnsecuredSession {
                        None
                    } else {
                        end_device
                            .exchange_manager
                            .session_context(message.message_header.session_id)
                            .map(|s| s.encryption_key())
                            .flatten()
                    };
                response_message.encode(&mut sender.bytes, encryption_key);
            }
        }
    });
    // TODO: add a third task that terminates the 2 tasks
    let (send, recv, _) = tokio::join!(send_future, recv_future, mdns_future);
    send.unwrap();
    recv.unwrap();
}

fn handler<'a>(device_info: &'a DeviceInformation<'a>) -> impl Handler + 'a {
    root_endpoint::handler(0, device_info.clone()).chain(
        1,
        0,
        extended_color_light_endpoint::handler(1),
    )
}
