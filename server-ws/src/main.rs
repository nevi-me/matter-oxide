use std::net::SocketAddr;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, TypedHeader,
    },
    headers,
    response::IntoResponse,
    routing::get,
    Extension, Router, Json,
};
use common::{WsMessage, SCHEMA_VERSION};
use futures_util::{StreamExt, SinkExt};
use serde_json::json;

use crate::context::MatterContext;

mod device_controller;
mod server;
mod storage_controller;
mod context;

#[tokio::main]
async fn main() {
    // Create an axum server
    // Enable websockets
    // Implement a websocket listener
    // Interface with the controller

    let context = MatterContext::new();

    let app = Router::new()
        .merge(Router::new()
        .route("/", get(default_hander))
        .route("/ws", get(ws_handler)))
        // .layer(Extension(context))
        ;

    let addr = SocketAddr::from(([0, 0, 0, 0], 5580));
    println!("Matter WS Server listening on {addr}");
    let server =
        axum::Server::bind(&addr).serve(app.into_make_service_with_connect_info::<SocketAddr>());

    tokio::join!(server).0.unwrap();
}

async fn default_hander() -> impl IntoResponse {
    println!("default handler called");
    Json(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    // Extension(context): Extension<ApiContext>,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
        user_agent.to_string()
    } else {
        String::from("Unknown browser")
    };
    println!("`{user_agent}` at {addr} connected.");
    // Get a fresh subscription to the message broadcast
    // let ws_receiver = context.ws_broadcast.subscribe();
    // let db = context.db;
    ws.on_upgrade(move |socket| handle_socket(socket, addr))
}

async fn handle_socket(socket: WebSocket, who: SocketAddr) {
    // By splitting socket we can send and receive at the same time. In this example we will send
    // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
    let (mut sender, mut receiver) = socket.split();

    // Send the server's details as soon as the client connects
    let server_details = serde_json::to_string(&common::ServerInfoMessage {
        fabric_id: 1,
        compressed_fabric_id: 1,
        schema_version: SCHEMA_VERSION,
        min_supported_schema_version: SCHEMA_VERSION,
        sdk_version: "2023.04.06".to_string(),
        wifi_credentials_set: false,
        thread_credentials_set: false,
    }).unwrap();

    sender.send(Message::Text(server_details)).await.unwrap();

    let mut recv_task = tokio::spawn(async move {
        // Keep track of invalid messages and evict socket to prevent DoS
        let mut violations = 0;

        loop {
            if violations > 32 {
                println!("Too many websocket violations, disconnecting");
                break;
            }
            let msg = receiver.next().await;
            match msg {
                Some(Ok(Message::Text(text))) => {
                    println!("Received text message {text:?} from client {who:?}");

                    let Ok(message) = serde_json::from_str::<WsMessage>(&text) else {
                        violations += 1;
                        continue;
                    };
                    // Handle the incoming message
                    match message.command {
                        common::ApiCommand::StartListening => {
                            // Send a full dump of all nodes once and start receiving events
                            // TODO: check if listen command already called
                            let response = common::SuccessResultMessage {
                                message_id: message.message_id.clone(),
                                result: json!([]),
                            };
                            sender.send(Message::Text(serde_json::to_string(&response).unwrap())).await.unwrap()
                        },
                        common::ApiCommand::Diagnostics => todo!(),
                        common::ApiCommand::ServerInfo => todo!(),
                        common::ApiCommand::GetNodes => todo!(),
                        common::ApiCommand::GetNode => todo!(),
                        common::ApiCommand::CommissionWithCode => todo!(),
                        common::ApiCommand::CommissionOnNetwork => todo!(),
                        common::ApiCommand::SetWifiCredentials => todo!(),
                        common::ApiCommand::SetThreadDataset => todo!(),
                        common::ApiCommand::OpenCommissioningWindow => todo!(),
                        common::ApiCommand::Discover => todo!(),
                        common::ApiCommand::InterviewNode => todo!(),
                        common::ApiCommand::DeviceCommand => todo!(),
                        common::ApiCommand::RemoveNode => todo!(),
                    }
                }
                Some(Ok(Message::Binary(_))) => {
                    println!("Binary message not supported");
                    violations += 1;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                    // Do nothing (should send a pong though)
                    println!("Received ping");
                }
                Some(Ok(Message::Close(_))) => {
                    println!("Client closed connection, exit");
                    break;
                }
                Some(Err(e)) => {
                    println!("Error receiving websocket message: {e:?}");
                    break;
                }
                None => {
                    println!("No data received from websocket");
                    break;
                }
            }
        }
    });
    let mut send_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    // If any of the tasks exit, abort the other one.
    tokio::select! {
        rv_a = (&mut send_task) => {
            match rv_a {
                Ok(_) => println!("Sent messages"),
                Err(a) => println!("Error sending messages {a:?}")
            }
            recv_task.abort();
        },
        rv_b = (&mut recv_task) => {
            match rv_b {
                Ok(_) => println!("Received messages"),
                Err(b) => println!("Error receiving messages {b:?}")
            }
            send_task.abort();
        }
    };
}
