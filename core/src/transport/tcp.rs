/*
Does the controller run a Matter server or does it only connect to clients?
I think the latter, except for when advertising itself as a commissioner.

In that case, it'd need to connect each time it needs to make some interaction with a client, right?
So we mostly need a UDP client as a start
 */

use std::sync::Arc;

#[cfg(feature = "std-smol")]
use smol::net::TcpSocket;
#[cfg(feature = "std-tokio")]
use tokio::{
    io::AsyncWriteExt,
    net::{TcpSocket, TcpStream},
};

use super::SocketAddr;

#[derive(Clone)]
pub struct TcpListener {
    local_address: SocketAddr,
    // We should be able to use different implementations with feature-gates, so we might have to abstract
    socket: Arc<TcpSocket>,
}

// Is this really a client or both client and server?
impl TcpListener {
    /// Create a new UDP client bound to a local address.
    /// The common behaviour for a server is to bind to a specific port, while a client would request any port.
    /// To request any port, specify `0.0.0.0:0` for IPv4 or `[::]:0` for IPv6.
    pub async fn new(local_address: SocketAddr) -> Self {
        let socket = match local_address {
            SocketAddr::V4(_) => TcpSocket::new_v4().unwrap(),
            SocketAddr::V6(_) => TcpSocket::new_v6().unwrap(),
        };
        socket.set_reuseaddr(true).unwrap();
        socket.bind(local_address).unwrap();
        let socket = Arc::new(socket);

        Self {
            local_address: socket.local_addr().unwrap(),
            socket,
        }
    }

    pub fn local_address(&self) -> &SocketAddr {
        &self.local_address
    }
}

/*
Now that we have a client, let's:
- connect to a Metter commisisonable device
- send a message to it
- receive a response (or many) from it

A good approach would be to do this in Matter, using this abstraction of a client.
How would that look like?

We would like to receive messages and send messages out of band, why?
Because then we can separate the receipt and sending of messages and be able to act
on multiple messages being sent to us.
I feel like this is the flaw with the matter-rs implementation in that it's hard to
send multiple messages, which could hurt events.

The tokio docs say that one doesn't have to clone the socket, but can Arc::clone() it.
That could make it easy for us to have a recv loop while also handling separate sends.
 */

#[derive(Clone)]
pub struct TcpInterface {
    listener: TcpListener,
}

impl TcpInterface {
    /// Create a new instance and connect to a remote address
    pub async fn new(local_address: SocketAddr) -> Self {
        let listener = TcpListener::new(local_address).await;

        Self { listener }
    }
    /// Send a message to the remote address that we've connected to
    pub async fn send_to(&self, msg: &[u8], remote_address: SocketAddr) -> usize {
        let mut stream = TcpStream::connect(remote_address).await.unwrap();
        let msg_len = msg.len();
        stream.write_all(msg).await.unwrap();
        msg_len
    }

    /// To read from the socket, it looks like one has to do their own polling,
    /// so we expose the underlying socket as a clone.
    pub fn socket(&self) -> Arc<TcpSocket> {
        self.listener.socket.clone()
    }

    pub fn local_address(&self) -> &SocketAddr {
        &self.listener.local_address
    }
}
