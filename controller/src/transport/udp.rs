/*
Does the controller run a Matter server or does it only connect to clients?
I think the latter, except for when advertising itself as a commissioner.

In that case, it'd need to connect each time it needs to make some interaction with a client, right?
So we mostly need a UDP client as a start
 */

#[cfg(feature = "std")]
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use std::sync::Arc;

use tokio::net::UdpSocket;

#[derive(Clone, Debug)]
pub enum SocketAddress {
    V4((heapless::Vec<u8, 4>, u16)),
    V6((heapless::Vec<u16, 8>, u16)),
}

impl SocketAddress {
    #[cfg(feature = "std")]
    pub fn to_std(&self) -> std::net::SocketAddr {
        match self {
            SocketAddress::V4((addr, port)) => {
                let addr = [addr[0], addr[0], addr[2], addr[3]];
                SocketAddr::V4(SocketAddrV4::new(addr.into(), *port))
            }
            SocketAddress::V6((addr, port)) => {
                let addr = [
                    addr[0], addr[0], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ];
                SocketAddr::V6(SocketAddrV6::new(addr.into(), *port, 0, 0))
            }
        }
    }

    #[cfg(feature = "std")]
    pub fn from_std(addr: &std::net::SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4((
                heapless::Vec::from_slice(&v4.ip().octets()).unwrap(),
                v4.port(),
            )),
            SocketAddr::V6(v6) => {
                // Have to cast [u8; 16] to [u16; 8]
                let address = unsafe { core::mem::transmute::<_, &[u16; 8]>(v6.ip()) };
                Self::V6((heapless::Vec::from_slice(&address[..]).unwrap(), v6.port()))
            }
        }
    }
}

#[derive(Clone)]
pub struct UdpListener {
    local_address: SocketAddress,
    // We should be able to use different implementations with feature-gates, so we might have to abstract
    socket: Arc<UdpSocket>,
}

// Is this really a client or both client and server?
impl UdpListener {
    /// Create a new UDP client bound to a local address.
    /// The common behaviour for a server is to bind to a specific port, while a client would request any port.
    /// To request any port, specify `0.0.0.0:0` for IPv4 or `[::]:0` for IPv6.
    pub async fn new(local_address: SocketAddress) -> Self {
        let socket = Arc::new(UdpSocket::bind(local_address.to_std()).await.unwrap());

        Self {
            local_address: SocketAddress::from_std(&socket.local_addr().unwrap()),
            socket,
        }
    }

    pub fn local_address(&self) -> &SocketAddress {
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
pub struct UdpInterface {
    listener: UdpListener,
}

impl UdpInterface {
    /// Create a new instance and connect to a remote address
    pub async fn new(local_address: SocketAddress) -> Self {
        let listener = UdpListener::new(local_address).await;

        Self { listener }
    }
    /// Send a message to the remote address that we've connected to
    pub async fn send_to(&self, msg: &[u8], remote_address: SocketAddress) -> usize {
        self.listener
            .socket
            .send_to(msg, remote_address.to_std())
            .await
            .unwrap()
    }

    /// To read from the socket, it looks like one has to do their own polling,
    /// so we expose the underlying socket as a clone.
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.listener.socket.clone()
    }

    pub fn local_address(&self) -> &SocketAddress {
        &self.listener.local_address
    }
}
