#[cfg(feature = "std")]
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::BytesMut;
use thingbuf::{recycling, Recycle};

pub mod bluetooth;
// TODO: implement mdns for end_device
#[cfg(feature = "controller")]
pub mod mdns;
pub mod tcp;
pub mod udp;

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

pub enum Address {
    Ble,
    Tcp,
    Udp,
}

#[derive(Clone)]
pub struct Packet {
    pub bytes: BytesMut,
    pub recipient: Option<SocketAddress>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            bytes: BytesMut::with_capacity(1024),
            recipient: None,
        }
    }
}

impl Packet {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: BytesMut::with_capacity(capacity),
            recipient: None,
        }
    }

    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub fn shrink_to(&mut self, min_capacity: usize) {
        if self.capacity() > min_capacity {
            self.bytes.resize(min_capacity, 0u8)
        }
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.recipient = None;
    }
}

impl Recycle<Packet> for recycling::WithCapacity {
    fn new_element(&self) -> Packet {
        Packet::with_capacity(self.min_capacity())
    }

    fn recycle(&self, element: &mut Packet) {
        element.clear();
        element.shrink_to(self.max_capacity());
    }
}
