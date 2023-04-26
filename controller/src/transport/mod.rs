// Note: To compile for no-std, an alternative is required here.
// no-std-net is a viable option, however it's not async and would require some
// wrapping or API adjustments.
pub use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::BytesMut;
use thingbuf::{recycling, Recycle};

pub mod bluetooth;
// TODO: implement mdns for end_device
#[cfg(feature = "controller")]
pub mod mdns;
pub mod tcp;
pub mod udp;

pub enum Address {
    Ble,
    Tcp,
    Udp,
}

#[derive(Clone)]
pub struct Packet {
    pub bytes: BytesMut,
    pub recipient: Option<SocketAddr>,
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
