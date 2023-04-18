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
