pub mod bluetooth;
pub mod mdns;
pub mod tcp;
pub mod udp;

pub enum Address {
    Ble,
    Tcp,
    Udp,
}
