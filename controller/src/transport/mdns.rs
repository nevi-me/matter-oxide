use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
};

use libmdns::{Responder, Service};
use once_cell::sync::Lazy;
use trust_dns_client::rr::Name;

pub const MDNS_BROADCAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251); // "224.0.0.251"
pub const MDNS_BROADCAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff, 0x02, 0, 0, 0, 0, 0, 0xfb); // "ff02::fb"
pub const MDNS_BROADCAST_PORT: u16 = 5353;
pub const DNS_MATTER_PORT: u16 = 5540;

static RESPONDER: Lazy<Mutex<Responder>> = Lazy::new(|| {
    Mutex::new(
        Responder::new_with_ip_list(vec![
            IpAddr::V4(MDNS_BROADCAST_IPV4),
            IpAddr::V6(MDNS_BROADCAST_IPV6),
        ])
        .unwrap(),
    )
});

pub struct MdnsHandler {
    node_info: Option<MdnsNodeInfo>,
}

impl MdnsHandler {
    pub fn publish_service(name: &str, mode: DnsServiceMode) -> MdnsService {
        match mode {
            DnsServiceMode::Commissionable(mode) => {
                let discriminator = 0xFFu16.to_string(); // TODO
                let mode = mode.to_string();
                let txt_values = [
                    ["D", &discriminator],
                    ["CM", mode.as_str()],
                    // ...
                ];

                MdnsService::new(name, "_matterc", "_udp", DNS_MATTER_PORT, &txt_values)
            }
            DnsServiceMode::Commissioned => {
                MdnsService::new(name, "_matter", "_tcp", DNS_MATTER_PORT, &[])
            }
            DnsServiceMode::Commisioner(port) => {
                MdnsService::new(name, "_matterd", "_udp", port, &[])
            }
        }
    }
}

pub fn query_service() {
    use trust_dns_client::client::{Client, SyncClient};
    let conn = trust_dns_client::multicast::MdnsClientConnection::new_ipv6(None, Some(0xffff));
    let sync_client = SyncClient::new(conn);
    let name: Name = Name::from_utf8("_matterc._udp").unwrap();
    let result = sync_client
        .query(
            &name,
            trust_dns_client::rr::DNSClass::ANY,
            trust_dns_client::rr::RecordType::AAAA,
        )
        .unwrap();
    dbg!(result);
}

pub struct MdnsNodeInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_type: u16,
    pub device_name: String,
    pub pairing_hint: u16,
    pub pairing_instruction: u8,
}

pub struct MdnsService {
    service: Service,
}

impl MdnsService {
    fn new(name: &str, service: &str, protocol: &str, port: u16, txt_values: &[[&str; 2]]) -> Self {
        let txts = txt_values
            .iter()
            .map(|kv| format!("{}={}", kv[0], kv[2]))
            .collect::<Vec<_>>();
        let txt = txts.iter().map(|v| v.as_str()).collect::<Vec<_>>();

        let responder = RESPONDER.lock().unwrap();
        let service = responder.register(format!("{service}.{protocol}"), name.into(), port, &txt);
        Self { service }
    }
}

pub enum DnsServiceMode {
    // TODO make this an enum
    /// Specify a commissioning mode
    /// - 1: Initial commissioning
    /// - 2: In commissioning due to the Open Commisisoning Window command
    Commissionable(u8),
    Commissioned,
    /// Specify a unique port for Commissioner Discovert
    Commisioner(u16),
}

#[test]
fn test() {
    query_service()
}