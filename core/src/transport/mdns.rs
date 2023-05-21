use core::fmt::Write;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
};

use libmdns::{Responder, Service};
use once_cell::sync::Lazy;

use crate::cluster::utility::basic_information::DeviceInformation;

pub const MDNS_BROADCAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251); // "224.0.0.251"
pub const MDNS_BROADCAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FA); // "ff02::fb"
pub const MDNS_BROADCAST_PORT: u16 = 5353;
pub const DNS_MATTER_PORT: u16 = 5541;

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
    pub fn publish_service(
        name: &str,
        mode: DnsServiceMode,
        device_info: &DeviceInformation,
    ) -> MdnsService {
        match mode {
            DnsServiceMode::Commissionable(mode) => {
                let discriminator = 0xFFu16.to_string(); // TODO
                let mode = mode.to_string();
                let vp = {
                    let mut vp = heapless::String::<11>::new();
                    write!(
                        &mut vp,
                        "{}+{}",
                        device_info.vendor_id, device_info.product_id
                    )
                    .unwrap();
                    vp
                };
                let txt_values = [
                    ["D", &discriminator],
                    ["CM", mode.as_str()],
                    ["DN", "Test Device"],
                    ["VP", vp.as_str()],
                    ["SII", "10000"],
                    ["SAI", "500"],
                    ["PI", ""], // ...
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
            .map(|kv| format!("{}={}", kv[0], kv[1]))
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

pub async fn query_service() {
    use futures_util::{pin_mut, stream::StreamExt};
    use mdns::{Error, Record, RecordKind};
    use std::{net::IpAddr, time::Duration};

    // Iterate through responses from each Cast device, asking for new devices every 15s
    let stream = mdns::discover::all("_matterc._udp.local", Duration::from_secs(15))
        .unwrap()
        .listen();
    pin_mut!(stream);

    while let Some(Ok(response)) = stream.next().await {
        let addr = response.records().collect::<Vec<_>>();
        let txt = response.txt_records().collect::<Vec<_>>();
        dbg!(&response);
        // let x = response.hostname();
        // dbg!(x);
        // dbg!(txt);

        // dbg!(addr);
    }
}

fn to_ip_addr(record: &mdns::Record) -> Option<IpAddr> {
    match record.kind {
        mdns::RecordKind::A(addr) => Some(addr.into()),
        mdns::RecordKind::AAAA(addr) => Some(addr.into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "long running test, doesn't assert anything, needs more work"]
    async fn test() {
        query_service().await
    }
}
