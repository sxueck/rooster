use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr;

#[derive(Serialize)]
pub struct NetworkSnapshot {
    pub connection_ip: Option<String>,
    pub interfaces: Vec<NetworkInterface>,
}

#[derive(Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<String>,
    pub state: String,
    pub mac: Option<String>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

pub fn snapshot() -> NetworkSnapshot {
    let addresses = interface_addresses();
    let interfaces = fs::read_to_string("/proc/net/dev")
        .map(|contents| parse_proc_net_dev(&contents, &addresses))
        .unwrap_or_default();
    NetworkSnapshot {
        connection_ip: None,
        interfaces,
    }
}

fn parse_proc_net_dev(
    contents: &str,
    addresses: &BTreeMap<String, Vec<String>>,
) -> Vec<NetworkInterface> {
    contents
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (name, counters) = line.rsplit_once(':')?;
            let name = name.trim();
            let values: Vec<u64> = counters
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            if values.len() < 16 {
                return None;
            }
            let sysfs = Path::new("/sys/class/net").join(name);
            let state = fs::read_to_string(sysfs.join("operstate"))
                .map(|value| value.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let mac = fs::read_to_string(sysfs.join("address"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            Some(NetworkInterface {
                name: name.to_string(),
                addresses: addresses.get(name).cloned().unwrap_or_default(),
                state,
                mac,
                rx_bytes: values[0],
                rx_packets: values[1],
                rx_errors: values[2],
                rx_dropped: values[3],
                tx_bytes: values[8],
                tx_packets: values[9],
                tx_errors: values[10],
                tx_dropped: values[11],
            })
        })
        .collect()
}

fn interface_addresses() -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::<String, Vec<String>>::new();
    let mut head = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return result;
    }
    let _guard = IfAddrsGuard(head);
    let mut current = head;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
            let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let address = unsafe {
                match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let addr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        Some(IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())))
                    }
                    libc::AF_INET6 => {
                        let addr = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
                    }
                    _ => None,
                }
            };
            if let Some(address) = address {
                result.entry(name).or_default().push(address.to_string());
            }
        }
        current = entry.ifa_next;
    }
    for values in result.values_mut() {
        values.sort();
        values.dedup();
    }
    result
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_interface_counters_without_history() {
        let sample = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 1234 12 1 2 0 0 0 0 5678 56 3 4 0 0 0 0\n";
        let interfaces = parse_proc_net_dev(sample, &BTreeMap::new());
        assert_eq!(interfaces.len(), 1);
        let eth0 = &interfaces[0];
        assert_eq!(eth0.name, "eth0");
        assert_eq!(
            (
                eth0.rx_bytes,
                eth0.rx_packets,
                eth0.rx_errors,
                eth0.rx_dropped,
            ),
            (1234, 12, 1, 2)
        );
        assert_eq!(
            (
                eth0.tx_bytes,
                eth0.tx_packets,
                eth0.tx_errors,
                eth0.tx_dropped,
            ),
            (5678, 56, 3, 4)
        );
    }

    #[test]
    fn skips_malformed_interface_lines() {
        assert!(parse_proc_net_dev("header\nheader\neth0: broken\n", &BTreeMap::new()).is_empty());
    }
}
