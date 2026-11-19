#[cfg(target_os = "linux")]
use crate::error::EnclaveError;
#[cfg(target_os = "linux")]
use rand::RngCore;
#[cfg(target_os = "linux")]
use rand::rngs::OsRng;
#[cfg(target_os = "linux")]
use sb_proto::error::ErrorCode;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
const FLAGS_BROADCAST: u16 = 0x8000;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS_SERVERS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQ_LIST: u8 = 55;
const OPT_END: u8 = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLease {
    pub yiaddr: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub router: Option<[u8; 4]>,
    pub dns_servers: Vec<[u8; 4]>,
    pub server_id: Option<[u8; 4]>,
    pub lease_time_secs: u32,
}

/// Builds a minimal RFC 2131 `DHCPDISCOVER` broadcast frame (300 bytes).
pub fn build_dhcpv4_discover(xid: u32, mac: [u8; 6]) -> [u8; 300] {
    let mut pkt = [0u8; 300];
    pkt[0] = BOOTREQUEST;
    pkt[1] = HTYPE_ETHERNET;
    pkt[2] = HLEN_ETHERNET;
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10..12].copy_from_slice(&FLAGS_BROADCAST.to_be_bytes());
    pkt[28..34].copy_from_slice(&mac);
    pkt[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    let mut pos = 240;
    // Option 53: DHCP Message Type = DISCOVER
    pkt[pos..pos + 3].copy_from_slice(&[OPT_MSG_TYPE, 1, DHCP_DISCOVER]);
    pos += 3;
    // Option 55: Parameter Request List (Subnet Mask, Router, DNS)
    pkt[pos..pos + 5].copy_from_slice(&[
        OPT_PARAM_REQ_LIST,
        3,
        OPT_SUBNET_MASK,
        OPT_ROUTER,
        OPT_DNS_SERVERS,
    ]);
    pos += 5;
    pkt[pos] = OPT_END;
    pkt
}

/// Builds a minimal RFC 2131 `DHCPREQUEST` broadcast frame (312 bytes).
pub fn build_dhcpv4_request(
    xid: u32,
    mac: [u8; 6],
    requested_ip: [u8; 4],
    server_id: Option<[u8; 4]>,
) -> [u8; 312] {
    let mut pkt = [0u8; 312];
    pkt[0] = BOOTREQUEST;
    pkt[1] = HTYPE_ETHERNET;
    pkt[2] = HLEN_ETHERNET;
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10..12].copy_from_slice(&FLAGS_BROADCAST.to_be_bytes());
    pkt[28..34].copy_from_slice(&mac);
    pkt[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    let mut pos = 240;
    pkt[pos..pos + 3].copy_from_slice(&[OPT_MSG_TYPE, 1, DHCP_REQUEST]);
    pos += 3;
    pkt[pos..pos + 2].copy_from_slice(&[OPT_REQUESTED_IP, 4]);
    pkt[pos + 2..pos + 6].copy_from_slice(&requested_ip);
    pos += 6;
    if let Some(sid) = server_id {
        pkt[pos..pos + 2].copy_from_slice(&[OPT_SERVER_ID, 4]);
        pkt[pos + 2..pos + 6].copy_from_slice(&sid);
        pos += 6;
    }
    pkt[pos..pos + 5].copy_from_slice(&[
        OPT_PARAM_REQ_LIST,
        3,
        OPT_SUBNET_MASK,
        OPT_ROUTER,
        OPT_DNS_SERVERS,
    ]);
    pos += 5;
    pkt[pos] = OPT_END;
    pkt
}

/// Parses and validates an incoming `DHCPOFFER` or `DHCPACK` reply against `expected_xid` and `expected_mac`.
pub fn parse_dhcpv4_reply(
    pkt: &[u8],
    expected_xid: u32,
    expected_mac: [u8; 6],
) -> Option<(u8, DhcpLease)> {
    if pkt.len() < 240 {
        return None;
    }
    if pkt[0] != BOOTREPLY || pkt[1] != HTYPE_ETHERNET || pkt[2] != HLEN_ETHERNET {
        return None;
    }
    let xid = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if xid != expected_xid || pkt[28..34] != expected_mac {
        return None;
    }
    if pkt[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    let yiaddr = [pkt[16], pkt[17], pkt[18], pkt[19]];
    if yiaddr == [0, 0, 0, 0] {
        return None;
    }

    let mut msg_type: Option<u8> = None;
    let mut subnet_mask = [255, 255, 255, 0];
    let mut router: Option<[u8; 4]> = None;
    let mut dns_servers = Vec::new();
    let mut server_id: Option<[u8; 4]> = None;
    let mut lease_time_secs: u32 = 3_600;

    let mut idx = 240;
    while idx < pkt.len() {
        let code = pkt[idx];
        idx += 1;
        if code == OPT_PAD {
            continue;
        }
        if code == OPT_END {
            break;
        }
        if idx >= pkt.len() {
            return None;
        }
        let len = pkt[idx] as usize;
        idx += 1;
        if idx + len > pkt.len() {
            return None;
        }
        let val = &pkt[idx..idx + len];
        idx += len;

        match code {
            OPT_MSG_TYPE if len == 1 => {
                msg_type = Some(val[0]);
            }
            OPT_SUBNET_MASK if len == 4 => {
                subnet_mask = [val[0], val[1], val[2], val[3]];
            }
            OPT_ROUTER if len >= 4 => {
                router = Some([val[0], val[1], val[2], val[3]]);
            }
            OPT_DNS_SERVERS if len >= 4 && len.is_multiple_of(4) => {
                for &chunk in val.as_chunks::<4>().0 {
                    dns_servers.push(chunk);
                }
            }
            OPT_LEASE_TIME if len == 4 => {
                let raw_secs = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                lease_time_secs = raw_secs.clamp(60, 86_400);
            }
            OPT_SERVER_ID if len == 4 => {
                server_id = Some([val[0], val[1], val[2], val[3]]);
            }
            _ => {}
        }
    }

    let kind = msg_type?;
    Some((
        kind,
        DhcpLease {
            yiaddr,
            subnet_mask,
            router,
            dns_servers,
            server_id,
            lease_time_secs,
        },
    ))
}

#[cfg(target_os = "linux")]
pub fn acquire_dhcpv4_lease(
    ifname: &str,
    step_timeout: Duration,
) -> Result<DhcpLease, EnclaveError> {
    use std::ffi::CString;
    use std::mem::DropGuard;

    if ifname.is_empty() || ifname.len() >= libc::IFNAMSIZ {
        return Err(EnclaveError::new(
            ErrorCode::Validation,
            "invalid network interface name for DHCPv4",
        ));
    }

    // SAFETY: Creates an owned AF_INET UDP socket for DHCPv4 client negotiation (port 68 -> 67).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("DHCPv4 socket failed: {}", std::io::Error::last_os_error()),
        ));
    }
    let _fd_guard = DropGuard::new(fd, |raw| {
        // SAFETY: `raw` is owned solely by this scope.
        unsafe {
            let _ = libc::close(raw);
        }
    });

    // Bring NIC up at 0.0.0.0 and fetch its 6-byte Ethernet MAC address.
    let mac = unsafe {
        let mut flag_req: libc::ifreq = std::mem::zeroed();
        for (i, b) in ifname.bytes().enumerate() {
            flag_req.ifr_name[i] = b as libc::c_char;
        }
        if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut flag_req) == 0 {
            flag_req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let _ = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &mut flag_req);
        }

        let mut hw_req: libc::ifreq = std::mem::zeroed();
        for (i, b) in ifname.bytes().enumerate() {
            hw_req.ifr_name[i] = b as libc::c_char;
        }
        if libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut hw_req) != 0 {
            return Err(EnclaveError::new(
                ErrorCode::TransportFailure,
                format!(
                    "SIOCGIFHWADDR failed on {ifname}: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        let d = hw_req.ifr_ifru.ifru_hwaddr.sa_data;
        [
            d[0] as u8, d[1] as u8, d[2] as u8, d[3] as u8, d[4] as u8, d[5] as u8,
        ]
    };

    let c_ifname = CString::new(ifname)
        .map_err(|_| EnclaveError::new(ErrorCode::Validation, "NUL byte in NIC name"))?;

    // Configure SO_REUSEADDR, SO_BROADCAST, SO_BINDTODEVICE, and bind 0.0.0.0:68.
    unsafe {
        let one: libc::c_int = 1;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const one).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            (&raw const one).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(EnclaveError::new(
                ErrorCode::TransportFailure,
                "failed enabling SO_BROADCAST on DHCPv4 socket",
            ));
        }
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            c_ifname.as_ptr().cast(),
            c_ifname.as_bytes_with_nul().len() as libc::socklen_t,
        );

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let mut bind_addr: libc::sockaddr_in = std::mem::zeroed();
        bind_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        bind_addr.sin_port = 68u16.to_be();
        bind_addr.sin_addr.s_addr = 0;
        if libc::bind(
            fd,
            (&raw const bind_addr).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(EnclaveError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed binding DHCPv4 client port 68: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
    }

    let bcast_addr = unsafe {
        let mut dst: libc::sockaddr_in = std::mem::zeroed();
        dst.sin_family = libc::AF_INET as libc::sa_family_t;
        dst.sin_port = 67u16.to_be();
        dst.sin_addr.s_addr = u32::MAX;
        dst
    };

    let xid = OsRng.next_u32();
    let discover = build_dhcpv4_discover(xid, mac);
    let mut recv_buf = [0u8; 1500];

    for _attempt in 0..3 {
        let sent = unsafe {
            libc::sendto(
                fd,
                discover.as_ptr().cast(),
                discover.len(),
                0,
                (&raw const bcast_addr).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            continue;
        }

        let offer_deadline = Instant::now() + step_timeout;
        let mut offered: Option<DhcpLease> = None;
        while Instant::now() < offer_deadline {
            let n = unsafe { libc::recv(fd, recv_buf.as_mut_ptr().cast(), recv_buf.len(), 0) };
            if n > 0
                && let Some((DHCP_OFFER, lease)) =
                    parse_dhcpv4_reply(&recv_buf[..n as usize], xid, mac)
            {
                offered = Some(lease);
                break;
            }
        }

        let Some(offer) = offered else {
            continue;
        };

        let req = build_dhcpv4_request(xid, mac, offer.yiaddr, offer.server_id);
        let req_sent = unsafe {
            libc::sendto(
                fd,
                req.as_ptr().cast(),
                req.len(),
                0,
                (&raw const bcast_addr).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if req_sent < 0 {
            continue;
        }

        let ack_deadline = Instant::now() + step_timeout;
        while Instant::now() < ack_deadline {
            let n = unsafe { libc::recv(fd, recv_buf.as_mut_ptr().cast(), recv_buf.len(), 0) };
            if n > 0
                && let Some((DHCP_ACK, ack_lease)) =
                    parse_dhcpv4_reply(&recv_buf[..n as usize], xid, mac)
            {
                if ack_lease.yiaddr != offer.yiaddr {
                    continue;
                }
                if let Some(expected_srv) = offer.server_id
                    && ack_lease.server_id.is_some_and(|srv| srv != expected_srv)
                {
                    continue;
                }
                return Ok(ack_lease);
            }
        }
    }

    let _ = OsRng.next_u32();
    Err(EnclaveError::new(
        ErrorCode::TransportFailure,
        format!("timed out waiting for DHCPv4 lease on {ifname}"),
    ))
}

#[cfg(target_os = "linux")]
pub fn spawn_dhcpv4_renewal_daemon<F>(ifname: String, initial_lease: DhcpLease, mut apply_lease: F)
where
    F: FnMut(&DhcpLease) + Send + 'static,
{
    let _ = std::thread::Builder::new()
        .name("sb-dhcpv4-renew".into())
        .spawn(move || {
            let mut current = initial_lease;
            loop {
                let t1_secs = u64::from(current.lease_time_secs / 2).max(30);
                std::thread::sleep(Duration::from_secs(t1_secs));
                if let Ok(renewed) = acquire_dhcpv4_lease(&ifname, Duration::from_millis(2_000)) {
                    apply_lease(&renewed);
                    current = renewed;
                }
            }
        });
}
