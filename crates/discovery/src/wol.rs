//! Wake-on-LAN.
//!
//! A machine whose adapter has WoL enabled wakes when it sees a "magic
//! packet": 6 bytes of `0xFF` followed by its MAC address repeated 16 times,
//! anywhere in a frame. Sending it as UDP broadcast to the discard (9) and
//! echo (7) ports is the convention every NIC firmware and router understands.
//! The host publishes its MAC in the rendezvous [`Record`](crate::Record) so
//! the viewer can wake it before resolving.

use crate::{DiscoveryError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// Ports the magic packet is sent to. Neither needs a listener: the NIC
/// inspects the frame before the OS is even running.
pub const WOL_PORTS: [u16; 2] = [9, 7];

/// Copies sent per destination; WoL is fire-and-forget over UDP and a
/// sleeping NIC occasionally drops the first frame after link-up.
const REPEATS: usize = 3;

/// Parse `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF` or `AABBCCDDEEFF`
/// (case-insensitive, surrounding whitespace ignored) into its 6 bytes.
pub fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let bad = || DiscoveryError::Other(format!("invalid MAC address: {mac:?}"));
    let trimmed = mac.trim();
    let hex: String = if trimmed.len() == 12 {
        trimmed.to_string()
    } else {
        let parts: Vec<&str> = trimmed.split([':', '-']).collect();
        if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
            return Err(bad());
        }
        parts.concat()
    };
    if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Canonical `AA:BB:CC:DD:EE:FF` rendering.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// The 102-byte magic packet for `mac`.
pub fn magic_packet(mac: &[u8; 6]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(6 + 16 * 6);
    pkt.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        pkt.extend_from_slice(mac);
    }
    pkt
}

/// Send the magic packet for `mac` to the limited broadcast address
/// (`255.255.255.255`) on ports 9 and 7, plus to `broadcast` when given
/// (typically the subnet's directed broadcast, e.g. `192.168.1.255`, which
/// routers forward where the limited one is not). Each destination gets
/// three copies. Fails only if no packet at all could be sent.
pub fn send_magic_packet(mac: &str, broadcast: Option<IpAddr>) -> Result<()> {
    let packet = magic_packet(&parse_mac(mac)?);
    let mut targets: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::BROADCAST)];
    if let Some(b) = broadcast {
        if !targets.contains(&b) {
            targets.push(b);
        }
    }
    let mut sent = 0usize;
    let mut last_err: Option<std::io::Error> = None;
    for target in targets {
        let bind: SocketAddr = match target {
            IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let sock = match UdpSocket::bind(bind).and_then(|s| s.set_broadcast(true).map(|()| s)) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        for port in WOL_PORTS {
            for _ in 0..REPEATS {
                match sock.send_to(&packet, SocketAddr::new(target, port)) {
                    Ok(_) => sent += 1,
                    Err(e) => last_err = Some(e),
                }
            }
        }
    }
    if sent == 0 {
        return Err(match last_err {
            Some(e) => DiscoveryError::Io(e),
            None => DiscoveryError::Other("no Wake-on-LAN target".into()),
        });
    }
    Ok(())
}

/// MAC of the primary network adapter (the one the OS routes through), as
/// `AA:BB:CC:DD:EE:FF`. `None` when there is no usable adapter or the
/// platform refuses to tell.
pub fn local_mac_address() -> Option<String> {
    let mac = mac_address::get_mac_address().ok().flatten()?;
    let bytes = mac.bytes();
    // Some virtual/loopback adapters report an all-zero MAC; useless for WoL.
    if bytes == [0u8; 6] {
        return None;
    }
    Some(format_mac(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_accepted_notation() {
        let want = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF").unwrap(), want);
        assert_eq!(parse_mac("aa-bb-cc-dd-ee-ff").unwrap(), want);
        assert_eq!(parse_mac("AABBCCDDEEFF").unwrap(), want);
        assert_eq!(parse_mac("  aabbccddeeff\n").unwrap(), want);
        assert_eq!(parse_mac("00:11:22:33:44:55").unwrap(), [0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(format_mac(&want), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn rejects_malformed_macs() {
        for bad in [
            "",
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:FF:00",
            "AABBCCDDEEF",
            "AABBCCDDEEFFA",
            "GG:BB:CC:DD:EE:FF",
            "AA:BB:CC:DD:EE:F",
            "AA.BB.CC.DD.EE.FF",
            "AA:BB:CC:DD:EE:FFF",
            "A:ABB:CC:DD:EE:FF",
            "ZZZZZZZZZZZZ",
        ] {
            assert!(parse_mac(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn magic_packet_layout() {
        let mac = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB];
        let pkt = magic_packet(&mac);
        assert_eq!(pkt.len(), 102);
        assert!(pkt[..6].iter().all(|&b| b == 0xFF));
        for i in 0..16 {
            assert_eq!(&pkt[6 + i * 6..12 + i * 6], &mac, "repetition {i}");
        }
    }

    #[test]
    fn send_rejects_bad_mac_before_touching_the_network() {
        assert!(send_magic_packet("nope", None).is_err());
    }

    /// Sending is best-effort; it must never panic, whatever the network.
    #[test]
    fn send_to_broadcast_does_not_panic() {
        let _ = send_magic_packet("AA:BB:CC:DD:EE:FF", Some("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn local_mac_is_canonical_when_present() {
        if let Some(mac) = local_mac_address() {
            assert_eq!(mac.len(), 17);
            assert_eq!(format_mac(&parse_mac(&mac).unwrap()), mac);
        }
    }
}
