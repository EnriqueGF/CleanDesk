//! RotoDesk Relay — the fallback media path (spec sections 19–20), as a library.
//!
//! When two peers cannot establish a direct P2P link (symmetric NAT, strict
//! firewalls) the ICE agent in `rotodesk-transport` falls back to a relayed
//! candidate. This crate runs a standards-compliant **TURN server (RFC 5766,
//! UDP)** so any WebRTC stack can use it natively via `turn:` URLs plus
//! long-term credentials (RFC 5389 §10.2). The relay is intentionally dumb: it
//! only forwards traffic that is already DTLS/SRTP-encrypted end-to-end and
//! never holds session keys.
//!
//! # Configuration (environment variables)
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `ROTODESK_RELAY_PORT` | `7421` | UDP port TURN clients connect to. |
//! | `ROTODESK_RELAY_BIND` | `0.0.0.0` | Local IP to bind the listening socket and relay sockets to. |
//! | `ROTODESK_RELAY_PUBLIC_IP` | `127.0.0.1` | IP advertised inside relayed candidates. **Required** for real deployments: the default only works on loopback. |
//! | `ROTODESK_RELAY_REALM` | `rotodesk` | Authentication realm; part of the long-term credential hash. |
//! | `ROTODESK_RELAY_USERS` | *(none)* | Comma-separated `user:password` list. **At least one entry is mandatory** — the server refuses to start as an open relay. |
//! | `ROTODESK_RELAY_MIN_PORT` / `ROTODESK_RELAY_MAX_PORT` | *(any port)* | Optional inclusive range for relay allocations (useful to open a single firewall range). Both must be set together. |
//! | `ROTODESK_RELAY_COMMUNITY` | `0` | `1` accepts the public community credential and announces the relay on the DHT. |
//! | `ROTODESK_RELAY_ALLOW_PRIVATE_PEERS` | `0` | `1` relays towards loopback / link-local / private / multicast peers too (only for a relay that serves one private network). See [`guard`]. |
//! | `ROTODESK_RELAY_ALLOCATION_MAX_SECS` | `86400` | Lifetime cap per allocation; `0` = unlimited. |
//! | `ROTODESK_RELAY_ALLOCATION_MAX_BYTES` | `0` (private) / `17179869184` (community) | Bytes relayed per allocation, both directions; `0` = unlimited. |
//! | `ROTODESK_RELAY_ALLOCATION_MAX_KBPS` | `0` (private) / `25000` (community) | Sustained throughput per allocation in kbit/s; `0` = unlimited. |
//! | `ROTODESK_RELAY_MAX_ALLOCATIONS` | `1000` | Live allocations across all clients; `0` = unlimited. |
//! | `ROTODESK_RELAY_MAX_ALLOCATIONS_PER_IP` | `8` | Live allocations per source address; `0` = unlimited. |
//! | `ROTODESK_RELAY_IDENTITY` | `rotodesk-relay-identity.pem` | Ed25519 key the community relay signs its DHT record with (created if missing). |
//!
//! [`RelayConfig::from_env`] reads the real process environment;
//! [`RelayConfig::from_vars`] takes any iterator of `(key, value)` pairs so the
//! parsing is testable without touching the environment. [`run`] starts the
//! server and returns a [`RelayHandle`] that reports the bound address and
//! shuts the server down on request. The binary in `main.rs` is a thin wrapper.

pub mod guard;

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use guard::{AllocationCaps, GuardedRelayGenerator, Ledger, ListenerGuard, PeerPolicy, Quotas};

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use turn::{
    auth::{generate_auth_key, AuthHandler},
    relay::{
        relay_range::RelayAddressGeneratorRanges, relay_static::RelayAddressGeneratorStatic,
        RelayAddressGenerator,
    },
    server::{
        config::{ConnConfig, ServerConfig},
        Server,
    },
};
use webrtc_util::vnet::net::Net;

/// Realm used when `ROTODESK_RELAY_REALM` is unset.
pub const DEFAULT_REALM: &str = "rotodesk";

pub const ENV_PORT: &str = "ROTODESK_RELAY_PORT";
pub const ENV_BIND: &str = "ROTODESK_RELAY_BIND";
pub const ENV_PUBLIC_IP: &str = "ROTODESK_RELAY_PUBLIC_IP";
pub const ENV_REALM: &str = "ROTODESK_RELAY_REALM";
pub const ENV_USERS: &str = "ROTODESK_RELAY_USERS";
/// `1` enables community mode (public credentials + DHT announcement).
pub const ENV_COMMUNITY: &str = "ROTODESK_RELAY_COMMUNITY";
pub const ENV_MIN_PORT: &str = "ROTODESK_RELAY_MIN_PORT";
pub const ENV_MAX_PORT: &str = "ROTODESK_RELAY_MAX_PORT";
/// `1` relays to loopback/link-local/private/multicast peers (default: refused).
pub const ENV_ALLOW_PRIVATE_PEERS: &str = "ROTODESK_RELAY_ALLOW_PRIVATE_PEERS";
/// Per-allocation lifetime cap in seconds (`0` = unlimited).
pub const ENV_ALLOCATION_MAX_SECS: &str = "ROTODESK_RELAY_ALLOCATION_MAX_SECS";
/// Per-allocation byte cap, both directions (`0` = unlimited).
pub const ENV_ALLOCATION_MAX_BYTES: &str = "ROTODESK_RELAY_ALLOCATION_MAX_BYTES";
/// Per-allocation sustained rate in kbit/s (`0` = unlimited).
pub const ENV_ALLOCATION_MAX_KBPS: &str = "ROTODESK_RELAY_ALLOCATION_MAX_KBPS";
/// Live allocations across all clients (`0` = unlimited).
pub const ENV_MAX_ALLOCATIONS: &str = "ROTODESK_RELAY_MAX_ALLOCATIONS";
/// Live allocations per source IP (`0` = unlimited).
pub const ENV_MAX_ALLOCATIONS_PER_IP: &str = "ROTODESK_RELAY_MAX_ALLOCATIONS_PER_IP";
/// Path of the relay's Ed25519 identity (PEM) used to sign its DHT record.
pub const ENV_IDENTITY: &str = "ROTODESK_RELAY_IDENTITY";

/// Default allocation lifetime cap: one day.
pub const DEFAULT_ALLOCATION_MAX_SECS: u64 = 24 * 60 * 60;
/// Default per-allocation byte cap in community mode (16 GiB): generous for
/// a long desktop session, bounded for an open relay.
pub const DEFAULT_COMMUNITY_ALLOCATION_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Default per-allocation rate in community mode: enough for a high-quality
/// desktop stream, not enough to turn the relay into a flood source.
pub const DEFAULT_COMMUNITY_ALLOCATION_MAX_KBPS: u64 = 25_000;
/// Default live-allocation caps.
pub const DEFAULT_MAX_ALLOCATIONS: usize = 1000;
pub const DEFAULT_MAX_ALLOCATIONS_PER_IP: usize = 8;
/// Default identity file, relative to the working directory.
pub const DEFAULT_IDENTITY_PATH: &str = "rotodesk-relay-identity.pem";

/// Errors produced while turning environment variables into a [`RelayConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{var}: invalid value {value:?} ({reason})")]
    Invalid {
        var: &'static str,
        value: String,
        reason: String,
    },
    #[error(
        "{ENV_USERS} is empty: at least one `user:password` entry is required \
         (an unauthenticated relay would be an open proxy)"
    )]
    NoUsers,
    #[error(
        "{ENV_USERS}: entry #{index} is malformed, expected `user:password` with non-empty fields"
    )]
    MalformedUser { index: usize },
    #[error("{ENV_USERS}: duplicate user {user:?}")]
    DuplicateUser { user: String },
    #[error("{ENV_MIN_PORT} and {ENV_MAX_PORT} must be set together")]
    PartialPortRange,
    #[error("relay port range {min}-{max} is invalid (need 1 <= min <= max)")]
    BadPortRange { min: u16, max: u16 },
}

/// Errors produced while starting or stopping the relay.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("binding {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("turn: {0}")]
    Turn(#[from] turn::Error),
}

/// One long-term credential. `Debug` deliberately redacts the password so a
/// dumped config never leaks secrets into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayUser {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for RelayUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayUser")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Inclusive UDP port range used for relay allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

/// Fully resolved relay configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub public_ip: IpAddr,
    pub realm: String,
    pub users: Vec<RelayUser>,
    pub port_range: Option<PortRange>,
    /// Community mode: accept the public RotoDesk community credentials and
    /// announce this relay on the BitTorrent DHT so any client can find it.
    pub community: bool,
    /// Relay to loopback / link-local / private / multicast peers.
    pub allow_private_peers: bool,
    /// Per-allocation limits (`0` = unlimited).
    pub quotas: Quotas,
    /// Live allocation caps (`0` = unlimited).
    pub caps: AllocationCaps,
    /// Where the relay's signing identity lives (community mode).
    pub identity_path: PathBuf,
}

impl RelayConfig {
    /// Parse from the real process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(std::env::vars())
    }

    /// Parse from an arbitrary set of `(key, value)` pairs. Unknown keys are
    /// ignored so the whole environment can be passed in unchanged.
    pub fn from_vars<I, K, V>(vars: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        let vars: HashMap<String, String> = vars
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_owned(), v.into()))
            .collect();
        // Treat blank values like unset ones: `VAR=` in a systemd unit or a
        // `.env` file should fall back to the default, not fail to parse.
        let get = |key: &str| {
            vars.get(key)
                .map(String::as_str)
                .filter(|v| !v.trim().is_empty())
        };

        let port = match get(ENV_PORT) {
            Some(v) => parse(ENV_PORT, v)?,
            None => rotodesk_proto::DEFAULT_RELAY_PORT,
        };
        let bind = match get(ENV_BIND) {
            Some(v) => parse(ENV_BIND, v)?,
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let public_ip = match get(ENV_PUBLIC_IP) {
            Some(v) => parse(ENV_PUBLIC_IP, v)?,
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let realm = get(ENV_REALM).unwrap_or(DEFAULT_REALM).trim().to_owned();
        let community = matches!(get(ENV_COMMUNITY).map(str::trim), Some("1" | "true" | "yes" | "on"));
        let mut users = match get(ENV_USERS) {
            Some(v) => parse_users(v)?,
            None if community => Vec::new(),
            None => parse_users("")?,
        };
        if community
            && !users
                .iter()
                .any(|u| u.username == rotodesk_discovery::COMMUNITY_TURN_USER)
        {
            users.push(RelayUser {
                username: rotodesk_discovery::COMMUNITY_TURN_USER.to_string(),
                password: rotodesk_discovery::COMMUNITY_TURN_PASS.to_string(),
            });
        }

        let port_range = match (get(ENV_MIN_PORT), get(ENV_MAX_PORT)) {
            (None, None) => None,
            (Some(min), Some(max)) => {
                let min: u16 = parse(ENV_MIN_PORT, min)?;
                let max: u16 = parse(ENV_MAX_PORT, max)?;
                if min == 0 || max < min {
                    return Err(ConfigError::BadPortRange { min, max });
                }
                Some(PortRange { min, max })
            }
            _ => return Err(ConfigError::PartialPortRange),
        };

        let allow_private_peers =
            matches!(get(ENV_ALLOW_PRIVATE_PEERS).map(str::trim), Some("1" | "true" | "yes" | "on"));
        let max_secs = match get(ENV_ALLOCATION_MAX_SECS) {
            Some(v) => parse(ENV_ALLOCATION_MAX_SECS, v)?,
            None => DEFAULT_ALLOCATION_MAX_SECS,
        };
        let max_bytes = match get(ENV_ALLOCATION_MAX_BYTES) {
            Some(v) => parse(ENV_ALLOCATION_MAX_BYTES, v)?,
            None if community => DEFAULT_COMMUNITY_ALLOCATION_MAX_BYTES,
            None => 0,
        };
        let max_kbps = match get(ENV_ALLOCATION_MAX_KBPS) {
            Some(v) => parse(ENV_ALLOCATION_MAX_KBPS, v)?,
            None if community => DEFAULT_COMMUNITY_ALLOCATION_MAX_KBPS,
            None => 0,
        };
        let caps = AllocationCaps {
            total: match get(ENV_MAX_ALLOCATIONS) {
                Some(v) => parse(ENV_MAX_ALLOCATIONS, v)?,
                None => DEFAULT_MAX_ALLOCATIONS,
            },
            per_ip: match get(ENV_MAX_ALLOCATIONS_PER_IP) {
                Some(v) => parse(ENV_MAX_ALLOCATIONS_PER_IP, v)?,
                None => DEFAULT_MAX_ALLOCATIONS_PER_IP,
            },
        };
        let identity_path = PathBuf::from(get(ENV_IDENTITY).unwrap_or(DEFAULT_IDENTITY_PATH).trim());

        Ok(Self {
            bind,
            port,
            public_ip,
            realm,
            users,
            port_range,
            community,
            allow_private_peers,
            quotas: Quotas { max_secs, max_bytes, max_kbps },
            caps,
            identity_path,
        })
    }

    /// The policy applied to every relay socket.
    pub fn peer_policy(&self) -> PeerPolicy {
        PeerPolicy { allow_private: self.allow_private_peers, quotas: self.quotas }
    }

    /// Whether the advertised IP is a loopback address, i.e. the relay can only
    /// serve peers on this very machine.
    pub fn advertises_loopback(&self) -> bool {
        self.public_ip.is_loopback()
    }

    fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind, self.port)
    }
}

fn parse<T>(var: &'static str, value: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .trim()
        .parse()
        .map_err(|e: T::Err| ConfigError::Invalid {
            var,
            value: value.to_owned(),
            reason: e.to_string(),
        })
}

/// Parse `user:password[,user:password...]`. The password may itself contain
/// `:`; only the first one separates the fields. Empty entries (trailing comma)
/// are skipped, but an entry without a user or without a separator is an error
/// rather than silently ignored — a typo here must not weaken authentication.
fn parse_users(raw: &str) -> Result<Vec<RelayUser>, ConfigError> {
    let mut users: Vec<RelayUser> = Vec::new();
    for (index, entry) in raw.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (username, password) = entry
            .split_once(':')
            .ok_or(ConfigError::MalformedUser { index })?;
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            return Err(ConfigError::MalformedUser { index });
        }
        if users.iter().any(|u| u.username == username) {
            return Err(ConfigError::DuplicateUser {
                user: username.to_owned(),
            });
        }
        users.push(RelayUser {
            username: username.to_owned(),
            password: password.to_owned(),
        });
    }
    if users.is_empty() {
        return Err(ConfigError::NoUsers);
    }
    Ok(users)
}

/// Long-term credential store: username -> precomputed
/// `MD5(user:realm:password)` key. Only the derived key is kept in memory and
/// the lookup never inspects or logs the secret; the actual MESSAGE-INTEGRITY
/// comparison is done by the `turn` crate.
struct StaticUserAuth {
    keys: HashMap<String, Vec<u8>>,
}

impl StaticUserAuth {
    fn new(realm: &str, users: &[RelayUser]) -> Self {
        let keys = users
            .iter()
            .map(|u| {
                (
                    u.username.clone(),
                    generate_auth_key(&u.username, realm, &u.password),
                )
            })
            .collect();
        Self { keys }
    }
}

impl AuthHandler for StaticUserAuth {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Vec<u8>, turn::Error> {
        match self.keys.get(username) {
            Some(key) => Ok(key.clone()),
            None => {
                debug!(%src_addr, username, "unknown TURN user");
                Err(turn::Error::ErrNoSuchUser)
            }
        }
    }
}

/// A running relay. Dropping it does **not** stop the server; call
/// [`RelayHandle::shutdown`] for a clean close (allocations are released).
pub struct RelayHandle {
    server: Server,
    local_addr: SocketAddr,
}

impl RelayHandle {
    /// The address the TURN listener is actually bound to (port resolved even
    /// when `0` was requested).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the TURN server and every live allocation.
    pub async fn shutdown(&self) -> Result<(), RelayError> {
        self.server.close().await?;
        Ok(())
    }
}

/// Bind the listening socket and start serving TURN in background tasks.
pub async fn run(config: RelayConfig) -> Result<RelayHandle, RelayError> {
    let listen_addr = config.listen_addr();
    let socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|source| RelayError::Bind {
            addr: listen_addr,
            source,
        })?;
    let local_addr = socket.local_addr().map_err(|source| RelayError::Bind {
        addr: listen_addr,
        source,
    })?;

    if config.advertises_loopback() {
        warn!(
            public_ip = %config.public_ip,
            "{ENV_PUBLIC_IP} is unset or loopback: relayed candidates will only be \
             reachable from this machine. Set it to the server's public IP for real deployments."
        );
    }

    if config.allow_private_peers {
        warn!(
            "{ENV_ALLOW_PRIVATE_PEERS} is set: this relay will forward traffic to loopback, \
             link-local, private and multicast addresses reachable from this machine"
        );
    }

    // Relay sockets are bound on the same interface as the listener but the
    // address handed to clients is the public one (NAT/cloud mapping).
    let net = Arc::new(Net::new(None));
    let inner_generator: Box<dyn RelayAddressGenerator + Send + Sync> = match config.port_range {
        Some(PortRange { min, max }) => Box::new(RelayAddressGeneratorRanges {
            relay_address: config.public_ip,
            min_port: min,
            max_port: max,
            max_retries: 0, // 0 = crate default
            address: config.bind.to_string(),
            net,
        }),
        None => Box::new(RelayAddressGeneratorStatic {
            relay_address: config.public_ip,
            address: config.bind.to_string(),
            net,
        }),
    };
    // Every relay socket goes through the peer filter and the quotas, and
    // every allocation is counted against the caps.
    let ledger = Arc::new(Ledger::new(config.caps));
    let relay_addr_generator: Box<dyn RelayAddressGenerator + Send + Sync> =
        Box::new(GuardedRelayGenerator::new(inner_generator, config.peer_policy(), ledger.clone()));
    let listener: Arc<dyn webrtc_util::Conn + Send + Sync> =
        Arc::new(ListenerGuard::new(Arc::new(socket), ledger));

    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn: listener,
            relay_addr_generator,
        }],
        realm: config.realm.clone(),
        auth_handler: Arc::new(StaticUserAuth::new(&config.realm, &config.users)),
        // 0 selects the crate default (RFC 5766 §11: 10 minutes).
        channel_bind_timeout: Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await?;

    info!(
        %local_addr,
        public_ip = %config.public_ip,
        realm = %config.realm,
        users = config.users.len(),
        port_range = ?config.port_range,
        allow_private_peers = config.allow_private_peers,
        quotas = ?config.quotas,
        caps = ?config.caps,
        "RotoDesk Relay (TURN/UDP) listening"
    );

    Ok(RelayHandle { server, local_addr })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults_apply_when_only_users_given() {
        let cfg = RelayConfig::from_vars(vars(&[(ENV_USERS, "alice:s3cret")])).unwrap();
        assert_eq!(cfg.port, rotodesk_proto::DEFAULT_RELAY_PORT);
        assert_eq!(cfg.bind, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(cfg.public_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(cfg.advertises_loopback());
        assert_eq!(cfg.realm, DEFAULT_REALM);
        assert_eq!(cfg.port_range, None);
        assert_eq!(
            cfg.users,
            vec![RelayUser {
                username: "alice".into(),
                password: "s3cret".into()
            }]
        );
    }

    #[test]
    fn explicit_values_and_unknown_keys() {
        let cfg = RelayConfig::from_vars(vars(&[
            (ENV_PORT, "3478"),
            (ENV_BIND, "10.0.0.5"),
            (ENV_PUBLIC_IP, "203.0.113.7"),
            (ENV_REALM, "example"),
            (ENV_USERS, "a:1, b:pa:ss ,"),
            (ENV_MIN_PORT, "50000"),
            (ENV_MAX_PORT, "50100"),
            ("PATH", "/usr/bin"),
        ]))
        .unwrap();
        assert_eq!(cfg.port, 3478);
        assert_eq!(cfg.bind, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.public_ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert!(!cfg.advertises_loopback());
        assert_eq!(cfg.realm, "example");
        assert_eq!(
            cfg.port_range,
            Some(PortRange {
                min: 50000,
                max: 50100
            })
        );
        assert_eq!(cfg.users.len(), 2);
        // Only the first ':' separates user and password.
        assert_eq!(cfg.users[1].username, "b");
        assert_eq!(cfg.users[1].password, "pa:ss");
    }

    #[test]
    fn missing_or_blank_users_is_an_error() {
        assert!(matches!(
            RelayConfig::from_vars(vars(&[])),
            Err(ConfigError::NoUsers)
        ));
        assert!(matches!(
            RelayConfig::from_vars(vars(&[(ENV_USERS, " , ,")])),
            Err(ConfigError::NoUsers)
        ));
    }

    #[test]
    fn malformed_users_are_rejected() {
        for bad in ["alice", ":pw", "alice:", "ok:1,broken"] {
            let res = RelayConfig::from_vars(vars(&[(ENV_USERS, bad)]));
            assert!(
                matches!(res, Err(ConfigError::MalformedUser { .. })),
                "{bad:?} -> {res:?}"
            );
        }
        assert!(matches!(
            RelayConfig::from_vars(vars(&[(ENV_USERS, "a:1,a:2")])),
            Err(ConfigError::DuplicateUser { .. })
        ));
    }

    #[test]
    fn invalid_scalars_are_rejected() {
        let res = RelayConfig::from_vars(vars(&[(ENV_USERS, "a:1"), (ENV_PORT, "70000")]));
        assert!(matches!(
            res,
            Err(ConfigError::Invalid { var: ENV_PORT, .. })
        ));
        let res = RelayConfig::from_vars(vars(&[(ENV_USERS, "a:1"), (ENV_PUBLIC_IP, "nope")]));
        assert!(matches!(
            res,
            Err(ConfigError::Invalid {
                var: ENV_PUBLIC_IP,
                ..
            })
        ));
    }

    #[test]
    fn port_range_validation() {
        let res = RelayConfig::from_vars(vars(&[(ENV_USERS, "a:1"), (ENV_MIN_PORT, "5000")]));
        assert!(matches!(res, Err(ConfigError::PartialPortRange)));
        let res = RelayConfig::from_vars(vars(&[
            (ENV_USERS, "a:1"),
            (ENV_MIN_PORT, "6000"),
            (ENV_MAX_PORT, "5000"),
        ]));
        assert!(matches!(res, Err(ConfigError::BadPortRange { .. })));
    }

    #[test]
    fn peer_filter_and_quota_defaults() {
        let cfg = RelayConfig::from_vars(vars(&[(ENV_USERS, "a:1")])).unwrap();
        assert!(!cfg.allow_private_peers, "private peers refused unless opted in");
        assert_eq!(cfg.quotas, Quotas { max_secs: DEFAULT_ALLOCATION_MAX_SECS, max_bytes: 0, max_kbps: 0 });
        assert_eq!(cfg.caps, AllocationCaps { per_ip: DEFAULT_MAX_ALLOCATIONS_PER_IP, total: DEFAULT_MAX_ALLOCATIONS });
        assert_eq!(cfg.identity_path, PathBuf::from(DEFAULT_IDENTITY_PATH));
        let cfg = RelayConfig::from_vars(vars(&[(ENV_COMMUNITY, "1")])).unwrap();
        assert!(!cfg.allow_private_peers, "community mode never implies private peers");
        assert_eq!(cfg.quotas.max_bytes, DEFAULT_COMMUNITY_ALLOCATION_MAX_BYTES);
        assert_eq!(cfg.quotas.max_kbps, DEFAULT_COMMUNITY_ALLOCATION_MAX_KBPS);
        assert!(cfg.users.iter().any(|u| u.username == rotodesk_discovery::COMMUNITY_TURN_USER));
        let cfg = RelayConfig::from_vars(vars(&[
            (ENV_USERS, "a:1"),
            (ENV_ALLOW_PRIVATE_PEERS, "yes"),
            (ENV_ALLOCATION_MAX_SECS, "0"),
            (ENV_ALLOCATION_MAX_BYTES, "1024"),
            (ENV_ALLOCATION_MAX_KBPS, "500"),
            (ENV_MAX_ALLOCATIONS, "0"),
            (ENV_MAX_ALLOCATIONS_PER_IP, "3"),
            (ENV_IDENTITY, "/srv/relay.pem"),
        ]))
        .unwrap();
        assert!(cfg.allow_private_peers);
        assert_eq!(cfg.quotas, Quotas { max_secs: 0, max_bytes: 1024, max_kbps: 500 });
        assert_eq!(cfg.caps, AllocationCaps { per_ip: 3, total: 0 });
        assert_eq!(cfg.identity_path, PathBuf::from("/srv/relay.pem"));
        assert!(matches!(
            RelayConfig::from_vars(vars(&[(ENV_USERS, "a:1"), (ENV_ALLOCATION_MAX_BYTES, "lots")])),
            Err(ConfigError::Invalid { var: ENV_ALLOCATION_MAX_BYTES, .. })
        ));
    }

    #[test]
    fn debug_output_redacts_passwords() {
        let cfg = RelayConfig::from_vars(vars(&[(ENV_USERS, "alice:hunter2")])).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("alice"));
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn auth_handler_returns_key_only_for_known_users() {
        let users = vec![RelayUser {
            username: "alice".into(),
            password: "pw".into(),
        }];
        let auth = StaticUserAuth::new("rotodesk", &users);
        let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(
            auth.auth_handle("alice", "rotodesk", src).unwrap(),
            generate_auth_key("alice", "rotodesk", "pw")
        );
        assert!(auth.auth_handle("mallory", "rotodesk", src).is_err());
    }
}
