#[cfg(feature = "unstable")]
const DEF_IP_DENY_DIR: &str = ".";
#[cfg(feature = "unstable")]
const DEF_IP_DENY_S: i32 = 600;
const DEF_LIMIT_CLIENTS: i32 = 32768;
const DEF_LIMIT_IP_KBPS: i32 = 1000;
const DEF_LIMIT_IP_BYTE_BURST: i32 = 16 * 16 * 1024;
const DEF_LIMIT_IDLE_MILLIS: i32 = 10_000;

/// Configure and execute an SBD server.
#[derive(clap::Parser, Debug)]
#[command(version, styles=get_styles())]
pub struct Config {
    /// TLS certificate path (pem).
    /// If specified, `--priv-key-pem-file` must also be specified.
    /// It is recommended to run acme service on port 80 and only
    /// bind SBD to port 443.
    #[arg(long)]
    pub cert_pem_file: Option<std::path::PathBuf>,

    /// TLS private key path (pem).
    /// If specified, `--cert-pem-file` must also be specified.
    /// It is recommended to run acme service on port 80 and only
    /// bind SBD to port 443.
    #[arg(long)]
    pub priv_key_pem_file: Option<std::path::PathBuf>,

    /// Bind to this interface and port. If multiple bindings specify port
    /// zero, the server will attempt to bind the same port to each interface.
    /// If it cannot, it will allow all the ports to be different.
    /// Can be specified more than once.
    /// E.g. `--bind 127.0.0.1:0 --bind [::1]:0 --bind 192.168.0.10:443`.
    #[arg(long)]
    pub bind: Vec<String>,

    #[cfg(feature = "unstable")]
    /// Watch this directory, and reload TLS certificates 10s after any
    /// files change within it. Must be an exact match to the parent directory
    /// of both `--cert-pem-file` and `--priv-key-pem-file`.
    #[arg(long)]
    pub watch_reload_tls_dir: Option<std::path::PathBuf>,

    /// Use this http header to determine IP address instead of the raw
    /// TCP connection details.
    #[arg(long)]
    pub trusted_ip_header: Option<String>,

    #[cfg(feature = "unstable")]
    /// The directory in which to store the blocked ip addresses.
    /// Note v4 addresses will be mapped to v6 addresses per
    /// <https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2>.
    #[arg(long, default_value = DEF_IP_DENY_DIR)]
    pub ip_deny_dir: std::path::PathBuf,

    #[cfg(feature = "unstable")]
    /// How long to block ip addresses in seconds. Set to zero to block
    /// forever (or until the file is manually deleted).
    #[arg(long, default_value_t = DEF_IP_DENY_S)]
    pub ip_deny_s: i32,

    #[cfg(feature = "unstable")]
    /// Bind to this backchannel interface and port.
    /// Can be specified more than once.
    /// Note, this should be a local only or virtual private interface.
    #[arg(long)]
    pub back_bind: Vec<String>,

    #[cfg(feature = "unstable")]
    /// Allow incoming backchannel connections only
    /// from the following explicit addresses. Note, this is expecting direct
    /// connections, not through a proxy, so only the raw TCP address will
    /// be validated. (This ignores the --trusted-ip-header parameter).
    /// Can be specified more than once.
    /// E.g. `--back-allow-ip 192.168.0.2 --back-allow-ip 192.168.0.3`.
    #[arg(long)]
    pub back_allow_ip: Vec<String>,

    #[cfg(feature = "unstable")]
    /// Try to establish outgoing backchannel connections
    /// to the following ip+port addresses.
    /// Can be specified more than once.
    /// E.g. `--back-open 192.168.0.3:1443`
    #[arg(long)]
    pub back_open: Vec<String>,

    #[cfg(feature = "unstable")]
    /// Bind to this interface and port to provide prometheus metrics.
    /// Note, this should be a local only or virtual private interface.
    #[arg(long)]
    pub bind_prometheus: Option<String>,

    /// Limit client connections.
    #[arg(long, default_value_t = DEF_LIMIT_CLIENTS)]
    pub limit_clients: i32,

    /// If set, rate-limiting will be disabled on the server,
    /// and clients will be informed they have an 8gbps rate limit.
    #[arg(long)]
    pub disable_rate_limiting: bool,

    /// Rate limit connections to this kilobits per second.
    /// The default value of 1000 obviously limits connections to 1 mbps.
    /// If the default of 32768 connections were all sending this amount
    /// at the same time, the server would need a ~33 gbps connection.
    /// The rate limit passed to clients will be divided by the number
    /// of open connections for a given ip address.
    #[arg(long, default_value_t = DEF_LIMIT_IP_KBPS)]
    pub limit_ip_kbps: i32,

    /// Allow IPs to burst by this byte count.
    /// If the max message size is 16K, this value must be at least 16K.
    /// The default value provides 16 * 16K to allow for multiple connections
    /// from a single ip address sending full messages at the same time.
    #[arg(long, default_value_t = DEF_LIMIT_IP_BYTE_BURST)]
    pub limit_ip_byte_burst: i32,

    /// How long in milliseconds connections can remain idle before being
    /// closed. Clients must send either a message or a keepalive before
    /// this time expires to keep the connection alive.
    #[arg(long, default_value_t = DEF_LIMIT_IDLE_MILLIS)]
    pub limit_idle_millis: i32,
}

impl Default for Config {
    /// Construct a new config with some defaults set.
    fn default() -> Self {
        Self {
            cert_pem_file: None,
            priv_key_pem_file: None,
            bind: Vec::new(),
            #[cfg(feature = "unstable")]
            watch_reload_tls_dir: None,
            trusted_ip_header: None,
            #[cfg(feature = "unstable")]
            ip_deny_dir: std::path::PathBuf::from(DEF_IP_DENY_DIR),
            #[cfg(feature = "unstable")]
            ip_deny_s: DEF_IP_DENY_S,
            #[cfg(feature = "unstable")]
            back_bind: Vec::new(),
            #[cfg(feature = "unstable")]
            back_allow_ip: Vec::new(),
            #[cfg(feature = "unstable")]
            back_open: Vec::new(),
            #[cfg(feature = "unstable")]
            bind_prometheus: None,
            limit_clients: DEF_LIMIT_CLIENTS,
            disable_rate_limiting: false,
            limit_ip_kbps: DEF_LIMIT_IP_KBPS,
            limit_ip_byte_burst: DEF_LIMIT_IP_BYTE_BURST,
            limit_idle_millis: DEF_LIMIT_IDLE_MILLIS,
        }
    }
}

impl Config {
    pub(crate) fn idle_dur(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.limit_idle_millis as u64)
    }

    /// convert kbps into the nanosecond weight of each byte
    /// (easier to rate limit with this value)
    pub(crate) fn limit_ip_byte_nanos(&self) -> i32 {
        8_000_000 / self.limit_ip_kbps
    }
}

fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(
                    anstyle::AnsiColor::Yellow,
                ))),
        )
        .header(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(
                    anstyle::AnsiColor::Yellow,
                ))),
        )
        .literal(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(
                anstyle::AnsiColor::Green,
            ))),
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(
                    anstyle::AnsiColor::Green,
                ))),
        )
        .placeholder(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(
                anstyle::AnsiColor::White,
            ))),
        )
}
