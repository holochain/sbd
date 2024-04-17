const DEF_IP_DENY_DIR: &str = ".";
const DEF_IP_DENY_S: i32 = 600;
const DEF_LIMIT_FROM_IP: i32 = 4;
const DEF_LIMIT_CLIENTS: i32 = 32768;
const DEF_LIMIT_MESSAGE_BYTES: i32 = 16000;
const DEF_LIMIT_IP_BYTE_NANOS: i32 = 8000;
const DEF_LIMIT_IP_BYTE_BURST: i32 = 32768;

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

    /// Bind to this interface and port.
    /// Can be specified more than once.
    /// E.g. `--bind 0.0.0.0:0`
    /// E.g. `--bind [::]:0`
    /// E.g. `--bind 192.168.0.10:443`
    #[arg(long, verbatim_doc_comment)]
    pub bind: Vec<String>,

    /// Watch this directory, and reload TLS certificates 10s after any
    /// files change within it. Must be an exact match to the parent directory
    /// of both `--cert-pem-file` and `--priv-key-pem-file`.
    #[arg(long)]
    pub watch_reload_tls_dir: Option<std::path::PathBuf>,

    /// Use this http header to determine IP address instead of the raw
    /// TCP connection details.
    #[arg(long)]
    pub trusted_ip_header: Option<String>,

    /// The directory in which to store the blocked ip addresses.
    /// Note v4 addresses will be mapped to v6 addresses per
    /// <https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2>.
    #[arg(long, default_value = DEF_IP_DENY_DIR)]
    pub ip_deny_dir: std::path::PathBuf,

    /// How long to block ip addresses in seconds. Set to zero to block
    /// forever (or until the file is manually deleted).
    #[arg(long, default_value_t = DEF_IP_DENY_S)]
    pub ip_deny_s: i32,

    /// Bind to this backchannel interface and port.
    /// Can be specified more than once.
    /// Note, this should be a local only or virtual private interface.
    #[arg(long)]
    pub back_bind: Vec<String>,

    /// Allow incoming backchannel connections only
    /// from the following explicit addresses. Note, this is expecting direct
    /// connections, not through a proxy, so only the raw TCP address will
    /// be validated. (This ignores the --trusted-ip-header parameter).
    /// Can be specified more than once.
    /// E.g. `--back-allow-ip 192.168.0.2 --back-allow-ip 192.168.0.3`.
    #[arg(long)]
    pub back_allow_ip: Vec<String>,

    /// Try to establish outgoing backchannel connections
    /// to the following ip+port addresses.
    /// Can be specified more than once.
    /// E.g. `--back-open 192.168.0.3:1443`
    #[arg(long)]
    pub back_open: Vec<String>,

    /// Bind to this interface and port to provide prometheus metrics.
    /// Note, this should be a local only or virtual private interface.
    #[arg(long)]
    pub bind_prometheus: Option<String>,

    /// Limit connection count from a single IP.
    #[arg(long, default_value_t = DEF_LIMIT_FROM_IP)]
    pub limit_from_ip: i32,

    /// Limit client connections.
    #[arg(long, default_value_t = DEF_LIMIT_CLIENTS)]
    pub limit_clients: i32,

    /// Limit the size of individual messages in bytes.
    /// The default is 384 bytes short of 16KiB to account for overhead.
    #[arg(long, default_value_t = DEF_LIMIT_MESSAGE_BYTES)]
    pub limit_message_bytes: i32,

    /// How often in nanoseconds 1 byte is allowed to be sent from an IP.
    /// The default value of 8000 results in ~1 mbps being allowed.
    /// If the default of 32768 connections were all sending this amount
    /// at the same time, the server would need a ~33.6 gbps connection.
    /// Note, this limit is sent to clients as the limit for an individual
    /// connection. The limit on the server will be multiplied by the value
    /// of `limit_from_ip`.
    #[arg(long, default_value_t = DEF_LIMIT_IP_BYTE_NANOS)]
    pub limit_ip_byte_nanos: i32,

    /// Allow IPs to burst by this byte count.
    /// If the max message size is 16K, this value must be at least 16K.
    /// The default value provides 2 * 16K for an additional buffer.
    /// Note, this limit is not sent to clients but is the limit for an
    /// individual connection. The limit on the server will be multiplied
    /// by the value of `limit_from_ip`.
    #[arg(long, default_value_t = DEF_LIMIT_IP_BYTE_BURST)]
    pub limit_ip_byte_burst: i32,
}

impl Default for Config {
    /// Construct a new config with some defaults set.
    fn default() -> Self {
        Self {
            cert_pem_file: None,
            priv_key_pem_file: None,
            bind: Vec::new(),
            watch_reload_tls_dir: None,
            trusted_ip_header: None,
            ip_deny_dir: std::path::PathBuf::from(DEF_IP_DENY_DIR),
            ip_deny_s: DEF_IP_DENY_S,
            back_bind: Vec::new(),
            back_allow_ip: Vec::new(),
            back_open: Vec::new(),
            bind_prometheus: None,
            limit_from_ip: DEF_LIMIT_FROM_IP,
            limit_clients: DEF_LIMIT_CLIENTS,
            limit_message_bytes: DEF_LIMIT_MESSAGE_BYTES,
            limit_ip_byte_nanos: DEF_LIMIT_IP_BYTE_NANOS,
            limit_ip_byte_burst: DEF_LIMIT_IP_BYTE_BURST,
        }
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
