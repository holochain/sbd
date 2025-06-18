//! CURRENTLY A STUB!!

use crate::*;

pub struct IpDeny;

impl IpDeny {
    /// Construct a new filesystem-based ip deny list.
    pub fn new(_config: Arc<Config>) -> Self {
        Self
    }

    /// Check if a given ip is blocked.
    pub async fn is_blocked(&self, _ip: &Arc<Ipv6Addr>) -> bool {
        // TODO: THIS IS A STUB!!
        false
    }

    /// Block a given ip.
    pub async fn block(&self, _ip: &Arc<Ipv6Addr>) {
        // TODO: THIS IS A STUB!!
    }
}
