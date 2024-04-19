use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Map = HashMap<Arc<std::net::Ipv6Addr>, u64>;

pub struct IpRate {
    origin: tokio::time::Instant,
    map: Arc<Mutex<Map>>,
    disabled: bool,
    limit: u64,
    burst: u64,
    ip_deny: crate::ip_deny::IpDeny,
}

impl IpRate {
    /// Construct a new IpRate limit instance.
    pub fn new(config: Arc<crate::Config>) -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            map: Arc::new(Mutex::new(HashMap::new())),
            disabled: config.disable_rate_limiting,
            limit: config.limit_ip_byte_nanos() as u64,
            burst: config.limit_ip_byte_burst as u64
                * config.limit_ip_byte_nanos() as u64,
            ip_deny: crate::ip_deny::IpDeny::new(config),
        }
    }

    /// Prune entries that have tracked backwards 10s or more.
    /// The 10s just prevents hashtable thrashing if a connection
    /// is using significantly less than its rate limit.
    /// This is why the keepalive interval is 5 seconds and
    /// connections are closed after 10 seconds.
    pub fn prune(&self) {
        let now = self.origin.elapsed().as_nanos() as u64;
        self.map.lock().unwrap().retain(|_, cur| {
            if now <= *cur {
                true
            } else {
                // examples using seconds:
                // now:100,cur:120 100-120=-20<10  true=keep
                // now:100,cur:100 100-100=0<10    true=keep
                // now:100,cur:80   100-80=20<10  false=prune
                now - *cur < 10_000_000_000
            }
        });
    }

    /// Return true if this ip is blocked.
    pub async fn is_blocked(&self, ip: &Arc<std::net::Ipv6Addr>) -> bool {
        self.ip_deny.is_blocked(ip).await
    }

    /// Return true if we are not over the rate limit.
    pub async fn is_ok(
        &self,
        ip: &Arc<std::net::Ipv6Addr>,
        bytes: usize,
    ) -> bool {
        if self.disabled {
            return true;
        }

        // multiply by our rate allowed per byte
        let rate_add = bytes as u64 * self.limit;

        // get now
        let now = self.origin.elapsed().as_nanos() as u64;

        let is_ok = {
            // lock the map mutex
            let mut lock = self.map.lock().unwrap();

            // get the entry (default to now)
            let e = lock.entry(ip.clone()).or_insert(now);

            // if we've already used time greater than now use that,
            // otherwise consider we're starting from scratch
            let cur = std::cmp::max(*e, now) + rate_add;

            // update the map with the current limit
            *e = cur;

            // subtract now back out to see if we're greater than our burst
            cur - now <= self.burst
        };

        if !is_ok {
            self.ip_deny.block(ip).await;
        }

        is_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_new(limit: u64, burst: u64) -> IpRate {
        IpRate {
            origin: tokio::time::Instant::now(),
            map: Arc::new(Mutex::new(HashMap::new())),
            disabled: false,
            limit,
            burst,
            ip_deny: crate::ip_deny::IpDeny::new(Arc::new(
                crate::Config::default(),
            )),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn check_one_to_one() {
        let addr1 = Arc::new(std::net::Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1));

        let rate = test_new(1, 1);

        for _ in 0..10 {
            // should always be ok when advancing with time
            tokio::time::advance(std::time::Duration::from_nanos(1)).await;
            assert!(rate.is_ok(&addr1, 1).await);
        }

        // but one more without a time advance fails
        assert!(!rate.is_ok(&addr1, 1).await);

        tokio::time::advance(std::time::Duration::from_nanos(1)).await;

        // make sure prune doesn't prune it yet
        rate.prune();
        assert_eq!(1, rate.map.lock().unwrap().len());

        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        // make sure prune doesn't prune it yet
        rate.prune();
        assert_eq!(1, rate.map.lock().unwrap().len());

        // but one more should do it
        tokio::time::advance(std::time::Duration::from_nanos(1)).await;
        rate.prune();
        assert_eq!(0, rate.map.lock().unwrap().len());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn check_burst() {
        let addr1 = Arc::new(std::net::Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1));

        let rate = test_new(1, 5);

        for _ in 0..5 {
            assert!(rate.is_ok(&addr1, 1).await);
        }

        assert!(!rate.is_ok(&addr1, 1).await);

        tokio::time::advance(std::time::Duration::from_nanos(2)).await;
        assert!(rate.is_ok(&addr1, 1).await);

        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        tokio::time::advance(std::time::Duration::from_nanos(4)).await;

        rate.prune();
        assert_eq!(1, rate.map.lock().unwrap().len());

        tokio::time::advance(std::time::Duration::from_nanos(1)).await;

        rate.prune();
        assert_eq!(0, rate.map.lock().unwrap().len());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn check_limit_mult() {
        let addr1 = Arc::new(std::net::Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1));

        let rate = test_new(3, 13);

        assert!(rate.is_ok(&addr1, 2).await);
        assert!(rate.is_ok(&addr1, 2).await);
        assert!(!rate.is_ok(&addr1, 2).await);

        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        assert!(rate.is_ok(&addr1, 2).await);
        assert!(rate.is_ok(&addr1, 2).await);
        assert!(!rate.is_ok(&addr1, 2).await);
    }
}
