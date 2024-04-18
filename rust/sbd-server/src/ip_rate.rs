use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Map = HashMap<std::net::Ipv6Addr, u64>;

#[derive(Clone)]
pub struct IpRate {
    origin: tokio::time::Instant,
    map: Arc<Mutex<Map>>,
    limit: u64,
    burst: u64,
}

impl IpRate {
    pub fn new(limit: u64, burst: u64) -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            map: Arc::new(Mutex::new(HashMap::new())),
            limit,
            burst,
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

    /// Return true if we are not over the rate limit.
    pub fn is_ok(&self, ip: std::net::Ipv6Addr, bytes: usize) -> bool {
        // multiply by our rate allowed per byte
        let rate_add = bytes as u64 * self.limit;

        // get now
        let now = self.origin.elapsed().as_nanos() as u64;

        // lock the map mutex
        let mut lock = self.map.lock().unwrap();

        // get the entry (default to now)
        let e = lock.entry(ip).or_insert(now);

        // if we've already used time greater than now use that,
        // otherwise consider we're starting from scratch
        let cur = std::cmp::max(*e, now) + rate_add;

        // update the map with the current limit
        *e = cur;

        // subtract now back out to see if we're greater than our burst
        cur - now <= self.burst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR1: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1);

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn check_one_to_one() {
        let rate = IpRate::new(1, 1);

        for _ in 0..10 {
            // should always be ok when advancing with time
            tokio::time::advance(std::time::Duration::from_nanos(1)).await;
            assert!(rate.is_ok(ADDR1, 1));
        }

        // but one more without a time advance fails
        assert!(!rate.is_ok(ADDR1, 1));

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
        let rate = IpRate::new(1, 5);

        for _ in 0..5 {
            assert!(rate.is_ok(ADDR1, 1));
        }

        assert!(!rate.is_ok(ADDR1, 1));

        tokio::time::advance(std::time::Duration::from_nanos(2)).await;
        assert!(rate.is_ok(ADDR1, 1));

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
        let rate = IpRate::new(3, 13);

        assert!(rate.is_ok(ADDR1, 2));
        assert!(rate.is_ok(ADDR1, 2));
        assert!(!rate.is_ok(ADDR1, 2));

        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        assert!(rate.is_ok(ADDR1, 2));
        assert!(rate.is_ok(ADDR1, 2));
        assert!(!rate.is_ok(ADDR1, 2));
    }
}
