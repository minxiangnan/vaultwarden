//! Separate buckets so a burst of valid code reads cannot be used to hide password guesses,
//! and random invalid tokens cannot grow the token map.

use std::{net::IpAddr, num::NonZeroU32, sync::LazyLock, time::Duration};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};

use crate::CONFIG;

type Limiter<T> = RateLimiter<T, DashMapStateStore<T>, DefaultClock>;

static LIMIT_TOKEN: LazyLock<Limiter<String>> = LazyLock::new(|| {
    let seconds = Duration::from_secs(u64::from(CONFIG.mcp_ratelimit_seconds().max(1)));
    let burst = NonZeroU32::new(u32::from(CONFIG.mcp_ratelimit_burst().max(1))).expect("MCP burst is non-zero");
    RateLimiter::keyed(Quota::with_period(seconds).expect("MCP rate period").allow_burst(burst))
});

static LIMIT_IP: LazyLock<Limiter<IpAddr>> = LazyLock::new(|| {
    let burst = NonZeroU32::new(30).expect("auth burst");
    RateLimiter::keyed(Quota::with_period(Duration::from_secs(2)).expect("auth period").allow_burst(burst))
});

pub fn allow_token(token_hash: &str) -> bool {
    LIMIT_TOKEN.check_key(&token_hash.to_owned()).is_ok()
}

pub fn allow_ip(ip: &IpAddr) -> bool {
    LIMIT_IP.check_key(ip).is_ok()
}

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::db::test_db;

    #[test]
    fn token_bucket_rejects_the_request_past_the_burst() {
        test_db::run(async |_db| {
            let key = format!("test-{}", crate::util::get_uuid());
            let burst = usize::from(CONFIG.mcp_ratelimit_burst().max(1));
            for _ in 0..burst {
                assert!(allow_token(&key));
            }
            assert!(!allow_token(&key));
        });
    }
}
