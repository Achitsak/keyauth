from app.ratelimit import RateLimiter


def test_sweep_drops_idle_buckets():
    rl = RateLimiter()
    rl.allow("ip:1", limit=5, window=60, now=1000)
    assert "ip:1" in rl._hits
    rl.sweep(now=2000, max_window=60)  # 2000-60=1940 > 1000 -> idle
    assert "ip:1" not in rl._hits


def test_sweep_keeps_active_buckets():
    rl = RateLimiter()
    rl.allow("ip:1", limit=5, window=60, now=1000)
    rl.sweep(now=1030, max_window=60)  # entry at 1000 still within window
    assert "ip:1" in rl._hits
