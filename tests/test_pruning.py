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


def test_concurrent_allow_and_sweep_no_error():
    import threading
    rl = RateLimiter()
    for i in range(50):
        rl.allow(f"ip:{i}", limit=5, window=60, now=1000)  # idle buckets
    errors = []

    def worker(n):
        try:
            for j in range(200):
                rl.allow(f"ip:{n % 50}", limit=5, window=60, now=2000 + j)
                rl.sweep(now=2000 + j, max_window=60)  # cutoff 1940 > 1000 -> deletes
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
