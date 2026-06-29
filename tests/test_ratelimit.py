from app.ratelimit import RateLimiter


def test_allows_then_blocks_within_window():
    rl = RateLimiter()
    for i in range(3):
        assert rl.allow("ip:1", limit=3, window=60, now=1000 + i)
    assert not rl.allow("ip:1", limit=3, window=60, now=1001)


def test_window_rolls_off():
    rl = RateLimiter()
    assert rl.allow("ip:1", limit=1, window=60, now=1000)
    assert not rl.allow("ip:1", limit=1, window=60, now=1030)
    assert rl.allow("ip:1", limit=1, window=60, now=1061)
