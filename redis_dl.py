import redis

r = redis.Redis(host="localhost", port=6379, db=0)

r.flushdb()
print("Redis DB cleared بالكامل")
r.flushall()
print("ALL Redis databases cleared")