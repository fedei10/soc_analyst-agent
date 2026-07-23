
from app.config import settings  
import redis

def get_redis_connection():
    return redis.StrictRedis(
        host=settings.REDIS_HOST.get_secret_value(),
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        decode_responses=True
    )

def test_redis_connection():
    try:
        r = get_redis_connection()
        r.set("test", "ok")
        return "✅ Redis Connected Successfully"
    except Exception as e:
        return f"❌ Redis Connection Failed: {str(e)}"