import asyncio
import redis.asyncio as redis
from environmentals import REDIS_URL, REDIS_EXPIRE
from logger import logger
from datetime import timedelta


class RedisConnection:
    def __init__(self, url=REDIS_URL):
        self.url = url
        self.connection = None

    async def init_connection(self):
        """Initialize the Redis connection asynchronously."""
        try:
            self.connection = await redis.from_url(
                self.url,
                decode_responses=True,
                # ssl_cert_reqs=None,
            )
        except Exception as e:
            logger.exception(f"Redis connection failed: {e}")
            raise

    def get_connection(self):
        if not self.connection:
            raise RuntimeError(
                "Redis connection not initialized. Call init_connection()."
            )
        return self.connection

    async def close_connection(self):
        if self.connection:
            await self.connection.close()

    async def set(self, key, value, expire=timedelta(minutes=REDIS_EXPIRE)):
        return await self.connection.set(key, value, ex=expire)

    async def get(self, key):
        return await self.connection.get(key)

    async def delete(self, key):
        return await self.connection.delete(key)

    def pipeline(self):
        # aioredis pipeline is context-managed and async
        return self.connection.pipeline()


# Create a singleton instance
redis_conn = RedisConnection()
