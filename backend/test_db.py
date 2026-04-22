"""Quick DB connection test."""
import asyncio
import asyncpg

async def test():
    try:
        conn = await asyncpg.connect(
            user="sentinelx",
            password="sentinelx_secret",
            database="sentinelx",
            host="localhost",
            port=5433,
        )
        result = await conn.fetchval("SELECT 1")
        print(f"DB Connected successfully! Test query returned: {result}")
        await conn.close()
    except Exception as e:
        print(f"DB Connection FAILED: {e}")

asyncio.run(test())
