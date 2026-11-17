import asyncio

from database import engine, Base
import models


async def create_tables():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    print("Cyber Mirror database tables created successfully!")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(create_tables())