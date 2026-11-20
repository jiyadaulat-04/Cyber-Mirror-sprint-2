import asyncio
import getpass
import re

from sqlalchemy import select, text

from database import AsyncSessionLocal
from models import User
from security import hash_password


async def create_initial_admin():

    print("\n=== Cyber Mirror | Initial Admin Setup ===\n")

    username = input("Enter Admin username: ").strip().lower()

    if not re.fullmatch(r"[a-z0-9_.-]{3,50}", username):
        print("Error: Username must be 3-50 characters.")
        print("Use letters, numbers, dots, underscores or hyphens.")
        return

    password = getpass.getpass("Enter Admin password: ")
    confirm_password = getpass.getpass("Confirm Admin password: ")

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    if len(password) < 12 or len(password) > 128:
        print("Error: Password must contain 12-128 characters.")
        return

    async with AsyncSessionLocal() as db:

        async with db.begin():

            # Prevent simultaneous initial Admin creation.
            await db.execute(
                text("SELECT pg_advisory_xact_lock(20261118)")
            )

            existing_admin = await db.scalar(
                select(User).where(User.role == "admin").limit(1)
            )

            if existing_admin:
                print("Error: An Admin account already exists.")
                return

            existing_user = await db.scalar(
                select(User).where(User.username == username)
            )

            if existing_user:
                print("Error: This username is already registered.")
                return

            admin = User(
                username=username,
                password_hash=hash_password(password),
                role="admin",
                is_active=True
            )

            db.add(admin)
            await db.flush()

        await db.refresh(admin)

        print("\nAdmin account created successfully!")
        print(f"Admin ID: {admin.id}")
        print(f"Username: {admin.username}")
        print(f"Role: {admin.role}")


if __name__ == "__main__":
    asyncio.run(create_initial_admin())