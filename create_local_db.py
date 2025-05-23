import os

import pymysql
from dotenv import load_dotenv

load_dotenv()

MYSQL_USER = os.environ.get("LOCAL_MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("LOCAL_MYSQL_PASSWORD", "password")
MYSQL_HOST = os.environ.get("LOCAL_MYSQL_HOST", "localhost")
LOCAL_DB_NAME = os.environ.get("LOCAL_DB_NAME", "cloudworx_local")


def create_database() -> None:
    conn = pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{LOCAL_DB_NAME}`;")
            print(f"Database '{LOCAL_DB_NAME}' ensured.")
    finally:
        conn.close()


if __name__ == "__main__":
    create_database()
