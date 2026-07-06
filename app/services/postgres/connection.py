import psycopg2
from app.config import settings

def get_postgres_connection():
    return psycopg2.connect(
        host=settings.POSTGRES_HOST.get_secret_value(),
        port=settings.POSTGRES_PORT,
        user=settings.POSTGRES_USER.get_secret_value(),
        password=settings.POSTGRES_PASSWORD.get_secret_value(),
        dbname=settings.POSTGRES_DB.get_secret_value()
    )

def test_postgres_connection():
    try:
        conn = get_postgres_connection()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return f"✅ PostgreSQL Connected: {result[0]}"
    except Exception as e:
        return f"❌ PostgreSQL Connection Failed: {str(e)}"