# test_supabase.py
import psycopg2

MASTER_DB_URL = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)

try:
    with psycopg2.connect(MASTER_DB_URL, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            print("Basic connection: OK")

            cur.execute("SELECT schemaname FROM pg_namespace;")
            print("Schemas:", [row[0] for row in cur.fetchall()])
except Exception as e:
    print("Failed:", repr(e))
