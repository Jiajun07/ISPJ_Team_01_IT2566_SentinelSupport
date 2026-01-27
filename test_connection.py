# test_connection.py
import psycopg2

MASTER_DB_URL = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)

try:
    with psycopg2.connect(MASTER_DB_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            print("Connected successfully:", cur.fetchone()[0])

            # Fixed schema query
            cur.execute(
                "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT LIKE 'pg_%' AND schema_name != 'information_schema';")
            schemas = [row[0] for row in cur.fetchall()]
            print("Existing schemas:", schemas)

            # Check if tenants table exists
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'tenants';
            """)
            tenants_exists = cur.fetchone()
            print("public.tenants table exists:", bool(tenants_exists))

except Exception as e:
    print("Failed:", repr(e))
