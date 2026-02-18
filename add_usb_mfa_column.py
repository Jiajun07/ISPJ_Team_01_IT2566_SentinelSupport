"""
Direct database migration to add USB MFA column
"""
import psycopg2
from psycopg2 import sql

# Database connection settings  
DB_HOST = "aws-1-ap-south-1.pooler.supabase.com"
DB_PORT = 6543
DB_NAME = "postgres"
DB_USER = "postgres.ijbxuudpvxsjjdugewuj"
DB_PASSWORD = "SentinelSupport*2026"

try:
    print("🔗 Connecting to database...")
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    
    cursor = conn.cursor()
    
    # Get all tenant schemas
    print("🔍 Finding all tenant schemas...")
    cursor.execute("""
        SELECT schema_name FROM information_schema.schemata 
        WHERE schema_name LIKE 'tenant_%'
        ORDER BY schema_name
    """)
    
    tenant_schemas = [row[0] for row in cursor.fetchall()]
    print(f"Found {len(tenant_schemas)} tenants: {tenant_schemas}")
    
    for schema in tenant_schemas:
        # Check if column exists
        cursor.execute(sql.SQL("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_schema = %s
                AND table_name = 'users'
                AND column_name = 'usb_mfa_enabled'
            )
        """), (schema,))
        
        column_exists = cursor.fetchone()[0]
        
        if column_exists:
            print(f"✅ {schema}.users already has usb_mfa_enabled")
        else:
            print(f"❌ {schema}.users missing usb_mfa_enabled - adding...")
            try:
                cursor.execute(sql.SQL("""
                    ALTER TABLE {}.users 
                    ADD COLUMN usb_mfa_enabled BOOLEAN DEFAULT FALSE
                """).format(sql.Identifier(schema)))
                conn.commit()
                print(f"   ✅ Successfully added column to {schema}.users")
            except Exception as add_err:
                print(f"   ❌ Error: {add_err}")
                conn.rollback()
    
    cursor.close()
    conn.close()
    
    print("\n✅ Migration complete!")
    
except Exception as e:
    print(f"❌ Connection error: {e}")
    exit(1)
