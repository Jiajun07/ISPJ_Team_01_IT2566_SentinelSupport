"""
Migration script to add new file management tables to existing tenant schemas.
Run this once to upgrade existing tenants with the new database structure.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Supabase connection
MASTER_DB_URL = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport*2026@"
    "aws-1-ap-south-1.pooler.supabase.com:6543/postgres"
)

engine = create_engine(MASTER_DB_URL)
Session = sessionmaker(bind=engine)

def create_tables_for_tenant(tenant_id):
    """Create missing tables for a specific tenant schema"""
    schema_name = f"tenant_{tenant_id}"
    session = Session()
    
    try:
        print(f"\n🔄 Migrating schema: {schema_name}")
        
        # Check if schema exists
        result = session.execute(text(f"""
            SELECT schema_name FROM information_schema.schemata 
            WHERE schema_name = '{schema_name}'
        """))
        
        if not result.fetchone():
            print(f"❌ Schema {schema_name} does not exist. Skipping.")
            return False
        
        # Create files table
        print(f"  ✅ Creating files table...")
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".files (
                id SERIAL PRIMARY KEY,
                document_id VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                owner_user_id INT NOT NULL,
                owner_email VARCHAR(255) NOT NULL,
                file_data BYTEA NOT NULL,
                file_size BIGINT NOT NULL,
                file_hash VARCHAR(64) NOT NULL,
                mime_type VARCHAR(100),
                sensitivity VARCHAR(50) DEFAULT 'Public',
                classification VARCHAR(50),
                risk_level VARCHAR(50),
                notes TEXT,
                is_current_version BOOLEAN DEFAULT TRUE,
                is_deleted BOOLEAN DEFAULT FALSE,
                deleted_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        '''))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_document_id ON "{schema_name}".files(document_id)'))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_owner ON "{schema_name}".files(owner_user_id)'))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_current ON "{schema_name}".files(is_current_version)'))
        
        # Create file_versions table
        print(f"  ✅ Creating file_versions table...")
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".file_versions (
                id SERIAL PRIMARY KEY,
                document_id VARCHAR(50) NOT NULL,
                version_number INT NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_data BYTEA NOT NULL,
                file_size BIGINT NOT NULL,
                file_hash VARCHAR(64) NOT NULL,
                mime_type VARCHAR(100),
                uploaded_by VARCHAR(255) NOT NULL,
                uploaded_at TIMESTAMP DEFAULT NOW(),
                is_current BOOLEAN DEFAULT FALSE,
                UNIQUE(document_id, version_number)
            )
        '''))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_versions_document ON "{schema_name}".file_versions(document_id)'))
        
        # Create file_sharing_links table
        print(f"  ✅ Creating file_sharing_links table...")
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".file_sharing_links (
                id SERIAL PRIMARY KEY,
                document_id VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                share_token VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255),
                require_key_exchange BOOLEAN DEFAULT FALSE,
                exchange_id VARCHAR(255),
                created_by VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP,
                last_accessed TIMESTAMP,
                access_count INT DEFAULT 0
            )
        '''))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_share_links_token ON "{schema_name}".file_sharing_links(share_token)'))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_share_links_document ON "{schema_name}".file_sharing_links(document_id)'))
        
        # Create sharing table
        print(f"  ✅ Creating sharing table...")
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".sharing (
                id SERIAL PRIMARY KEY,
                document_id VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                shared_with_email VARCHAR(255) NOT NULL,
                shared_by_email VARCHAR(255) NOT NULL,
                access_level VARCHAR(50) DEFAULT 'view',
                is_accepted BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                shared_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP,
                last_accessed TIMESTAMP,
                access_count INT DEFAULT 0,
                UNIQUE(document_id, shared_with_email)
            )
        '''))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_sharing_document ON "{schema_name}".sharing(document_id)'))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_sharing_recipient ON "{schema_name}".sharing(shared_with_email)'))
        
        # Create sharing_activity table
        print(f"  ✅ Creating sharing_activity table...")
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".sharing_activity (
                id SERIAL PRIMARY KEY,
                document_id VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                action VARCHAR(50) NOT NULL,
                shared_with_email VARCHAR(255),
                shared_via_link VARCHAR(255),
                shared_by_email VARCHAR(255) NOT NULL,
                ip_address VARCHAR(50),
                user_agent VARCHAR(255),
                activity_at TIMESTAMP DEFAULT NOW(),
                details JSONB
            )
        '''))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_activity_document ON "{schema_name}".sharing_activity(document_id)'))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_activity_action ON "{schema_name}".sharing_activity(action)'))
        
        # Create key_exchanges table
        print(f"  ✅ Creating key_exchanges table...")
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".key_exchanges (
                id SERIAL PRIMARY KEY,
                exchange_id VARCHAR(255) UNIQUE NOT NULL,
                sharer_email VARCHAR(255) NOT NULL,
                recipient_email VARCHAR(255) NOT NULL,
                document_id VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                sharer_public_key TEXT,
                recipient_public_key TEXT,
                sharer_fingerprint VARCHAR(64),
                recipient_fingerprint VARCHAR(64),
                status VARCHAR(50) DEFAULT 'pending',
                sharer_verified BOOLEAN DEFAULT FALSE,
                recipient_verified BOOLEAN DEFAULT FALSE,
                recipient_confirmed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP,
                verified_at TIMESTAMP
            )
        '''))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_exchange_id ON "{schema_name}".key_exchanges(exchange_id)'))
        session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_exchange_status ON "{schema_name}".key_exchanges(status)'))
        
        session.commit()
        print(f"✅ {schema_name} migration completed successfully!\n")
        return True
        
    except Exception as e:
        print(f"❌ Error migrating {schema_name}: {e}")
        session.rollback()
        return False
    finally:
        session.close()


def migrate_all_tenants():
    """Find all existing tenants and create tables for them"""
    session = Session()
    
    try:
        # Get all tenant IDs from the tenants table
        result = session.execute(text("""
            SELECT id, company_name, status 
            FROM public.tenants 
            ORDER BY id
        """))
        
        tenants = result.fetchall()
        
        if not tenants:
            print("⚠️  No tenants found in database.")
            return
        
        print(f"\n🔍 Found {len(tenants)} tenant(s) in database:")
        for tenant_id, company_name, status in tenants:
            print(f"  - Tenant {tenant_id}: {company_name} (status: {status})")
        
        print("\n" + "="*60)
        print("STARTING MIGRATION")
        print("="*60)
        
        success_count = 0
        fail_count = 0
        
        for tenant_id, company_name, status in tenants:
            if create_tables_for_tenant(tenant_id):
                success_count += 1
            else:
                fail_count += 1
        
        print("\n" + "="*60)
        print("MIGRATION COMPLETE")
        print("="*60)
        print(f"✅ Successfully migrated: {success_count} tenant(s)")
        if fail_count > 0:
            print(f"❌ Failed: {fail_count} tenant(s)")
        print()
        
    except Exception as e:
        print(f"❌ Error listing tenants: {e}")
    finally:
        session.close()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("TENANT DATABASE MIGRATION SCRIPT")
    print("="*60)
    print("This will add new file management tables to existing tenant schemas.")
    print("Tables to be created:")
    print("  - files")
    print("  - file_versions")
    print("  - file_sharing_links")
    print("  - sharing")
    print("  - sharing_activity")
    print("  - key_exchanges")
    print("="*60 + "\n")
    
    response = input("Do you want to proceed? (yes/no): ").strip().lower()
    
    if response in ['yes', 'y']:
        migrate_all_tenants()
    else:
        print("\n❌ Migration cancelled.")
