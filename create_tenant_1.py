"""
Quick script to create tenant_1 schema and tables if it doesn't exist.
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

def create_tenant_1():
    """Create tenant_1 schema and all required tables"""
    schema_name = "tenant_1"
    session = Session()
    
    try:
        print(f"\n🔄 Creating schema and tables for {schema_name}...")
        
        # Create schema
        session.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))
        print(f"  ✅ Schema created/verified")
        
        # Create users table
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT NOW()
            )
        '''))
        
        # Create documents table
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".documents (
                id SERIAL PRIMARY KEY,
                owner_user_id INT REFERENCES "{schema_name}".users(id),
                file_path TEXT NOT NULL,
                classification VARCHAR(50) NOT NULL,
                version INT DEFAULT 1,
                created_at TIMESTAMP DEFAULT NOW()
            )
        '''))
        
        # Create audit_logs table
        session.execute(text(f'''
            CREATE TABLE IF NOT EXISTS "{schema_name}".audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INT REFERENCES "{schema_name}".users(id),
                action VARCHAR(100) NOT NULL,
                target_type VARCHAR(50),
                target_id INT,
                details TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        '''))
        
        # Create files table
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
        print(f"✅ All tables created successfully for {schema_name}!\n")
        return True
        
    except Exception as e:
        print(f"❌ Error creating tables for {schema_name}: {e}")
        session.rollback()
        return False
    finally:
        session.close()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("CREATE TENANT_1 SCHEMA AND TABLES")
    print("="*60)
    create_tenant_1()
