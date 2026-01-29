# database.py - SUPABASE MULTI-TENANT
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import bcrypt

# Supabase connection (same as your app.py)
MASTER_DB_URL = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport*2026@"
    "aws-1-ap-south-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
)

db = SQLAlchemy()


class Tenant(db.Model):
    __tablename__ = 'tenants'  # Explicit in public schema
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False, unique=True)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=db.func.now())


def create_tenant(company_name: str, admin_email: str, admin_password: str):
    """Creates tenant schema + identical tables + admin user"""
    try:
        # 1. Create public.tenants record
        tenant = Tenant(company_name=company_name)
        db.session.add(tenant)
        db.session.flush()
        tenant_id = tenant.id
        schema_name = f"tenant_{tenant_id}"

        # 2. CREATE SCHEMA (Supabase allows this)
        db.session.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))

        # 3. CREATE IDENTICAL TABLES
        tables_sql = f"""
        CREATE TABLE IF NOT EXISTS "{schema_name}".users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS "{schema_name}".documents (
            id SERIAL PRIMARY KEY,
            owner_user_id INT REFERENCES "{schema_name}".users(id),
            file_path TEXT NOT NULL,
            classification VARCHAR(50) NOT NULL,
            version INT DEFAULT 1,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS "{schema_name}".audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INT REFERENCES "{schema_name}".users(id),
            action VARCHAR(100) NOT NULL,
            target_type VARCHAR(50),
            target_id INT,
            details TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
        """
        db.session.execute(text(tables_sql))

        # 4. Insert admin user
        password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()
        db.session.execute(
            text(f'INSERT INTO "{schema_name}".users (email, password_hash, role) VALUES (%s, %s, %s)'),
            (admin_email, password_hash, 'admin')
        )

        db.session.commit()
        print(f"✅ Created {schema_name} with identical tables + admin user")
        return tenant_id, schema_name

    except Exception as e:
        db.session.rollback()
        raise Exception(f"Tenant creation failed: {str(e)}")


def get_all_tenants():
    """Admin dashboard: list active tenants"""
    return db.session.execute(
        text("SELECT * FROM tenants WHERE status = 'active' ORDER BY created_at DESC")
    ).fetchall()


def archive_tenant(tenant_id: int):
    """Archive on subscription end"""
    result = db.session.execute(
        text("UPDATE tenants SET status = 'archived' WHERE id = :tid RETURNING *"),
        {"tid": tenant_id}
    )
    tenant = result.fetchone()
    db.session.commit()
    return tenant


def get_tenant_stats(tenant_id: int):
    """Admin stats per tenant"""
    schema = f'tenant_{tenant_id}'
    session = sessionmaker(bind=create_engine(MASTER_DB_URL))()
    session.execute(text(f'SET search_path TO "{schema}", public'))

    stats = {
        'users': session.execute(text("SELECT COUNT(*) FROM users")).scalar(),
        'documents': session.execute(text("SELECT COUNT(*) FROM documents")).scalar(),
        'audit_logs': session.execute(text("SELECT COUNT(*) FROM audit_logs")).scalar()
    }
    session.close()
    return stats


# Raw engine for non-Flask context (tests)
master_engine = create_engine(MASTER_DB_URL)
MasterSessionLocal = sessionmaker(bind=master_engine)

