# database.py - SUPABASE MULTI-TENANT
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
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

def get_tenant_engine(db_name: str) -> Engine:
    return create_engine(
        f"postgresql://postgres:Jiajun07@@2025@localhost:5432/{db_name}"
    )

#class files(db.Model):
#    __tablename__ = 'files'
#    tenant_id = db.Column(db.Integer, nullable=False)
#    file_name = db.Column(db.String(255), nullable=False)
#    file_id = db.Column(db.Integer, nullable=False)
#    owner = db.Column(db.String(255), nullable=False)
#    sensitivity = db.Column(db.String(50), nullable=False)
#    date_modified = db.Column(db.DateTime, default=db.func.now())
#    file_size = db.Column(db.Float, nullable=False)    
#    file_path = db.Column(db.String(255), nullable=False)
#
#class file_sharing_link(db.Model):
#    """Public/restricted shareable links for files"""
#    __tablename__ = 'file_sharing_links'
#    id = db.Column(db.Integer, primary_key=True)
#    file_id = db.Column(db.Integer, nullable=False, index=True)
#    file_name = db.Column(db.String(255), nullable=False)
#    shared_link = db.Column(db.String(255), unique=True, nullable=False, index=True)
#    password = db.Column(db.String(255), nullable=True)  # Optional password protection
#    is_active = db.Column(db.Boolean, default=True)
#    created_by = db.Column(db.String(255), nullable=False)  # Who created the link
#    created_at = db.Column(db.DateTime, default=db.func.now(), index=True)
#    last_accessed = db.Column(db.DateTime, nullable=True)
#    access_count = db.Column(db.Integer, default=0)  # Track link usage
#
#
#class sharing(db.Model):
#    """Direct recipient sharing (email/username)"""
#    __tablename__ = 'sharing'
#    id = db.Column(db.Integer, primary_key=True)
#    file_id = db.Column(db.Integer, nullable=False, index=True)
#    file_name = db.Column(db.String(255), nullable=False)
#    shared_with = db.Column(db.String(255), nullable=False, index=True)  # Email or user_id
#    shared_by = db.Column(db.String(255), nullable=False)  # Who initiated the share
#    access_level = db.Column(db.String(50), nullable=False, default='view')  # 'view', 'edit', 'comment'
#    shared_at = db.Column(db.DateTime, default=db.func.now(), index=True)
#    expires_at = db.Column(db.DateTime, nullable=True)  # Optional expiration
#    is_accepted = db.Column(db.Boolean, default=False)  # Track if recipient accepted
#    last_accessed = db.Column(db.DateTime, nullable=True)  # Last time recipient accessed file
#    access_count = db.Column(db.Integer, default=0)  # Track how many times recipient accessed
#    
#    # Unique constraint: prevent sharing same file with same person multiple times
#    __table_args__ = (db.UniqueConstraint('file_id', 'shared_with', name='uq_file_user_sharing'),)
#
#
#class sharing_activity(db.Model):
#    """Track all sharing activities for audit and analytics"""
#    __tablename__ = 'sharing_activity'
#    id = db.Column(db.Integer, primary_key=True)
#    file_id = db.Column(db.Integer, nullable=False, index=True)
#    file_name = db.Column(db.String(255), nullable=False)
#    action = db.Column(db.String(50), nullable=False)  # 'shared', 'unshared', 'accessed', 'downloaded'
#    shared_with = db.Column(db.String(255), nullable=True)  # For direct shares
#    shared_via_link = db.Column(db.String(255), nullable=True)  # For link shares
#    shared_by = db.Column(db.String(255), nullable=False)
#    ip_address = db.Column(db.String(50), nullable=True)  # For link access tracking
#    activity_at = db.Column(db.DateTime, default=db.func.now(), index=True)
#    details = db.Column(db.JSON, nullable=True)  # Additional metadata
#
