# database.py - SUPABASE MULTI-TENANT
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker
import bcrypt
import os
import json
import datetime
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




def get_last_backup(tenant_id: int):
    """Get last backup timestamp for UI"""
    # Mock for now - replace with real backup log table
    return "Dec 15, 2025 15:23 PM"


def list_backups(tenant_id: int):
    """List available backups for restore dropdown"""
    # Scan backups folder or backup_logs table
    backups_dir = "backups"
    if not os.path.exists(backups_dir):
        return []

    pattern = f"tenant_{tenant_id}_*.json"
    import glob
    files = glob.glob(os.path.join(backups_dir, pattern))
    return [os.path.basename(f) for f in sorted(files, reverse=True)[:10]]  # Last 10


def backup_tenant(tenant_id: int):
    schema = f"tenant_{tenant_id}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    session = MasterSessionLocal()
    session.execute(text(f'SET search_path TO "{schema}", public'))

    users = session.execute(text("SELECT id, email, password_hash, role, created_at FROM users")).mappings().all()
    documents = session.execute(text("SELECT * FROM documents")).mappings().all()
    audit_logs = session.execute(text("SELECT * FROM audit_logs")).mappings().all()
    session.close()

    backup_data = {
        "tenant_id": tenant_id,
        "timestamp": timestamp,
        "users": list(users),
        "documents": list(documents),
        "audit_logs": list(audit_logs),
    }

    os.makedirs("backups", exist_ok=True)
    backup_path = f"backups/tenant_{tenant_id}_{timestamp}.json"
    with open(backup_path, "w") as f:
        json.dump(backup_data, f, default=str, indent=2)

    return backup_path

def restore_backup(tenant_id: int, backup_path: str):
    """Restore tenant from backup file"""
    try:
        schema = f'tenant_{tenant_id}'
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema}", public'))

        # Clear existing data (dangerous!)
        session.execute(text('TRUNCATE users, documents, audit_logs RESTART IDENTITY CASCADE'))

        # Load backup data
        with open(backup_path, 'r') as f:
            backup_data = json.load(f)

        # Restore users (example)
        for user_data in backup_data.get('users', []):
            session.execute(text("""
                INSERT INTO users (id, email, password_hash, role, created_at)
                VALUES (%(id)s, %(email)s, %(password_hash)s, %(role)s, %(created_at)s)
            """), user_data)

        session.commit()
        session.close()
        print(f"✅ Restored tenant_{tenant_id} from {backup_path}")
        return True

    except Exception as e:
        print(f"❌ Restore failed: {e}")
        return False


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


def authenticate_tenant_admin(email: str, password: str):
    """Find admin across tenant schemas"""
    tenants = Tenant.query.all()

    for tenant in tenants:
        schema_name = f"tenant_{tenant.id}"

        try:
            result = db.session.execute(
                text(f'SELECT password_hash FROM "{schema_name}".users WHERE email = :email AND role = :role'),
                {'email': email, 'role': 'admin'}
            ).fetchone()

            if result and bcrypt.checkpw(password.encode(), result.password_hash.encode()):
                return {
                    'tenant_id': tenant.id,
                    'schema_name': schema_name,
                    'company_name': tenant.company_name
                }
        except:
            continue  # Skip if table doesn't exist

    return None


def find_tenant_admin(email: str, password: str):
    """Search ALL tenant schemas for admin user + verify password"""
    tenants = get_all_tenants()

    for tenant_row in tenants:
        tenant_id = tenant_row.id
        schema_name = f"tenant_{tenant_id}"

        try:
            session = MasterSessionLocal()
            session.execute(text(f'SET search_path TO "{schema_name}", public'))

            # Get user + password hash
            user_row = session.execute(
                text("SELECT id, email, password_hash, role FROM users WHERE email = :email"),
                {"email": email}
            ).fetchone()

            if user_row and user_row.role == 'admin':
                # Verify password
                stored_hash = user_row.password_hash.encode()
                input_hash = bcrypt.hashpw(password.encode(), stored_hash)

                if input_hash == stored_hash:
                    session.close()
                    return {
                        'tenant_id': tenant_id,
                        'schema_name': schema_name,
                        'email': user_row.email,
                        'company_name': tenant_row.company_name
                    }

            session.close()
        except Exception as e:
            print(f"Skipping tenant_{tenant_id}: {e}")
            continue

    return None

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
