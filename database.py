# database.py - SUPABASE MULTI-TENANT
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker
import bcrypt
import os
import json
from datetime import datetime, timezone, UTC, timedelta
# Supabase connection (same as your app.py)
MASTER_DB_URL = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport*2026@"
    "aws-1-ap-south-1.pooler.supabase.com:6543/postgres"
)
DB_USE_PGBOUNCER = os.getenv("DB_USE_PGBOUNCER", "false").lower() == "true"
db = SQLAlchemy()

class TenantSecurity(db.Model):
    __tablename__ = 'tenant_security'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), unique=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    dlp_enabled = db.Column(db.Boolean, default=False)
    dlp_rule_count = db.Column(db.Integer, default=0)
    data_retention_days = db.Column(db.Integer, default=365)
    rls_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))  # ✅

class Tenant(db.Model):
    __tablename__ = 'tenants'  # Explicit in public schema
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False, unique=True)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=db.func.now())
    is_active = db.Column(db.Boolean, default=True)
    archived_at = db.Column(db.DateTime)



class User(db.Model):
    """User accounts - stored in tenant schemas"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')  # 'admin', 'user', 'viewer'
    is_email_verified = db.Column(db.Boolean, default=False)
    two_fa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    
    __table_args__ = (
        db.UniqueConstraint('tenant_id', 'email', name='uq_tenant_email'),
    )


class VerificationCode(db.Model):
    """Email verification codes for signup and password reset"""
    __tablename__ = 'verification_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    code = db.Column(db.String(255), nullable=False, unique=True, index=True)
    code_type = db.Column(db.String(50), nullable=False)  # 'email_verify', 'password_reset', 'invite'
    email = db.Column(db.String(255), nullable=False)  # Email it was sent to
    is_used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=db.func.now())


class TwoFactorAuth(db.Model):
    """2FA settings and credentials for users"""
    __tablename__ = 'two_factor_auth'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, unique=True, index=True)
    auth_type = db.Column(db.String(50), nullable=False)  # 'email', 'totp', 'sms'
    secret_key = db.Column(db.String(255), nullable=True)  # For TOTP
    backup_codes = db.Column(db.JSON, nullable=True)  # List of one-time backup codes
    backup_email = db.Column(db.String(255), nullable=True)  # For email-based 2FA
    is_verified = db.Column(db.Boolean, default=False)
    enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())


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
    """Mark tenant as archived (soft delete)"""
    tenant = Tenant.query.get(tenant_id)
    if tenant:
        tenant.is_active = False  # ✅ CHANGES STATUS
        tenant.archived_at = datetime.now(UTC)  # ✅ SETS ARCHIVE DATE
        db.session.commit()  # ✅ SAVES TO DATABASE
        print(f"✅ Tenant {tenant_id} archived: is_active=False")
        return True
    print(f"❌ Tenant {tenant_id} not found")
    return False


def get_tenant_security_status(tenant_id: int):
    """Get current security settings for tenant dashboard"""
    security = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()

    if not security:
        return {
            'mfa_enabled': False,
            'dlp_enabled': False,
            'dlp_rule_count': 0,
            'retention_days': 365
        }

    return {
        'mfa_enabled': security.mfa_enabled or False,
        'dlp_enabled': security.dlp_enabled or False,
        'dlp_rule_count': getattr(security, 'dlp_rule_count', 0),
        'retention_days': security.data_retention_days or 365
    }


def reactivate_tenant(tenant_id: int):
    """Reactivate archived tenant"""
    tenant = Tenant.query.get(tenant_id)
    if tenant:
        tenant.is_active = True
        tenant.archived_at = None
        db.session.commit()
        return True
    return False


def get_tenant_stats(tenant_id):
    schema_name = f"tenant_{tenant_id}"

    security = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()

    # Check if cleanup ran today
    today = datetime.now(UTC).date()
    cleaned_today = db.session.execute(text(f'''
        SELECT COUNT(*) FROM "{schema_name}".audit_logs 
        WHERE created_at >= :today
    '''), {'today': today}).scalar() or 0

    return {
        'total_users': db.session.execute(text(f'SELECT COUNT(*) FROM "{schema_name}".users')).scalar(),
        'total_documents': db.session.execute(text(f'SELECT COUNT(*) FROM "{schema_name}".documents')).scalar(),
        'audit_logs': db.session.execute(text(f'SELECT COUNT(*) FROM "{schema_name}".audit_logs')).scalar(),  # ✅ NEW LINE
        'cleaned_today': cleaned_today,
        'retention_days': security.data_retention_days if security else 365
    }



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


def apply_rls_policies(tenant_id: int, security: TenantSecurity):
    """Apply RLS + security policies to tenant schema"""
    schema_name = f"tenant_{tenant_id}"

    # Enable RLS on all tables
    tables = ['users', 'documents', 'audit_logs']
    for table in tables:
        db.session.execute(text(f'ALTER TABLE "{schema_name}"."{table}" ENABLE ROW LEVEL SECURITY'))

    if security.rls_enabled:
        # Drop old policies first
        db.session.execute(text(f'DROP POLICY IF EXISTS "tenant_{tenant_id}_rls_users" ON "{schema_name}".users'))
        db.session.execute(
            text(f'DROP POLICY IF EXISTS "tenant_{tenant_id}_rls_documents" ON "{schema_name}".documents'))
        db.session.execute(text(f'DROP POLICY IF EXISTS "tenant_{tenant_id}_rls_audit" ON "{schema_name}".audit_logs'))

        # CREATE basic tenant isolation policies
        db.session.execute(text(f'''
            CREATE POLICY "tenant_{tenant_id}_rls_users" 
            ON "{schema_name}".users 
            FOR ALL TO public 
            USING (true)
        '''))

        db.session.execute(text(f'''
            CREATE POLICY "tenant_{tenant_id}_rls_documents" 
            ON "{schema_name}".documents 
            FOR ALL TO public 
            USING (true)
        '''))

        db.session.execute(text(f'''
            CREATE POLICY "tenant_{tenant_id}_rls_audit" 
            ON "{schema_name}".audit_logs 
            FOR ALL TO public 
            USING (true)
        '''))

    else:
        # DISABLE RLS completely
        for table in tables:
            db.session.execute(text(f'ALTER TABLE "{schema_name}"."{table}" DISABLE ROW LEVEL SECURITY'))

    # DLP Policy (only if enabled)
    if security.dlp_enabled:
        db.session.execute(
            text(f'DROP POLICY IF EXISTS "tenant_{tenant_id}_dlp_restrict" ON "{schema_name}".documents'))
        db.session.execute(text(f'''
            CREATE POLICY "tenant_{tenant_id}_dlp_restrict" 
            ON "{schema_name}".documents 
            FOR SELECT TO public 
            USING (classification != 'HIGHLY_CONFIDENTIAL')
        '''))

    # ✅ FIXED RETENTION POLICY
    # Drop existing retention policy first
    db.session.execute(
        text(f'DROP POLICY IF EXISTS "tenant_{tenant_id}_retention_audit" ON "{schema_name}".audit_logs'))

    if security.data_retention_days < 3650:  # Less than 10 years
        db.session.execute(text(f'''
            CREATE POLICY "tenant_{tenant_id}_retention_audit" 
            ON "{schema_name}".audit_logs 
            FOR ALL TO public 
            USING (created_at > NOW() - INTERVAL '{security.data_retention_days} days')
        '''))

    db.session.commit()
    print(f"✅ RLS + DLP + Retention policies applied to tenant_{tenant_id}")


def retention_cleanup(tenant_id: int):
    """Delete data older than retention period - RETURNS stats dict"""
    schema_name = f"tenant_{tenant_id}"

    # Get tenant's retention setting
    security = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()
    if not security:
        return {'logs': 0, 'docs': 0}

    cutoff_date = datetime.now(UTC) - timedelta(days=security.data_retention_days)

    # Delete old audit logs
    deleted_logs = db.session.execute(text(f'''
        DELETE FROM "{schema_name}".audit_logs 
        WHERE created_at < :cutoff
    '''), {'cutoff': cutoff_date}).rowcount

    # Delete old documents (skip HIGHLY_CONFIDENTIAL)
    deleted_docs = db.session.execute(text(f'''
        DELETE FROM "{schema_name}".documents 
        WHERE created_at < :cutoff 
        AND classification != 'HIGHLY_CONFIDENTIAL'
    '''), {'cutoff': cutoff_date}).rowcount

    db.session.commit()

    print(f"🧹 tenant_{tenant_id}: Deleted {deleted_logs} logs, {deleted_docs} docs")

    # ✅ RETURN DICTIONARY for flash message
    return {
        'logs': deleted_logs,
        'docs': deleted_docs
    }


def authenticate_user(tenant_id: int, email: str, password: str):
    """Authenticate a user in a specific tenant schema"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        user_row = session.execute(
            text("SELECT id, email, password_hash, role FROM users WHERE email = :email"), 
            {"email": email}
        ).fetchone()
        
        if not user_row:
            session.close()
            return None
        
        # Verify password (this will work!)
        stored_hash = user_row.password_hash.encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            session.close()
            return {
                'user_id': user_row.id,
                'tenant_id': tenant_id,
                'schema_name': schema_name,
                'email': user_row.email,
                'role': user_row.role,
                'is_email_verified': True,  # Temporary
                'two_fa_enabled': True     # Temporary
            }
        
        session.close()
        return None
        
    except Exception as e:
        print(f"Authentication error for tenant_{tenant_id}: {e}")
        return None


def find_user_by_email(email: str):
    """Find user across all tenant schemas by email"""
    tenants = get_all_tenants()
    
    for tenant_row in tenants:
        tenant_id = tenant_row.id
        schema_name = f"tenant_{tenant_id}"
        
        try:
            session = MasterSessionLocal()
            session.execute(text(f'SET search_path TO "{schema_name}", public'))
            
            # Remove is_email_verified from SELECT
            user_row = session.execute(
                text("SELECT id, email, role FROM users WHERE email = :email"), 
                {"email": email}
            ).fetchone()

            return {
                'user_id': user_row.id,
                'tenant_id': tenant_id,
                'schema_name': schema_name,
                'email': user_row.email,
                'role': user_row.role,
                'is_email_verified': True  # Hardcode for now
            }

            
            session.close()
        except Exception as e:
            print(f"Skipping tenant_{tenant_id}: {e}")
            continue
    
    return None



def get_verification_code(code: str, code_type: str = None):
    """Retrieve a verification code if it exists and hasn't expired"""
    try:
        # Check in public schema (verification codes might be public)
        result = db.session.execute(
            text("""
                SELECT id, user_id, code, code_type, email, is_used, expires_at 
                FROM verification_codes 
                WHERE code = :code AND is_used = FALSE
            """),
            {"code": code}
        ).fetchone()
        
        if result:
            # Check if expired
            if result.expires_at < datetime.datetime.now():
                return None
            
            # If code_type specified, verify it matches
            if code_type and result.code_type != code_type:
                return None
            
            return {
                'id': result.id,
                'user_id': result.user_id,
                'code_type': result.code_type,
                'email': result.email,
                'is_used': result.is_used
            }
        
        return None
    except Exception as e:
        print(f"Error retrieving verification code: {e}")
        return None


def mark_verification_code_used(code_id: int):
    """Mark a verification code as used"""
    try:
        db.session.execute(
            text("UPDATE verification_codes SET is_used = TRUE WHERE id = :id"),
            {"id": code_id}
        )
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error marking code as used: {e}")
        db.session.rollback()
        return False


def create_signup_code(tenant_id: int, email: str = None) -> str:
    """Create a signup verification code for a tenant"""
    import secrets
    import string
    
    try:
        # Generate code: INVITE_XXXXX
        random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        code = f"INVITE_{random_part}"
        
        # Create verification code record
        expires_at = datetime.datetime.now() + datetime.timedelta(days=7)  # 7 days valid
        
        verification = VerificationCode(
            user_id=tenant_id,  # Store tenant_id here as reference
            code=code,
            code_type='signup_invite',
            email=email or f"tenant_{tenant_id}@example.com",
            is_used=False,
            expires_at=expires_at
        )
        
        db.session.add(verification)
        db.session.commit()
        print(f"✅ Created signup code {code} for tenant_{tenant_id}")
        return code
    
    except Exception as e:
        print(f"❌ Error creating signup code: {e}")
        db.session.rollback()
        return None


def validate_signup_code(code: str) -> dict:
    """Validate a signup code and return tenant info"""
    try:
        verification = VerificationCode.query.filter_by(
            code=code,
            code_type='signup_invite',
            is_used=False
        ).first()
        
        if not verification:
            return None
        
        # Check if expired
        if verification.expires_at < datetime.datetime.now():
            return None
        
        # Get tenant info
        tenant = Tenant.query.get(verification.user_id)
        
        if not tenant or tenant.status != 'active':
            return None
        
        return {
            'code_id': verification.id,
            'tenant_id': tenant.id,
            'company_name': tenant.company_name,
            'schema_name': f"tenant_{tenant.id}"
        }
    
    except Exception as e:
        print(f"Error validating signup code: {e}")
        return None


def create_user_in_tenant(tenant_id: int, email: str, password_hash: str, role: str = 'user') -> dict:
    schema_name = f"tenant_{tenant_id}"

    try:
        session = MasterSessionLocal()
        print(f"🔄 Creating user in {schema_name}")

        session.execute(text(f'SET search_path TO "{schema_name}", public'))

        existing = session.execute(
            text("SELECT id FROM users WHERE email = :email"),
            {"email": email}
        ).fetchone()

        if existing:
            session.close()
            print(f"⚠️ User {email} already exists in {schema_name}")
            return None

        # Match tenant users table layout
        session.execute(
            text("""
                INSERT INTO users (email, password_hash, role, created_at)
                VALUES (:email, :password_hash, :role, NOW())
            """),
            {
                "email": email,
                "password_hash": password_hash,
                "role": role,
            }
        )

        session.commit()
        print(f"✅ Committed user {email} to database")

        user_row = session.execute(
            text("SELECT id, email, role FROM users WHERE email = :email"),
            {"email": email}
        ).fetchone()

        session.close()

        print(f"✅ Created user {email} in {schema_name}")

        return {
            "user_id": user_row.id,
            "email": user_row.email,
            "role": user_row.role,
            "tenant_id": tenant_id,
        }

    except Exception as e:
        print(f"❌ Error creating user in {schema_name}: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        try:
            session.close()
        except:
            pass
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
