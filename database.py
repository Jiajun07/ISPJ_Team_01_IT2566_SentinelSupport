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


# models.py - ADD THIS CLASS
class TenantBackupConfig(db.Model):
    __tablename__ = 'tenant_backup_config'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), unique=True)
    frequency = db.Column(db.String(20), default='daily')  # daily, weekly, monthly
    backup_time = db.Column(db.String(5), default='02:00')  # HH:MM
    enable_scheduled = db.Column(db.Boolean, default=False)
    scope_full = db.Column(db.Boolean, default=True)
    scope_compliance = db.Column(db.Boolean, default=False)
    retention_days = db.Column(db.Integer, default=30)
    last_backup = db.Column(db.DateTime, nullable=True)
    next_backup = db.Column(db.DateTime, nullable=True)

    tenant = db.relationship('Tenant', backref='backup_config')


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

def should_run_backup(config):
    """Check if backup should run now"""
    if not config.last_backup:
        return True
    return config.next_backup <= datetime.now()


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

def get_user_role(tenant_id: int, email: str):
    """Get user role from tenant_X.users table"""
    try:
        schema_name = f"tenant_{tenant_id}"
        result = db.session.execute(
            text(f'SELECT role FROM "{schema_name}".users WHERE email = :email'),
            {'email': email}
        )
        user = result.fetchone()
        return user[0] if user else 'user'
    except:
        return 'user'


def get_all_tenants():
    """Admin dashboard: list active tenants"""
    try:
        # Use ORM instead of raw SQL to avoid transaction issues
        tenants = Tenant.query.filter_by(status='active').order_by(Tenant.created_at.desc()).all()
        return tenants
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error getting tenants: {e}")
        return []


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
    try:
        tenants = Tenant.query.all()
    except Exception as e:
        print(f"❌ Error querying tenants in authenticate_tenant_admin: {e}")
        db.session.rollback()
        return None

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
        except Exception as e:
            db.session.rollback()
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
    session = None
    
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
        if session:
            session.rollback()
            session.close()
        return None


def find_user_by_email(email: str):
    """Find user across all tenant schemas by email"""
    try:
        tenants = get_all_tenants()
        print(f"🔍 Searching for {email} across {len(tenants)} tenant(s)")
    except Exception as e:
        print(f"❌ Error getting tenants in find_user_by_email: {e}")
        db.session.rollback()
        return None
    
    for tenant_row in tenants:
        tenant_id = tenant_row.id
        schema_name = f"tenant_{tenant_id}"
        print(f"  Checking {schema_name}...")
        
        try:
            session = MasterSessionLocal()
            session.execute(text(f'SET search_path TO "{schema_name}", public'))
            
            # Remove is_email_verified from SELECT
            user_row = session.execute(
                text("SELECT id, email, role FROM users WHERE email = :email"), 
                {"email": email}
            ).fetchone()

            session.close()
            
            if user_row:
                print(f"  ✅ Found user in {schema_name}!")
                return {
                    'user_id': user_row.id,
                    'tenant_id': tenant_id,
                    'schema_name': schema_name,
                    'email': user_row.email,
                    'role': user_row.role,
                    'is_email_verified': True  # Hardcode for now
                }
            
        except Exception as e:
            print(f"  ⚠️ Error in tenant_{tenant_id}: {e}")
            if 'session' in locals():
                try:
                    session.close()
                except:
                    pass
            continue
    
    print(f"  ❌ User {email} not found in any tenant")
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


# ==================== FILE MANAGEMENT HELPER FUNCTIONS ====================

def generate_document_id():
    """Generate unique document ID for file tracking across versions"""
    import uuid
    return str(uuid.uuid4())


def store_file_in_db(tenant_id, file_data, filename, owner_user_id, owner_email, 
                     file_hash, mime_type='application/octet-stream', 
                     sensitivity='Public', classification=None, risk_level=None, notes=None):
    """Store a new file in the database with blob storage"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        # Generate document ID for this file
        document_id = generate_document_id()
        file_size = len(file_data)
        
        # Insert file record with blob data
        result = session.execute(text(f'''
            INSERT INTO "{schema_name}".files 
            (document_id, file_name, owner_user_id, owner_email, file_data, 
             file_size, file_hash, mime_type, sensitivity, classification, 
             risk_level, notes, is_current_version, is_deleted, created_at, updated_at)
            VALUES 
            (:document_id, :file_name, :owner_user_id, :owner_email, :file_data,
             :file_size, :file_hash, :mime_type, :sensitivity, :classification,
             :risk_level, :notes, TRUE, FALSE, NOW(), NOW())
            RETURNING id
        '''), {
            'document_id': document_id,
            'file_name': filename,
            'owner_user_id': owner_user_id,
            'owner_email': owner_email,
            'file_data': file_data,
            'file_size': file_size,
            'file_hash': file_hash,
            'mime_type': mime_type,
            'sensitivity': sensitivity,
            'classification': classification,
            'risk_level': risk_level,
            'notes': notes
        })
        
        file_id = result.scalar()
        
        # Add initial version entry
        session.execute(text(f'''
            INSERT INTO "{schema_name}".file_versions 
            (document_id, version_number, file_name, file_data, file_size, 
             file_hash, mime_type, uploaded_by, uploaded_at, is_current)
            VALUES 
            (:document_id, 1, :file_name, :file_data, :file_size,
             :file_hash, :mime_type, :uploaded_by, NOW(), TRUE)
        '''), {
            'document_id': document_id,
            'file_name': filename,
            'file_data': file_data,
            'file_size': file_size,
            'file_hash': file_hash,
            'mime_type': mime_type,
            'uploaded_by': owner_email
        })
        
        session.commit()
        session.close()
        
        print(f"✅ Stored file '{filename}' in {schema_name}.files (id={file_id}, doc_id={document_id})")
        
        return {
            'success': True,
            'file_id': file_id,
            'document_id': document_id,
            'filename': filename,
            'size': file_size
        }
        
    except Exception as e:
        print(f"❌ Error storing file in {schema_name}: {e}")
        import traceback
        traceback.print_exc()
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def add_file_version(tenant_id, document_id, file_data, filename, uploaded_by, 
                     file_hash, mime_type='application/octet-stream'):
    """Add a new version to an existing file"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        # Get current version number
        current_version = session.execute(text(f'''
            SELECT MAX(version_number) FROM "{schema_name}".file_versions 
            WHERE document_id = :document_id
        '''), {'document_id': document_id}).scalar() or 0
        
        next_version = current_version + 1
        file_size = len(file_data)
        
        # Mark all previous versions as not current
        session.execute(text(f'''
            UPDATE "{schema_name}".file_versions 
            SET is_current = FALSE 
            WHERE document_id = :document_id
        '''), {'document_id': document_id})
        
        # Update main file record
        session.execute(text(f'''
            UPDATE "{schema_name}".files 
            SET file_data = :file_data, 
                file_name = :file_name,
                file_size = :file_size, 
                file_hash = :file_hash,
                mime_type = :mime_type,
                updated_at = NOW()
            WHERE document_id = :document_id AND is_current_version = TRUE
        '''), {
            'document_id': document_id,
            'file_data': file_data,
            'file_name': filename,
            'file_size': file_size,
            'file_hash': file_hash,
            'mime_type': mime_type
        })
        
        # Add new version entry
        session.execute(text(f'''
            INSERT INTO "{schema_name}".file_versions 
            (document_id, version_number, file_name, file_data, file_size,
             file_hash, mime_type, uploaded_by, uploaded_at, is_current)
            VALUES 
            (:document_id, :version_number, :file_name, :file_data, :file_size,
             :file_hash, :mime_type, :uploaded_by, NOW(), TRUE)
        '''), {
            'document_id': document_id,
            'version_number': next_version,
            'file_name': filename,
            'file_data': file_data,
            'file_size': file_size,
            'file_hash': file_hash,
            'mime_type': mime_type,
            'uploaded_by': uploaded_by
        })
        
        session.commit()
        session.close()
        
        print(f"✅ Added version {next_version} to document {document_id}")
        
        return {
            'success': True,
            'version_number': next_version,
            'document_id': document_id
        }
        
    except Exception as e:
        print(f"❌ Error adding version: {e}")
        import traceback
        traceback.print_exc()
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def get_file_from_db(tenant_id, document_id=None, filename=None, include_deleted=False):
    """Retrieve a file from database by document_id or filename"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        if document_id:
            query = f'''
                SELECT id, document_id, file_name, owner_user_id, owner_email,
                       file_data, file_size, file_hash, mime_type, sensitivity,
                       classification, risk_level, notes, is_current_version,
                       is_deleted, deleted_at, created_at, updated_at
                FROM "{schema_name}".files
                WHERE document_id = :document_id AND is_current_version = TRUE
            '''
            if not include_deleted:
                query += ' AND is_deleted = FALSE'
            
            result = session.execute(text(query), {'document_id': document_id}).fetchone()
        elif filename:
            query = f'''
                SELECT id, document_id, file_name, owner_user_id, owner_email,
                       file_data, file_size, file_hash, mime_type, sensitivity,
                       classification, risk_level, notes, is_current_version,
                       is_deleted, deleted_at, created_at, updated_at
                FROM "{schema_name}".files
                WHERE file_name = :filename AND is_current_version = TRUE
            '''
            if not include_deleted:
                query += ' AND is_deleted = FALSE'
            
            result = session.execute(text(query), {'filename': filename}).fetchone()
        else:
            session.close()
            return None
        
        session.close()
        
        if result:
            return {
                'id': result[0],
                'document_id': result[1],
                'file_name': result[2],
                'owner_user_id': result[3],
                'owner_email': result[4],
                'file_data': result[5],
                'file_size': result[6],
                'file_hash': result[7],
                'mime_type': result[8],
                'sensitivity': result[9],
                'classification': result[10],
                'risk_level': result[11],
                'notes': result[12],
                'is_current_version': result[13],
                'is_deleted': result[14],
                'deleted_at': result[15],
                'created_at': result[16],
                'updated_at': result[17]
            }
        
        return None
        
    except Exception as e:
        print(f"❌ Error retrieving file: {e}")
        try:
            session.close()
        except:
            pass
        return None


def get_all_files_for_tenant(tenant_id, owner_email=None, include_deleted=False):
    """Get all files for a tenant, optionally filtered by owner"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        query = f'''
            SELECT id, document_id, file_name, owner_user_id, owner_email,
                   file_size, file_hash, mime_type, sensitivity, classification,
                   risk_level, created_at, updated_at, is_deleted
            FROM "{schema_name}".files
            WHERE is_current_version = TRUE
        '''
        
        if not include_deleted:
            query += ' AND is_deleted = FALSE'
        
        params = {}
        if owner_email:
            query += ' AND owner_email = :owner_email'
            params['owner_email'] = owner_email
        
        query += ' ORDER BY created_at DESC'
        
        results = session.execute(text(query), params).fetchall()
        session.close()
        
        files = []
        for row in results:
            files.append({
                'id': row[0],
                'document_id': row[1],
                'file_name': row[2],
                'owner_user_id': row[3],
                'owner_email': row[4],
                'file_size': row[5],
                'file_hash': row[6],
                'mime_type': row[7],
                'sensitivity': row[8],
                'classification': row[9],
                'risk_level': row[10],
                'created_at': row[11],
                'updated_at': row[12],
                'is_deleted': row[13]
            })
        
        return files
        
    except Exception as e:
        print(f"❌ Error listing files: {e}")
        try:
            session.close()
        except:
            pass
        return []


def get_file_versions_from_db(tenant_id, document_id):
    """Get all versions of a file"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        results = session.execute(text(f'''
            SELECT id, version_number, file_name, file_size, file_hash,
                   mime_type, uploaded_by, uploaded_at, is_current
            FROM "{schema_name}".file_versions
            WHERE document_id = :document_id
            ORDER BY version_number DESC
        '''), {'document_id': document_id}).fetchall()
        
        session.close()
        
        versions = []
        for row in results:
            versions.append({
                'id': row[0],
                'version_number': row[1],
                'file_name': row[2],
                'file_size': row[3],
                'file_hash': row[4],
                'mime_type': row[5],
                'uploaded_by': row[6],
                'uploaded_at': row[7],
                'is_current': row[8]
            })
        
        return versions
        
    except Exception as e:
        print(f"❌ Error getting versions: {e}")
        try:
            session.close()
        except:
            pass
        return []


def delete_file_from_db(tenant_id, document_id, soft_delete=True):
    """Delete a file (soft or hard delete)"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        if soft_delete:
            # Soft delete - mark as deleted
            session.execute(text(f'''
                UPDATE "{schema_name}".files
                SET is_deleted = TRUE, deleted_at = NOW()
                WHERE document_id = :document_id
            '''), {'document_id': document_id})
        else:
            # Hard delete - remove from database
            session.execute(text(f'''
                DELETE FROM "{schema_name}".file_versions
                WHERE document_id = :document_id
            '''), {'document_id': document_id})
            
            session.execute(text(f'''
                DELETE FROM "{schema_name}".files
                WHERE document_id = :document_id
            '''), {'document_id': document_id})
        
        session.commit()
        session.close()
        
        print(f"✅ {'Soft' if soft_delete else 'Hard'} deleted document {document_id}")
        return {'success': True}
        
    except Exception as e:
        print(f"❌ Error deleting file: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def restore_file_from_db(tenant_id, document_id):
    """Restore a soft-deleted file"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        session.execute(text(f'''
            UPDATE "{schema_name}".files
            SET is_deleted = FALSE, deleted_at = NULL
            WHERE document_id = :document_id
        '''), {'document_id': document_id})
        
        session.commit()
        session.close()
        
        print(f"✅ Restored document {document_id}")
        return {'success': True}
        
    except Exception as e:
        print(f"❌ Error restoring file: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def update_file_metadata(tenant_id, document_id, sensitivity=None, classification=None, 
                        risk_level=None, notes=None):
    """Update file metadata"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        updates = []
        params = {'document_id': document_id}
        
        if sensitivity is not None:
            updates.append('sensitivity = :sensitivity')
            params['sensitivity'] = sensitivity
        if classification is not None:
            updates.append('classification = :classification')
            params['classification'] = classification
        if risk_level is not None:
            updates.append('risk_level = :risk_level')
            params['risk_level'] = risk_level
        if notes is not None:
            updates.append('notes = :notes')
            params['notes'] = notes
        
        if updates:
            updates.append('updated_at = NOW()')
            query = f'''
                UPDATE "{schema_name}".files
                SET {', '.join(updates)}
                WHERE document_id = :document_id
            '''
            session.execute(text(query), params)
            session.commit()
        
        session.close()
        return {'success': True}
        
    except Exception as e:
        print(f"❌ Error updating metadata: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


# ==================== FILE MANAGEMENT MODELS ====================

class File(db.Model):
    """Master file records - stores files per tenant with blob storage"""
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(50), nullable=False, index=True)  # Group ID for all versions
    file_name = db.Column(db.String(255), nullable=False)
    owner_user_id = db.Column(db.Integer, nullable=False, index=True)  # References tenant_{X}.users.id
    owner_email = db.Column(db.String(255), nullable=False, index=True)
    
    # File content stored as binary blob
    file_data = db.Column(db.LargeBinary, nullable=False)  # Blob storage
    file_size = db.Column(db.BigInteger, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash
    mime_type = db.Column(db.String(100), nullable=True)
    
    # Security and classification
    sensitivity = db.Column(db.String(50), default='Public')  # Public, Internal, Confidential, Restricted
    classification = db.Column(db.String(50), nullable=True)  # DLP classification
    risk_level = db.Column(db.String(50), nullable=True)  # Critical, High, Medium, Low
    
    # Metadata
    notes = db.Column(db.Text, nullable=True)
    is_current_version = db.Column(db.Boolean, default=True, index=True)
    is_deleted = db.Column(db.Boolean, default=False, index=True)  # For bin functionality
    deleted_at = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=db.func.now(), index=True)
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    
    # Ensure we track tenant (not FK to allow flexible schema)
    # Note: These tables will be created in each tenant schema, so tenant_id is implicit


class FileVersion(db.Model):
    """Version history for files"""
    __tablename__ = 'file_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(50), nullable=False, index=True)  # Links to File.document_id
    version_number = db.Column(db.Integer, nullable=False)  # 1, 2, 3, etc.
    file_name = db.Column(db.String(255), nullable=False)
    
    # Version content
    file_data = db.Column(db.LargeBinary, nullable=False)  # Blob storage
    file_size = db.Column(db.BigInteger, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)
    
    uploaded_by = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.now(), index=True)
    
    # Link back to current file
    is_current = db.Column(db.Boolean, default=False)
    
    __table_args__ = (
        db.UniqueConstraint('document_id', 'version_number', name='uq_document_version'),
    )


class FileSharingLink(db.Model):
    """Public/restricted shareable links for files"""
    __tablename__ = 'file_sharing_links'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(50), nullable=False, index=True)  # Links to File.document_id
    file_name = db.Column(db.String(255), nullable=False)
    share_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    
    # Security
    password_hash = db.Column(db.String(255), nullable=True)  # Bcrypt hash if password protected
    require_key_exchange = db.Column(db.Boolean, default=False)
    exchange_id = db.Column(db.String(255), nullable=True)  # Reference to KeyExchange
    
    # Metadata
    created_by = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    # Usage tracking
    last_accessed = db.Column(db.DateTime, nullable=True)
    access_count = db.Column(db.Integer, default=0)


class Sharing(db.Model):
    """Direct recipient sharing (email/username)"""
    __tablename__ = 'sharing'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(50), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    
    # Sharing details
    shared_with_email = db.Column(db.String(255), nullable=False, index=True)
    shared_by_email = db.Column(db.String(255), nullable=False)
    access_level = db.Column(db.String(50), nullable=False, default='view')  # 'view', 'edit', 'download'
    
    # Status
    is_accepted = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Timestamps
    shared_at = db.Column(db.DateTime, default=db.func.now(), index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_accessed = db.Column(db.DateTime, nullable=True)
    access_count = db.Column(db.Integer, default=0)
    
    __table_args__ = (
        db.UniqueConstraint('document_id', 'shared_with_email', name='uq_file_user_sharing'),
    )


class SharingActivity(db.Model):
    """Track all sharing activities for audit and analytics"""
    __tablename__ = 'sharing_activity'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(50), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    
    # Action details
    action = db.Column(db.String(50), nullable=False, index=True)  # 'shared', 'unshared', 'accessed', 'downloaded', 'link_created'
    shared_with_email = db.Column(db.String(255), nullable=True, index=True)
    shared_via_link = db.Column(db.String(255), nullable=True)
    shared_by_email = db.Column(db.String(255), nullable=False)
    
    # Tracking
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    activity_at = db.Column(db.DateTime, default=db.func.now(), index=True)
    
    # Additional metadata
    details = db.Column(db.JSON, nullable=True)


class KeyExchange(db.Model):
    """Security key exchanges for encrypted file sharing"""
    __tablename__ = 'key_exchanges'
    
    id = db.Column(db.Integer, primary_key=True)
    exchange_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    
    # Parties
    sharer_email = db.Column(db.String(255), nullable=False, index=True)
    recipient_email = db.Column(db.String(255), nullable=False, index=True)
    
    # File reference
    document_id = db.Column(db.String(50), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    
    # Keys and fingerprints
    sharer_public_key = db.Column(db.Text, nullable=True)
    recipient_public_key = db.Column(db.Text, nullable=True)
    sharer_fingerprint = db.Column(db.String(64), nullable=True)
    recipient_fingerprint = db.Column(db.String(64), nullable=True)
    
    # Verification status
    status = db.Column(db.String(50), default='pending', index=True)  # pending, verified, expired, rejected
    sharer_verified = db.Column(db.Boolean, default=False)
    recipient_verified = db.Column(db.Boolean, default=False)
    recipient_confirmed = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=db.func.now(), index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)


# ==================== SHARING HELPER FUNCTIONS ====================

def create_share_link(tenant_id, document_id, filename, created_by, password_hash=None, 
                      require_key_exchange=False, exchange_id=None, expires_at=None):
    """Create a share link in database"""
    import secrets
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        # Insert file
        result = session.execute(text(f'''
            INSERT INTO files (
                document_id, file_name, owner_user_id, owner_email, 
                file_data, file_size, file_hash, mime_type,
                sensitivity, classification, risk_level, notes,
                is_current_version, created_at, updated_at
            ) VALUES (
                :doc_id, :filename, :owner_id, :owner_email,
                :file_data, :file_size, :file_hash, :mime_type,
                :sensitivity, :classification, :risk_level, :notes,
                TRUE, NOW(), NOW()
            ) RETURNING id
        '''), {
            'doc_id': document_id,
            'filename': filename,
            'owner_id': owner_user_id,
            'owner_email': owner_email,
            'file_data': file_data,
            'file_size': len(file_data),
            'file_hash': file_hash,
            'mime_type': mime_type,
            'sensitivity': sensitivity,
            'classification': classification,
            'risk_level': risk_level,
            'notes': notes
        })
        
        file_id = result.fetchone()[0]
        
        # Create initial version entry
        session.execute(text(f'''
            INSERT INTO file_versions (
                document_id, version_number, file_name,
                file_data, file_size, file_hash, mime_type,
                uploaded_by, uploaded_at, is_current
            ) VALUES (
                :doc_id, 1, :filename,
                :file_data, :file_size, :file_hash, :mime_type,
                :uploaded_by, NOW(), TRUE
            )
        '''), {
            'doc_id': document_id,
            'filename': filename,
            'file_data': file_data,
            'file_size': len(file_data),
            'file_hash': file_hash,
            'mime_type': mime_type,
            'uploaded_by': owner_email
        })
        
        session.commit()
        session.close()
        
        return {
            'success': True,
            'file_id': file_id,
            'document_id': document_id,
            'filename': filename
        }
        
    except Exception as e:
        session.rollback()
        session.close()
        print(f"Error storing file in DB: {e}")
        return {'success': False, 'error': str(e)}


# NOTE: Duplicate add_file_version removed - using the correct one defined earlier (line 753)
        print(f"Error retrieving file from DB: {e}")
        return None


def delete_file_from_db(tenant_id: int, document_id: str, soft_delete: bool = True):
    """Delete or soft-delete a file from database"""
    schema_name = f"tenant_{tenant_id}"
    session = MasterSessionLocal()
    
    try:
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        if soft_delete:
            # Soft delete - mark as deleted
            session.execute(text(f'''
                UPDATE files SET 
                    is_deleted = TRUE,
                    deleted_at = NOW()
                WHERE document_id = :doc_id
            '''), {'doc_id': document_id})
        else:
            # Hard delete - remove from database
            session.execute(text(f'DELETE FROM file_versions WHERE document_id = :doc_id'), {'doc_id': document_id})
            session.execute(text(f'DELETE FROM files WHERE document_id = :doc_id'), {'doc_id': document_id})
        
        session.commit()
        session.close()
        return {'success': True}
        
    except Exception as e:
        session.rollback()
        session.close()
        print(f"Error deleting file: {e}")
        return {'success': False, 'error': str(e)}


def get_file_versions_from_db(tenant_id: int, document_id: str):
    """Get all versions of a file"""
    schema_name = f"tenant_{tenant_id}"
    session = MasterSessionLocal()
    
    try:
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        result = session.execute(text(f'''
            SELECT id, version_number, file_name, file_size, file_hash, 
                   uploaded_by, uploaded_at, is_current
            FROM file_versions
            WHERE document_id = :doc_id
            ORDER BY version_number DESC
        '''), {'doc_id': document_id}).mappings().fetchall()
        
        session.close()
        return [dict(row) for row in result]
        
    except Exception as e:
        session.close()
        print(f"Error getting file versions: {e}")
        return []


# ==================== SHARING HELPER FUNCTIONS ====================

def create_share_link(tenant_id, document_id, filename, created_by, password_hash=None, 
                      require_key_exchange=False, exchange_id=None, expires_at=None):
    """Create a share link in database"""
    import secrets
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        # Generate unique share token
        share_token = secrets.token_urlsafe(32)
        
        # Insert share link
        session.execute(text(f'''
            INSERT INTO "{schema_name}".file_sharing_links
            (document_id, file_name, share_token, password_hash, require_key_exchange,
             exchange_id, created_by, is_active, created_at, expires_at, access_count)
            VALUES
            (:document_id, :file_name, :share_token, :password_hash, :require_key_exchange,
             :exchange_id, :created_by, TRUE, NOW(), :expires_at, 0)
        '''), {
            'document_id': document_id,
            'file_name': filename,
            'share_token': share_token,
            'password_hash': password_hash,
            'require_key_exchange': require_key_exchange,
            'exchange_id': exchange_id,
            'created_by': created_by,
            'expires_at': expires_at
        })
        
        session.commit()
        session.close()
        
        print(f"✅ Created share link for {filename}: {share_token}")
        return {'success': True, 'share_token': share_token}
        
    except Exception as e:
        print(f"❌ Error creating share link: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def get_share_link_by_token(tenant_id, share_token):
    """Retrieve share link by token"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        result = session.execute(text(f'''
            SELECT id, document_id, file_name, share_token, password_hash,
                   require_key_exchange, exchange_id, created_by, is_active,
                   created_at, expires_at, last_accessed, access_count
            FROM "{schema_name}".file_sharing_links
            WHERE share_token = :token AND is_active = TRUE
        '''), {'token': share_token}).fetchone()
        
        session.close()
        
        if result:
            return {
                'id': result[0],
                'document_id': result[1],
                'file_name': result[2],
                'share_token': result[3],
                'password_hash': result[4],
                'require_key_exchange': result[5],
                'exchange_id': result[6],
                'created_by': result[7],
                'is_active': result[8],
                'created_at': result[9],
                'expires_at': result[10],
                'last_accessed': result[11],
                'access_count': result[12]
            }
        
        return None
        
    except Exception as e:
        print(f"❌ Error getting share link: {e}")
        try:
            session.close()
        except:
            pass
        return None


def update_share_link_access(tenant_id, share_token):
    """Update last accessed time and increment access count"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        session.execute(text(f'''
            UPDATE "{schema_name}".file_sharing_links
            SET last_accessed = NOW(), access_count = access_count + 1
            WHERE share_token = :token
        '''), {'token': share_token})
        
        session.commit()
        session.close()
        return True
        
    except Exception as e:
        print(f"❌ Error updating share link access: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return False


def create_key_exchange(tenant_id, exchange_id, sharer_email, recipient_email, 
                       document_id, filename, sharer_public_key=None, expires_at=None):
    """Create a key exchange record for secure sharing"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        session.execute(text(f'''
            INSERT INTO "{schema_name}".key_exchanges
            (exchange_id, sharer_email, recipient_email, document_id, file_name,
             sharer_public_key, status, created_at, expires_at)
            VALUES
            (:exchange_id, :sharer_email, :recipient_email, :document_id, :file_name,
             :sharer_public_key, 'pending', NOW(), :expires_at)
        '''), {
            'exchange_id': exchange_id,
            'sharer_email': sharer_email,
            'recipient_email': recipient_email,
            'document_id': document_id,
            'file_name': filename,
            'sharer_public_key': sharer_public_key,
            'expires_at': expires_at
        })
        
        session.commit()
        session.close()
        
        print(f"✅ Created key exchange {exchange_id}")
        return {'success': True, 'exchange_id': exchange_id}
        
    except Exception as e:
        print(f"❌ Error creating key exchange: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def get_key_exchange(tenant_id, exchange_id):
    """Get key exchange by ID"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        result = session.execute(text(f'''
            SELECT exchange_id, sharer_email, recipient_email, document_id, file_name,
                   sharer_public_key, recipient_public_key, sharer_fingerprint,
                   recipient_fingerprint, status, sharer_verified, recipient_verified,
                   recipient_confirmed, created_at, expires_at, verified_at
            FROM "{schema_name}".key_exchanges
            WHERE exchange_id = :exchange_id
        '''), {'exchange_id': exchange_id}).fetchone()
        
        session.close()
        
        if result:
            return {
                'exchange_id': result[0],
                'sharer_email': result[1],
                'recipient_email': result[2],
                'document_id': result[3],
                'file_name': result[4],
                'sharer_public_key': result[5],
                'recipient_public_key': result[6],
                'sharer_fingerprint': result[7],
                'recipient_fingerprint': result[8],
                'status': result[9],
                'sharer_verified': result[10],
                'recipient_verified': result[11],
                'recipient_confirmed': result[12],
                'created_at': result[13],
                'expires_at': result[14],
                'verified_at': result[15]
            }
        
        return None
        
    except Exception as e:
        print(f"❌ Error getting key exchange: {e}")
        try:
            session.close()
        except:
            pass
        return None


def update_key_exchange(tenant_id, exchange_id, **updates):
    """Update key exchange fields"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        # Build SET clause
        set_parts = []
        params = {'exchange_id': exchange_id}
        
        for key, value in updates.items():
            set_parts.append(f"{key} = :{key}")
            params[key] = value
        
        if set_parts:
            query = f'''
                UPDATE "{schema_name}".key_exchanges
                SET {', '.join(set_parts)}
                WHERE exchange_id = :exchange_id
            '''
            session.execute(text(query), params)
            session.commit()
        
        session.close()
        return {'success': True}
        
    except Exception as e:
        print(f"❌ Error updating key exchange: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return {'success': False, 'error': str(e)}


def log_sharing_activity(tenant_id, document_id, filename, action, shared_by_email,
                         shared_with_email=None, shared_via_link=None, ip_address=None,
                         user_agent=None, details=None):
    """Log sharing activity for audit trail"""
    schema_name = f"tenant_{tenant_id}"
    
    try:
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        session.execute(text(f'''
            INSERT INTO "{schema_name}".sharing_activity
            (document_id, file_name, action, shared_with_email, shared_via_link,
             shared_by_email, ip_address, user_agent, activity_at, details)
            VALUES
            (:document_id, :file_name, :action, :shared_with_email, :shared_via_link,
             :shared_by_email, :ip_address, :user_agent, NOW(), :details)
        '''), {
            'document_id': document_id,
            'file_name': filename,
            'action': action,
            'shared_with_email': shared_with_email,
            'shared_via_link': shared_via_link,
            'shared_by_email': shared_by_email,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': json.dumps(details) if details else None
        })
        
        session.commit()
        session.close()
        return True
        
    except Exception as e:
        print(f"❌ Error logging sharing activity: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        return False


class SuperAdmin(db.Model):
    __tablename__ = 'superadmins'
    __table_args__ = {'schema': 'public'}

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=db.func.now()
    )


def authenticate_superadmin(email: str, password: str):
    result = db.session.execute(
        text("""
            SELECT id, password_hash
            FROM public.superadmins
            WHERE email = :email AND is_active = TRUE
        """),
        {"email": email}
    ).fetchone()

    if result and bcrypt.checkpw(password.encode(), result.password_hash.encode()):
        return {"id": result.id}

    return None
