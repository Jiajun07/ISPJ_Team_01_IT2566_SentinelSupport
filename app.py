# app.py

#Note: All Log Audit Events is Gavier's. If have issues, just call me if urgent. I might not see the text

import bcrypt
import os
import hashlib
import base64
import secrets
import zipfile
import shutil
import psutil
import time
import subprocess
import smtplib
import re
import json
import atexit
import threading
from webbrowser import get
from dotenv import load_dotenv
from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, jsonify, session, flash, current_app
from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, jsonify, session, flash, flash, current_app, send_file, Response
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from sqlalchemy.orm import sessionmaker
from database import (db, MasterSessionLocal, list_backups, restore_backup, get_last_backup, authenticate_tenant_admin,
                      TenantSecurity, apply_rls_policies, authenticate_user, find_user_by_email, get_verification_code,
                      mark_verification_code_used, validate_signup_code, create_user_in_tenant, create_signup_code,
                      retention_cleanup, reactivate_tenant, get_tenant_security_status, get_user_role,
                      store_file_in_db, add_file_version, get_file_from_db, get_all_files_for_tenant, 
                      get_file_versions_from_db, delete_file_from_db, restore_file_from_db, update_file_metadata,
                      create_share_link, get_share_link_by_token, update_share_link_access,
                      create_key_exchange, get_key_exchange, update_key_exchange, log_sharing_activity, authenticate_superadmin, should_run_backup,
                      TenantBackupConfig)
from tenant_service import get_db_name_for_company
from markupsafe import escape
from forms import (Loginform, SignUpForm, ForgetPasswordForm, ResetPasswordForm, TenantDeactivateForm, CompanySignupForm,
                   SecurityBaselineForm, TenantRecoveryForm, BackupScheduleForm, BackupActionForm,AddTenantUserForm)
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from DLPScannerModules.DLPScanner import DLPScanner
from DLPScannerModules.FileProcessor import FileProcessor
from datetime import datetime, timedelta
from sqlalchemy import text
from database import archive_tenant, get_tenant_stats, Tenant
from AuditService.LogService import SysLogService
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict, deque
from ComplianceService.routes.complianceroutes import compliance_bp
from ComplianceService.routes.exportroutes import export_bp
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,     # Test connections
    "pool_recycle": 300,       # Recycle every 5 min
    "pool_size": 5,            # Smaller pool for PgBouncer
    "max_overflow": 10
}

# Initialize DB
db.init_app(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def ensure_tenant_tables_exist():
    """
    Automatically create missing tables for all existing tenant schemas.
    Called at app startup to prevent 'table does not exist' errors.
    """
    try:
        # Get all existing tenants (including inactive ones to ensure schema integrity)
        tenants = Tenant.query.all()
        
        for tenant in tenants:
            schema_name = f"tenant_{tenant.id}"
            
            try:
                # Check if schema exists
                result = db.session.execute(text(f"""
                    SELECT schema_name FROM information_schema.schemata 
                    WHERE schema_name = '{schema_name}'
                """))
                
                if not result.fetchone():
                    print(f"⚠️  Schema {schema_name} does not exist. Skipping.")
                    continue
                
                print(f"🔄 Ensuring tables exist for {schema_name}...")
                
                # Create all required tables (IF NOT EXISTS prevents duplicates)
                db.session.execute(text(f'''
                    CREATE TABLE IF NOT EXISTS "{schema_name}".users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        role VARCHAR(50) NOT NULL DEFAULT 'user',
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                '''))
                
                db.session.execute(text(f'''
                    CREATE TABLE IF NOT EXISTS "{schema_name}".documents (
                        id SERIAL PRIMARY KEY,
                        owner_user_id INT REFERENCES "{schema_name}".users(id),
                        file_path TEXT NOT NULL,
                        classification VARCHAR(50) NOT NULL,
                        version INT DEFAULT 1,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                '''))
                
                db.session.execute(text(f'''
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
                
                db.session.execute(text(f'''
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
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_document_id ON "{schema_name}".files(document_id)'))
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_owner ON "{schema_name}".files(owner_user_id)'))
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_current ON "{schema_name}".files(is_current_version)'))
                
                db.session.execute(text(f'''
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
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_versions_document ON "{schema_name}".file_versions(document_id)'))
                
                db.session.execute(text(f'''
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
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_share_links_token ON "{schema_name}".file_sharing_links(share_token)'))
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_share_links_document ON "{schema_name}".file_sharing_links(document_id)'))
                
                db.session.execute(text(f'''
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
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_sharing_document ON "{schema_name}".sharing(document_id)'))
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_sharing_recipient ON "{schema_name}".sharing(shared_with_email)'))
                
                db.session.execute(text(f'''
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
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_activity_document ON "{schema_name}".sharing_activity(document_id)'))
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_activity_action ON "{schema_name}".sharing_activity(action)'))
                
                db.session.execute(text(f'''
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
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_exchange_id ON "{schema_name}".key_exchanges(exchange_id)'))
                db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_exchange_status ON "{schema_name}".key_exchanges(status)'))
                
                db.session.commit()
                print(f"✅ Tables verified/created for {schema_name}")
                
            except Exception as e:
                print(f"❌ Error ensuring tables for {schema_name}: {e}")
                db.session.rollback()
                
    except Exception as e:
        print(f"❌ Error in ensure_tenant_tables_exist: {e}")
        db.session.rollback()

# Create public.tenants table (run once)
with app.app_context():
     db.create_all()  # creates Tenant model table
     ensure_tenant_tables_exist()  # ensure all tenant schemas have required tables

load_dotenv()

# Initialize background scheduler for bin cleanup
scheduler = BackgroundScheduler()
scheduler.add_job(func=lambda: cleanup_bin_wrapper(), trigger="interval", hours=1, id='bin_cleanup')
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())


UPLOAD_FOLDER = os.path.join(app.root_path, 'DLPScannerModules', 'testfiles', 'upload')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads")
app.config['PENDING_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads_pending")
app.config['VERSIONS_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads", "versions")
VERSIONS_JSON = os.path.join(os.path.dirname(__file__), "file_versions.json")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg", "txt"}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PENDING_FOLDER'], exist_ok=True)
os.makedirs(app.config['VERSIONS_FOLDER'], exist_ok=True)

configPath = os.path.join(app.root_path, "config", "keywords.json")
fileConfigPath = os.path.join(app.root_path, "config", "supportedfiles.json")
dlpScanner = DLPScanner(configPath)
fileProcessor = FileProcessor(fileConfigPath)
app.register_blueprint(compliance_bp, url_prefix='/compliance')
app.register_blueprint(export_bp, url_prefix='/export')

csrf = CSRFProtect(app)



# Global error handler for database transaction errors
@app.errorhandler(Exception)
def handle_exception(e):
    """Handle uncaught exceptions and rollback database transactions"""
    # Rollback any pending database transactions
    db.session.rollback()
    
    # Log the error
    print(f"❌ Unhandled exception: {type(e).__name__}: {e}")
    
    # Re-raise the exception so Flask can handle it normally
    raise

performance_metrics = {
    'response_times': deque(maxlen=1000),  
    'api_requests': defaultdict(int),      
    'api_errors': defaultdict(int),        
    'total_requests': 0,
    'total_errors': 0,
    'start_time': time.time()
}

@app.before_request
def before_request():
    g.start_time = time.time()
    performance_metrics['total_requests'] += 1
    endpoint = request.endpoint or 'unknown'
    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
        request.headers.get('Content-Type', '').startswith('application/json') or
        request.headers.get('Accept', '').startswith('application/json')
    )
    if (request.path.startswith('/api/') or 
        is_ajax or 
        request.headers.get('Content-Type') == 'application/json'):
        performance_metrics['api_requests'][endpoint] += 1

@app.after_request
def after_request(response):
    try:
        if hasattr(g, 'start_time'):
            response_time = (time.time() - g.start_time) * 1000
            performance_metrics['response_times'].append(response_time)
            if response.status_code >= 400:
                performance_metrics['total_errors'] += 1
                endpoint = request.endpoint or 'unknown'
                is_ajax = (
                    request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
                    request.headers.get('Content-Type', '').startswith('application/json') or
                    request.headers.get('Accept', '').startswith('application/json')
                )
                
                if (request.path.startswith('/api/') or 
                    is_ajax or 
                    request.headers.get('Content-Type') == 'application/json'):
                    performance_metrics['api_errors'][endpoint] += 1
    except Exception as e:
        print(f"Error tracking response metrics: {e}")
    
    return response


def get_current_tenant():
    """Get current tenant ID from session, fallback to request only if needed"""
    tenant_id = session.get('tenant_id')
    if tenant_id:
        return str(tenant_id)
    return request.args.get('tenant') or request.form.get('tenant')

def get_tenant_upload_folder(tenant_id):
    """Get upload folder for specific tenant"""
    tenant_folder = os.path.join(os.path.dirname(__file__), "uploads", f"tenant_{tenant_id}")
    os.makedirs(tenant_folder, exist_ok=True)
    return tenant_folder

def sanitize_filename(filename):
    """Sanitize filename while preserving spaces and common characters."""
    # Remove any path components
    filename = os.path.basename(filename)
    # Remove potentially dangerous characters but keep spaces, dots, hyphens, underscores, parentheses
    filename = re.sub(r'[^\w\s.()-]', '', filename)
    # Remove any leading/trailing whitespace or dots
    filename = filename.strip('. ')
    # Collapse multiple spaces into one
    filename = re.sub(r'\s+', ' ', filename)
    return filename if filename else 'unnamed'

@app.route("/", methods=["GET", "POST"])
def home():
    user_email = session.get('email', 'Anonymous')
    log_audit_event(
        action_type='HOME_ACCESS',
        description=f"User {user_email} accessed home page",
        category='USER_ACTIVITY',
        user_email=user_email
    )
    return render_template("front_page.html")




app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads")
app.config['PENDING_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads_pending")
app.config['VERSIONS_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads", "versions")
VERSIONS_JSON = os.path.join(os.path.dirname(__file__), "file_versions.json")
FILE_METADATA_JSON = os.path.join(os.path.dirname(__file__), "file_metadata.json")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg", "txt"}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PENDING_FOLDER'], exist_ok=True)
os.makedirs(app.config['VERSIONS_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def compute_sha256(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_versions():
    """Load version history from JSON file."""
    if not os.path.exists(VERSIONS_JSON):
        return {}
    try:
        with open(VERSIONS_JSON, 'r') as f:
            return json.load(f)
    except:
        return {}


def save_versions(versions):
    """Save version history to JSON file."""
    with open(VERSIONS_JSON, 'w') as f:
        json.dump(versions, f, indent=2)


def load_file_metadata():
    if not os.path.exists(FILE_METADATA_JSON):
        return {}
    try:
        with open(FILE_METADATA_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_file_metadata(metadata):
    with open(FILE_METADATA_JSON, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)


def set_file_metadata(filename, tenant_id, metadata):
    all_metadata = load_file_metadata()
    tenant_key = f"tenant_{tenant_id}"
    if tenant_key not in all_metadata:
        all_metadata[tenant_key] = {}
    all_metadata[tenant_key][filename] = metadata
    save_file_metadata(all_metadata)


def get_file_metadata(filename, tenant_id):
    all_metadata = load_file_metadata()
    tenant_key = f"tenant_{tenant_id}"
    return all_metadata.get(tenant_key, {}).get(filename, {})


def rename_file_metadata(old_name, new_name, tenant_id):
    all_metadata = load_file_metadata()
    tenant_key = f"tenant_{tenant_id}"
    tenant_meta = all_metadata.get(tenant_key, {})
    if old_name in tenant_meta:
        tenant_meta[new_name] = tenant_meta.pop(old_name)
        all_metadata[tenant_key] = tenant_meta
        save_file_metadata(all_metadata)


def add_version(filename, version_info, tenant_id=None):
    """Add a new version entry for a file for a specific tenant."""
    if tenant_id is None:
        tenant_id = get_current_tenant()
    versions = load_versions()
    version_key = f"tenant_{tenant_id}/{filename}"
    if version_key not in versions:
        versions[version_key] = []
    versions[version_key].append(version_info)
    save_versions(versions)


def get_file_versions(filename, tenant_id=None):
    """Get all versions of a file for a specific tenant."""
    if tenant_id is None:
        tenant_id = get_current_tenant()
    versions = load_versions()
    version_key = f"tenant_{tenant_id}/{filename}"
    return versions.get(version_key, [])


def delete_file_versions(filename, tenant_id=None):
    """Delete all version history for a file."""
    if tenant_id is None:
        tenant_id = get_current_tenant()
    versions = load_versions()
    version_key = f"tenant_{tenant_id}/{filename}"
    if version_key in versions:
        del versions[version_key]
        save_versions(versions)


def detect_file_extension(filepath):
    """Detect file type from magic bytes and return appropriate extension."""
    try:
        with open(filepath, 'rb') as f:
            magic_bytes = f.read(12)
        
        # Check magic bytes for common file types
        if magic_bytes.startswith(b'\xFF\xD8\xFF'):  # JPEG
            return '.jpg'
        elif magic_bytes.startswith(b'\x89PNG'):  # PNG
            return '.png'
        elif magic_bytes.startswith(b'%PDF'):  # PDF
            return '.pdf'
        elif magic_bytes.startswith(b'PK\x03\x04'):  # ZIP (DOCX, XLSX, etc)
            return '.docx'
        elif magic_bytes.startswith(b'\xD0\xCF\x11\xE0'):  # OLE (DOC, XLS)
            return '.doc'
        else:
            return '.bin'  # Unknown binary
    except:
        return '.bin'


def detect_file_extension_from_data(file_data):
    """Detect file type from magic bytes in binary data and return appropriate extension."""
    try:
        magic_bytes = file_data[:12] if len(file_data) >= 12 else file_data
        
        # Check magic bytes for common file types
        if magic_bytes.startswith(b'\xFF\xD8\xFF'):  # JPEG
            return '.jpg'
        elif magic_bytes.startswith(b'\x89PNG'):  # PNG
            return '.png'
        elif magic_bytes.startswith(b'%PDF'):  # PDF
            return '.pdf'
        elif magic_bytes.startswith(b'PK\x03\x04'):  # ZIP (DOCX, XLSX, etc)
            return '.docx'
        elif magic_bytes.startswith(b'\xD0\xCF\x11\xE0'):  # OLE (DOC, XLS)
            return '.doc'
        else:
            return '.bin'  # Unknown binary
    except:
        return '.bin'


def get_file_extension(filename):
    """Get file extension, preferring actual file content detection."""
    _, ext = os.path.splitext(filename)
    return ext if ext else '.bin'


def get_uploaded_files():
    """Get all files from database for current tenant"""
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    
    # Get all files from database
    db_files = get_all_files_for_tenant(tenant_id, owner_email=user_email, include_deleted=False)
    
    files = []
    for db_file in db_files:
        files.append({
            "name": db_file['file_name'],
            "size": db_file['file_size'],
            "url": url_for("download_file", filename=db_file['file_name'], tenant=tenant_id),
            "hash": db_file['file_hash'],
            "owner": db_file['owner_email'],
            "modified": db_file['updated_at'].strftime('%d %B %Y') if db_file.get('updated_at') else 'N/A',
            "sensitivity": db_file.get('sensitivity') or 'Public',
            "document_id": db_file['document_id']
        })
    
    return files


@app.route('/myfiles', methods=['GET'])
def myfiles():
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    files = get_uploaded_files()

    log_tenant_event(
        action_type='TENANT_FILE_ACCESS',
        description=f"User {user_email} accessed their file list",
        category='FILE_MANAGEMENT',
        tenant_id=tenant_id,
        user_email=user_email,
        target_resource='FILE_LIST',
        additional_data={'file_count': len(files)}
    )

    return render_template("users/myfiles.html", files=files, tenant_id=tenant_id, account_name=user_email)


@app.route('/shared-with-me', methods=['GET'])
def shared_with_me():
    """View files shared with current tenant - uses database"""
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    
    # Query sharing_activity table for files shared with this tenant
    # We'll get unique file shares for this tenant
    from sqlalchemy import text
    
    try:
        with db.engine.connect() as conn:
            conn.execute(text(f'SET search_path TO tenant_{tenant_id}'))
            
            # Get all active share links where files have been accessed
            query = text("""
                SELECT DISTINCT ON (fsl.document_id)
                    f.document_id,
                    f.file_name,
                    f.file_size,
                    f.updated_at,
                    f.sensitivity,
                    fsl.share_token,
                    fsl.created_by as owner,
                    fsl.require_key_exchange,
                    fsl.exchange_id,
                    fsl.created_at as date_shared
                FROM file_sharing_links fsl
                JOIN files f ON fsl.document_id = f.document_id
                WHERE f.is_deleted = FALSE
                ORDER BY fsl.document_id, fsl.created_at DESC
            """)
            
            result = conn.execute(query)
            rows = result.fetchall()
            
            tenant_shares = []
            for row in rows:
                verification_status = 'not_required'
                if row[7]:  # require_key_exchange
                    if row[8]:  # exchange_id
                        exchange = get_key_exchange(tenant_id, row[8])
                        if exchange:
                            verification_status = exchange.get('status', 'pending')
                            # Only show verified exchanges
                            if verification_status != 'verified':
                                continue
                        else:
                            continue
                
                tenant_shares.append({
                    'document_id': row[0],
                    'name': row[1],
                    'size': row[2],
                    'modified': row[3].strftime('%Y-%m-%d %H:%M:%S') if row[3] else 'N/A',
                    'owner': row[6],
                    'sensitivity': row[4] or 'Public',
                    'url': f"/download/shared/{row[1]}?share={row[5]}&tenant={tenant_id}",
                    'share_token': row[5],
                    'owner_tenant_id': tenant_id,
                    'require_key_exchange': row[7],
                    'exchange_id': row[8],
                    'verification_status': verification_status,
                    'date_shared': row[9].strftime('%Y-%m-%d') if row[9] else 'N/A'
                })
            
            return render_template("users/shared_with_me.html", files=tenant_shares, tenant_id=tenant_id, account_name=user_email)
    
    except Exception as e:
        print(f"❌ Error loading shared files: {e}")
        #log audit event

    log_user_activity(
        action_type='SHARED_FILES_ACCESS',
        description=f"User accessed shared files list",
        category='FILE_MANAGEMENT',
        target_resource='SHARED_FILES',
        additional_data={'shared_file_count': len(tenant_shares)}
    )
    return render_template("users/shared_with_me.html", files=[], tenant_id=tenant_id, account_name=user_email)


# Share link storage (in production, use database)
SHARE_LINKS_FILE = os.path.join(os.path.dirname(__file__), "share_links.json")
SHARE_LINKS_LOG = os.path.join(os.path.dirname(__file__), "share_links_log.txt")
RECEIVED_SHARES_FILE = os.path.join(os.path.dirname(__file__), "received_shares.json")
KEY_EXCHANGE_JSON = os.path.join(os.path.dirname(__file__), "key_exchanges.json")
USER_KEYS_JSON = os.path.join(os.path.dirname(__file__), "user_keys.json")
BIN_METADATA_FILE = os.path.join(os.path.dirname(__file__), "bin_metadata.json")
BIN_FOLDER = os.path.join(os.path.dirname(__file__), "bin")
os.makedirs(BIN_FOLDER, exist_ok=True)

def load_received_shares():
    """Load received shares from JSON file"""
    if not os.path.exists(RECEIVED_SHARES_FILE):
        return {}
    try:
        with open(RECEIVED_SHARES_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_received_shares(shares):
    """Save received shares to JSON file"""
    with open(RECEIVED_SHARES_FILE, 'w') as f:
        json.dump(shares, f, indent=2)

def load_share_links():
    """Load share links from JSON file"""
    if not os.path.exists(SHARE_LINKS_FILE):
        return {}
    try:
        with open(SHARE_LINKS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_share_links(links):
    """Save share links to JSON file"""
    with open(SHARE_LINKS_FILE, 'w') as f:
        json.dump(links, f, indent=2)


def load_bin_metadata():
    """Load bin metadata from JSON file"""
    if not os.path.exists(BIN_METADATA_FILE):
        return {}
    try:
        with open(BIN_METADATA_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}


def save_bin_metadata(metadata):
    """Save bin metadata to JSON file"""
    with open(BIN_METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=2, default=str)


def move_file_to_bin(filename, tenant_id, original_path):
    """Move a file to bin instead of permanently deleting it"""
    bin_metadata = load_bin_metadata()
    
    # Create unique bin entry key
    bin_key = f"tenant_{tenant_id}/{filename}_{int(datetime.now().timestamp())}"
    
    # Create bin file path
    bin_filename = f"{tenant_id}_{filename}_{int(datetime.now().timestamp())}"
    bin_file_path = os.path.join(BIN_FOLDER, bin_filename)
    
    # Copy file to bin folder
    try:
        if os.path.exists(original_path):
            shutil.copy2(original_path, bin_file_path)
    except Exception as e:
        print(f"Error copying file to bin: {e}")
    
    # Store metadata
    bin_metadata[bin_key] = {
        'original_filename': filename,
        'tenant_id': tenant_id,
        'bin_filename': bin_filename,
        'deleted_at': datetime.now().isoformat(),
        'original_path': original_path,
        'versions': get_file_versions(filename, tenant_id) if filename else []
    }
    
    save_bin_metadata(bin_metadata)
    return bin_key


def restore_file_from_bin(bin_key):
    """Restore a file from bin"""
    bin_metadata = load_bin_metadata()
    
    if bin_key not in bin_metadata:
        return False, "File not found in bin"
    
    entry = bin_metadata[bin_key]
    filename = entry['original_filename']
    tenant_id = entry['tenant_id']
    bin_filename = entry['bin_filename']
    bin_file_path = os.path.join(BIN_FOLDER, bin_filename)
    
    # Restore file to original location
    tenant_folder = get_tenant_upload_folder(tenant_id)
    restore_path = os.path.join(tenant_folder, filename)
    
    try:
        if os.path.exists(bin_file_path):
            shutil.copy2(bin_file_path, restore_path)
        
        # Restore version history if exists
        if entry.get('versions'):
            versions = load_versions()
            version_key = f"tenant_{tenant_id}/{filename}"
            versions[version_key] = entry['versions']
            save_versions(versions)
        
        # Remove from bin
        del bin_metadata[bin_key]
        save_bin_metadata(bin_metadata)
        
        return True, "File restored successfully"
    except Exception as e:
        return False, str(e)


def permanently_delete_from_bin(bin_key):
    """Permanently delete a file from bin"""
    bin_metadata = load_bin_metadata()
    
    if bin_key not in bin_metadata:
        return False, "File not found in bin"
    
    entry = bin_metadata[bin_key]
    bin_filename = entry['bin_filename']
    bin_file_path = os.path.join(BIN_FOLDER, bin_filename)
    
    try:
        # Delete bin file
        if os.path.exists(bin_file_path):
            os.remove(bin_file_path)
        
        # Remove metadata
        del bin_metadata[bin_key]
        save_bin_metadata(bin_metadata)
        
        return True, "File permanently deleted"
    except Exception as e:
        return False, str(e)


def cleanup_bin():
    """Automatically delete files from bin older than 30 days"""
    bin_metadata = load_bin_metadata()
    current_time = datetime.now()
    deleted_count = 0
    
    for bin_key, entry in list(bin_metadata.items()):
        try:
            deleted_at = datetime.fromisoformat(entry['deleted_at'])
            if (current_time - deleted_at).days >= 30:
                # Permanently delete the file
                bin_filename = entry['bin_filename']
                bin_file_path = os.path.join(BIN_FOLDER, bin_filename)
                
                if os.path.exists(bin_file_path):
                    os.remove(bin_file_path)
                
                del bin_metadata[bin_key]
                deleted_count += 1
        except Exception as e:
            print(f"Error cleaning up bin entry {bin_key}: {e}")
    
    if deleted_count > 0:
        save_bin_metadata(bin_metadata)
    
    print(f"✅ Bin cleanup: {deleted_count} files permanently deleted")
    return deleted_count


def cleanup_bin_wrapper():
    """Wrapper for scheduler to run cleanup_bin safely"""
    try:
        cleanup_bin()
    except Exception as e:
        print(f"❌ Error in scheduled bin cleanup: {e}")


def add_verified_share_to_recipient(exchange_id, exchange):
    """Ensure verified exchange shows in recipient's shared list."""
    try:
        recipient_tenant = str(exchange.get('recipient_tenant') or '')
        if not recipient_tenant or recipient_tenant == 'pending':
            return

        share_links = load_share_links()
        token = None
        link_info = None
        for share_token, info in share_links.items():
            if info.get('exchange_id') == exchange_id:
                token = share_token
                link_info = info
                break
        if not token or not link_info:
            return

        filename = link_info.get('filename') or exchange.get('filename')
        owner_tenant_id = str(link_info.get('tenant_id') or '')
        if not filename or not owner_tenant_id:
            return

        owner_folder = get_tenant_upload_folder(owner_tenant_id)
        file_path = os.path.join(owner_folder, filename)
        version_path = os.path.join(app.config['VERSIONS_FOLDER'], filename)
        source_path = file_path if os.path.exists(file_path) else version_path if os.path.exists(version_path) else None
        if not source_path:
            return

        file_stats = os.stat(source_path)
        file_info = {
            'name': filename,
            'size': file_stats.st_size,
            'modified': datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'owner': link_info.get('owner', 'Unknown'),
            'sensitivity': 'Shared',
            'url': f"/download/shared/{filename}?share={token}&tenant={owner_tenant_id}",
            'share_token': token,
            'owner_tenant_id': owner_tenant_id,
            'require_key_exchange': True,
            'exchange_id': exchange_id,
            'verification_status': 'verified'
        }

        received_shares = load_received_shares()
        recipient_key = f'tenant_{recipient_tenant}'
        if recipient_key not in received_shares:
            received_shares[recipient_key] = []

        existing = next((f for f in received_shares[recipient_key] if f.get('share_token') == token), None)
        if not existing:
            file_info['date_shared'] = datetime.now().strftime('%Y-%m-%d')
            received_shares[recipient_key].append(file_info)
        else:
            existing.update(file_info)

        save_received_shares(received_shares)
    except Exception:
        return


def load_user_keys():
    """Load user keys from JSON"""
    if not os.path.exists(USER_KEYS_JSON):
        return {}
    try:
        with open(USER_KEYS_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_keys(keys):
    """Save user keys to JSON"""
    with open(USER_KEYS_JSON, 'w', encoding='utf-8') as f:
        json.dump(keys, f, indent=2)


def generate_user_keypair(user_id, tenant_id):
    """Generate RSA keypair for a user"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    user_keys = load_user_keys()
    key_id = f"tenant_{tenant_id}/{user_id}"
    user_keys[key_id] = {
        "public_key": public_key_pem,
        "private_key": private_key_pem,
        "created": datetime.now().isoformat()
    }
    save_user_keys(user_keys)

    return public_key_pem


def get_or_create_user_key(user_id, tenant_id):
    """Get user's public key or create if not exists"""
    user_keys = load_user_keys()
    key_id = f"tenant_{tenant_id}/{user_id}"

    if key_id not in user_keys:
        return generate_user_keypair(user_id, tenant_id)

    return user_keys[key_id].get("public_key")


def load_key_exchanges():
    """Load key exchanges from JSON"""
    if not os.path.exists(KEY_EXCHANGE_JSON):
        return {}
    try:
        with open(KEY_EXCHANGE_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_key_exchanges(exchanges):
    """Save key exchanges to JSON"""
    with open(KEY_EXCHANGE_JSON, 'w', encoding='utf-8') as f:
        json.dump(exchanges, f, indent=2)


def generate_fingerprint(public_key_pem):
    """Generate a human-readable fingerprint from public key"""
    if not public_key_pem:
        return None
    key_hash = hashlib.sha256(public_key_pem.encode()).digest()
    fingerprint = base64.b64encode(key_hash).decode()[:16]
    return fingerprint.upper()


def log_share_link(share_token, filename, owner, tenant_id, base_url, has_password=False):
    """Log share link generation to text file"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    share_url = f"{base_url}/shared-with-me?share={share_token}&tenant={tenant_id}"
    
    log_entry = f"""
{'='*80}
Timestamp: {timestamp}
Sharer: {owner}
Tenant ID: {tenant_id}
Filename: {filename}
Share Token: {share_token}
Share Link: {share_url}
Password Protected: {'Yes' if has_password else 'No'}
{'='*80}
"""
    
    with open(SHARE_LINKS_LOG, 'a', encoding='utf-8') as f:
        f.write(log_entry)


@csrf.exempt
@app.route('/generate_share_link', methods=['POST'])
def generate_share_link():
    """Generate a secure share link for a file - stores in database"""
    try:
        data = request.json
        filename = data.get('filename')
        tenant_id = get_current_tenant()
        password = data.get('password')
        require_key_exchange = bool(data.get('require_key_exchange'))
        exchange_id = data.get('exchange_id')
        recipient_email = data.get('recipient_email')
        owner = session.get('email', 'Unknown')
        
        if not filename:
            return jsonify({'error': 'Filename required'}), 400

        if require_key_exchange and not exchange_id:
            return jsonify({'error': 'Key exchange required but exchange ID missing'}), 400
        
        # Get file from database
        file_record = get_file_from_db(tenant_id, filename=filename)
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        document_id = file_record['document_id']
        
        # Hash password if provided
        password_hash = None
        if password:
            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash(password)
        
        # Create share link in database
        result = create_share_link(
            tenant_id=tenant_id,
            document_id=document_id,
            filename=filename,
            created_by=owner,
            password_hash=password_hash,
            require_key_exchange=require_key_exchange,
            exchange_id=exchange_id,
            expires_at=None  # Could add expiration from request
        )
        
        if not result.get('success'):
            return jsonify({'error': 'Failed to create share link'}), 500
        
        share_token = result['share_token']
        
        # Generate the full share URL
        base_url = request.host_url.rstrip('/')
        share_url = f"{base_url}/shared-with-me?share={share_token}&tenant={tenant_id}"
        
        # Log sharing activity
        log_sharing_activity(
            tenant_id=tenant_id,
            document_id=document_id,
            filename=filename,
            action='link_created',
            shared_by_email=owner,
            shared_via_link=share_token,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            details={'password_protected': bool(password), 'key_exchange': require_key_exchange}
        )
        
        log_tenant_event(
            action_type='SHARE_LINK_GENERATED',
            description=f"Share link generated for file: {filename}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            tenant_id=tenant_id,
            resource_id=filename,
            additional_data={
                'recipient_email': recipient_email,
                'password_protected': bool(password),
                'require_key_exchange': require_key_exchange,
                'share_token': share_token[:8] + '...'
            }
        )

        return jsonify({
            'success': True,
            'share_link': share_url,
            'token': share_token
        })
        
    except Exception as e:
        print(f"❌ Error generating share link: {e}")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/initiate_key_exchange', methods=['POST'])
def initiate_key_exchange():
    """Initiate a key exchange for secure file sharing - stores in database"""
    try:
        data = request.json
        filename = data.get('filename')
        recipient_email = data.get('recipient_email')
        tenant_id = get_current_tenant()
        sharer_email = session.get('email', 'Unknown')

        if not filename or not recipient_email:
            return jsonify({'error': 'Missing filename or recipient email'}), 400

        # Get file from database
        file_record = get_file_from_db(tenant_id, filename=filename)
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        document_id = file_record['document_id']
        
        # Generate or get user's public key
        sharer_public_key = get_or_create_user_key(sharer_email, tenant_id)
        
        # Generate unique exchange ID
        import secrets
        exchange_id = secrets.token_urlsafe(32)
        
        # Create key exchange in database
        result = create_key_exchange(
            tenant_id=tenant_id,
            exchange_id=exchange_id,
            sharer_email=sharer_email,
            recipient_email=recipient_email,
            document_id=document_id,
            filename=filename,
            sharer_public_key=sharer_public_key,
            expires_at=None  # Could add expiration
        )
        
        if not result.get('success'):
            return jsonify({'error': 'Failed to create key exchange'}), 500

        sharer_fingerprint = generate_fingerprint(sharer_public_key)

        # Log activity
        log_sharing_activity(
            tenant_id=tenant_id,
            document_id=document_id,
            filename=filename,
            action='key_exchange_initiated',
            shared_by_email=sharer_email,
            shared_with_email=recipient_email,
            details={'exchange_id': exchange_id}
        )

        return jsonify({
            'success': True,
            'exchange_id': exchange_id,
            'sharer_fingerprint': sharer_fingerprint
        }), 200

    except Exception as e:
        print(f"❌ Error initiating key exchange: {e}")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/get_pending_verifications', methods=['GET'])
def get_pending_verifications():
    """Get pending key exchange verifications for current user - uses database"""
    try:
        tenant_id = get_current_tenant()
        user_email = session.get('email', '')
        
        from sqlalchemy import text
        
        with db.engine.connect() as conn:
            conn.execute(text(f'SET search_path TO tenant_{tenant_id}'))
            
            # Get all pending key exchanges for this tenant
            query = text("""
                SELECT 
                    ke.exchange_id,
                    f.file_name,
                    ke.sharer_email,
                    ke.recipient_email,
                    ke.sharer_public_key,
                    ke.recipient_fingerprint,
                    ke.created_at,
                    ke.recipient_verified,
                    ke.sharer_verified,
                    ke.recipient_confirmed,
                    ke.status
                FROM key_exchanges ke
                JOIN files f ON ke.document_id = f.document_id
                WHERE ke.status = 'pending'
                AND (ke.sharer_email = :user_email OR ke.recipient_email = :user_email)
            """)
            
            result = conn.execute(query, {'user_email': user_email})
            rows = result.fetchall()
            
            pending = []
            for row in rows:
                is_sharer = row[2] == user_email  # sharer_email
                pending.append({
                    'exchange_id': row[0],
                    'filename': row[1],
                    'sharer_id': row[2],
                    'recipient_email': row[3],
                    'sharer_fingerprint': generate_fingerprint(row[4]) if row[4] else '',
                    'recipient_fingerprint': row[5] or '',
                    'created': row[6].isoformat() if row[6] else '',
                    'recipient_verified': row[7],
                    'sharer_verified': row[8],
                    'recipient_confirmed': row[9],
                    'is_sharer': is_sharer
                })

        return jsonify({'success': True, 'pending_verifications': pending}), 200

    except Exception as e:
        print(f"❌ Error getting pending verifications: {e}")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/submit_recipient_key/<exchange_id>', methods=['POST'])
def submit_recipient_key(exchange_id):
    """Recipient submits their public key for the key exchange - uses database"""
    try:
        tenant_id = get_current_tenant()
        data = request.json
        recipient_email = data.get('recipient_email')

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        recipient_fingerprint = generate_fingerprint(public_key_pem)

        # Get exchange from database
        exchange = get_key_exchange(tenant_id, exchange_id)
        if not exchange:
            return jsonify({'error': 'Exchange not found'}), 404

        # Update exchange with recipient data
        update_key_exchange(
            tenant_id=tenant_id,
            exchange_id=exchange_id,
            recipient_public_key=public_key_pem,
            recipient_email=recipient_email or exchange.get('recipient_email'),
            recipient_verified=True,
            recipient_fingerprint=recipient_fingerprint
        )

        return jsonify({
            'success': True,
            'recipient_fingerprint': recipient_fingerprint,
            'message': 'Your key has been generated. Share this fingerprint with the sharer.'
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/verify_recipient_fingerprint/<exchange_id>', methods=['POST'])
def verify_recipient_fingerprint(exchange_id):
    """Sharer verifies recipient's fingerprint - uses database"""
    try:
        tenant_id = get_current_tenant()
        data = request.json
        recipient_fingerprint = data.get('recipient_fingerprint')

        # Get exchange from database
        exchange = get_key_exchange(tenant_id, exchange_id)
        if not exchange:
            return jsonify({'error': 'Exchange not found'}), 404

        actual_fingerprint = generate_fingerprint(exchange.get('recipient_public_key'))

        if not actual_fingerprint:
            return jsonify({'success': False, 'error': 'Recipient has not generated their key yet. Please ask them to generate their key first.'}), 400

        if recipient_fingerprint != actual_fingerprint:
            return jsonify({'success': False, 'error': 'Fingerprint mismatch!'}), 400

        # Determine new status
        new_status = 'verified' if exchange.get('recipient_confirmed') else exchange.get('status', 'pending')
        
        # Update exchange in database
        update_key_exchange(
            tenant_id=tenant_id,
            exchange_id=exchange_id,
            sharer_verified=True,
            status=new_status
        )

        return jsonify({'success': True, 'message': 'Recipient identity verified.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/verify_sharer_fingerprint/<exchange_id>', methods=['POST'])
def verify_sharer_fingerprint(exchange_id):
    """Recipient verifies sharer's fingerprint - uses database"""
    try:
        tenant_id = get_current_tenant()
        data = request.json
        sharer_fingerprint = data.get('sharer_fingerprint')

        # Get exchange from database
        exchange = get_key_exchange(tenant_id, exchange_id)
        if not exchange:
            return jsonify({'error': 'Exchange not found'}), 404

        actual_fingerprint = generate_fingerprint(exchange.get('sharer_public_key'))

        if not actual_fingerprint:
            return jsonify({'success': False, 'error': 'Sharer public key not available. This should not happen.'}), 400

        if sharer_fingerprint != actual_fingerprint:
            return jsonify({'success': False, 'error': 'Fingerprint mismatch!'}), 400

        # Determine new status
        new_status = 'verified' if exchange.get('sharer_verified') else exchange.get('status', 'pending')
        
        # Update exchange in database
        update_key_exchange(
            tenant_id=tenant_id,
            exchange_id=exchange_id,
            recipient_confirmed=True,
            status=new_status
        )

        return jsonify({'success': True, 'message': 'Sharer identity verified.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/verify-identities', methods=['GET'])
def verify_identities():
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    return render_template('users/verify_identities.html', tenant_id=tenant_id, account_name=user_email)


@csrf.exempt
@app.route('/clear_pending_verifications', methods=['POST'])
def clear_pending_verifications():
    """Clear all pending verifications for current tenant - uses database"""
    try:
        tenant_id = get_current_tenant()
        user_email = session.get('email', '')
        
        from sqlalchemy import text
        
        with db.engine.connect() as conn:
            conn.execute(text(f'SET search_path TO tenant_{tenant_id}'))
            
            # Delete all pending key exchanges for this user
            delete_query = text("""
                DELETE FROM key_exchanges
                WHERE status = 'pending'
                AND (sharer_email = :user_email OR recipient_email = :user_email)
            """)
            
            result = conn.execute(delete_query, {'user_email': user_email})
            conn.commit()
            
            deleted_count = result.rowcount
        
        return jsonify({'success': True, 'message': f'Cleared {deleted_count} pending verification(s).'}), 200
    
    except Exception as e:
        print(f"❌ Error clearing pending verifications: {e}")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@csrf.exempt
@app.route('/validate_share_link', methods=['GET', 'POST'])
def validate_share_link():
    """Validate a share link and return file info - uses database"""
    try:
        # Handle both GET and POST requests
        if request.method == 'GET':
            share_token = request.args.get('share')
            tenant_id = request.args.get('tenant', get_current_tenant())
            password = None
        else:
            # For POST, check if it's JSON
            if request.is_json:
                share_token = request.json.get('share')
                tenant_id = request.json.get('tenant', get_current_tenant())
                password = request.json.get('password')
            else:
                return jsonify({'error': 'Invalid request format'}), 400
        
        if not share_token:
            return jsonify({'error': 'Share token required'}), 400
        
        # Get share link from database
        link_info = get_share_link_by_token(tenant_id, share_token)
        
        if not link_info:
            return jsonify({'error': 'Invalid or expired share link'}), 404
        
        # Check if password is required
        if link_info.get('password_hash'):
            if not password:
                return jsonify({'error': 'Password required', 'requires_password': True}), 401
            from werkzeug.security import check_password_hash
            if not check_password_hash(link_info['password_hash'], password):
                return jsonify({'error': 'Incorrect password'}), 401
        
        document_id = link_info['document_id']
        filename = link_info['file_name']
        require_key_exchange = bool(link_info.get('require_key_exchange'))
        exchange_id = link_info.get('exchange_id')
        
        # Get file from database
        file_record = get_file_from_db(tenant_id, document_id=document_id)
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404

        verification_status = 'not_required'
        if require_key_exchange:
            if not exchange_id:
                verification_status = 'exchange_not_found'
            else:
                exchange = get_key_exchange(tenant_id, exchange_id)
                if not exchange:
                    verification_status = 'exchange_not_found'
                else:
                    verification_status = 'verified' if exchange.get('status') == 'verified' else 'pending'
        
        # Build file info response
        file_info = {
            'name': filename,
            'size': file_record['file_size'],
            'modified': file_record['updated_at'].strftime('%Y-%m-%d %H:%M:%S') if file_record.get('updated_at') else 'N/A',
            'owner': link_info.get('created_by', 'Unknown'),
            'sensitivity': file_record.get('sensitivity', 'Shared'),
            'url': f"/download/shared/{filename}?share={share_token}&tenant={tenant_id}",
            'share_token': share_token,
            'owner_tenant_id': tenant_id,
            'require_key_exchange': require_key_exchange,
            'exchange_id': exchange_id,
            'verification_status': verification_status,
            'document_id': document_id
        }
        
        # Get version history from database
        versions_raw = get_file_versions_from_db(tenant_id, document_id)
        versions = []
        for v in versions_raw:
            versions.append({
                "version": v['version_number'],
                "name": v['file_name'],
                "uploaded_by": v['uploaded_by'],
                "date": v['uploaded_at'].strftime('%d %B %Y') if v.get('uploaded_at') else 'N/A',
                "size": v['file_size'],
                "hash": v['file_hash'],
                "is_current": v.get('is_current', False)
            })
        
        # Update access tracking
        update_share_link_access(tenant_id, share_token)
        
        # Log access
        log_sharing_activity(
            tenant_id=tenant_id,
            document_id=document_id,
            filename=filename,
            action='accessed',
            shared_by_email=link_info['created_by'],
            shared_via_link=share_token,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'file': file_info,
            'versions': versions
        })
        
    except Exception as e:
        print(f"❌ Error validating share link: {e}")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/download/shared/<path:filename>', methods=['GET'])
def download_shared_file(filename):
    """Download shared file - uses database"""
    from urllib.parse import unquote
    from io import BytesIO
    filename = unquote(filename)
    share_token = request.args.get('share')
    tenant_id = request.args.get('tenant', get_current_tenant())

    if not share_token:
        return "Missing share token", 400

    # Get share link from database
    link_info = get_share_link_by_token(tenant_id, share_token)
    if not link_info:
        return "Invalid or expired share link", 404

    if link_info.get('file_name') != filename:
        return "Share link does not match file", 403

    document_id = link_info['document_id']
    
    # Check key exchange verification if required
    if link_info.get('require_key_exchange'):
        exchange_id = link_info.get('exchange_id')
        if not exchange_id:
            return "Identity not verified", 403
        exchange = get_key_exchange(tenant_id, exchange_id)
        if not exchange or exchange.get('status') != 'verified':
            return "Identity not verified", 403

    # Get file from database
    file_record = get_file_from_db(tenant_id, document_id=document_id)
    if not file_record:
        return "File not found", 404
    
    file_data = file_record['file_data']
    actual_filename = file_record['file_name']
    
    # Detect file extension if needed
    actual_ext = detect_file_extension_from_data(file_data)
    download_name = os.path.splitext(actual_filename)[0] + actual_ext
    
    # Update access count
    update_share_link_access(tenant_id, share_token)
    
    # Log download activity
    log_sharing_activity(
        tenant_id=tenant_id,
        document_id=document_id,
        filename=actual_filename,
        action='downloaded',
        shared_by_email=link_info['created_by'],
        shared_via_link=share_token,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    return send_file(
        BytesIO(file_data),
        as_attachment=True,
        download_name=download_name,
        mimetype='application/octet-stream'
    )


@csrf.exempt
@app.route('/send_share_email', methods=['POST'])
def send_share_email():
    """Send share link via email"""
    try:
        data = request.json
        email = data.get('email')
        share_link = data.get('share_link')
        filename = data.get('filename')
        
        if not email or not share_link or not filename:
            return jsonify({'error': 'Email, share link, and filename required'}), 400
        
        # In a real application, implement actual email sending
        # For now, just return success
        # You would use smtplib or a service like SendGrid here
        
        return jsonify({
            'success': True,
            'message': f'Share link sent to {email}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# 🔥 NEW: Centralized DLP Enforcement Helper
# ==========================================
def check_dlp_enforcement(file_path, tenant_id, original_filename):
    """
    Scans a file and determines the enforcement action based on TenantSecurity policy.
    Returns: (action, message, risk_level, risk_result)
    """
    action = "MONITOR"
    message = "File is safe."
    risk_level = "Low"
    risk_result = {}

    try:
        # 1. Extract Text & Scan Content
        with open(file_path, "rb") as f:
            from werkzeug.datastructures import FileStorage
            file_obj = FileStorage(stream=f, filename=original_filename)

            if not fileProcessor.passedProcessing(file_obj):
                return "MONITOR", "File type skipped", "Low", {}

            extracted_text = fileProcessor.readTextFromFile(file_obj)

        if extracted_text:
            matches = dlpScanner.scan_text(extracted_text)
            risk_result = dlpScanner.calculateRisk(matches)
            if risk_result:
                risk_level = risk_result.get("level", "Low")

    except Exception as e:
        print(f"🔥 DLP Backend Crash Prevented: {e}")
        return "MONITOR", "Scan Error (Passed to Monitoring)", "Low", {}

    # 3. Check Database Policy
    security_policy = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()
    if not security_policy:
        security_policy = TenantSecurity(dlp_monitor_only=True)

    # 4. Determine Action (Removed JUSTIFY)
    if risk_level in ["Critical", "High", "Medium"]:
        if security_policy.dlp_block_action:
            action = "BLOCK"
            message = f"⛔ Upload Blocked: File contains {risk_level} risk data."
        elif security_policy.dlp_notify_user:
            action = "WARN"
            message = "🛡️ Caution: Sensitive data involved."

    return action, message, risk_level, risk_result
def _pending_path(temp_id):
    """Find pending file by temp_id, accounting for tenant prefix"""
    for fname in os.listdir(app.config['PENDING_FOLDER']):
        # Pattern: {tenant_id}_{temp_id}__{filename}
        if f"_{temp_id}__" in fname:
            return os.path.join(app.config['PENDING_FOLDER'], fname)
    return None


@app.route('/file/<path:filename>', methods=['GET'])
def file_detail(filename):
    from urllib.parse import unquote
    tenant_id = get_current_tenant()
    filename = unquote(filename)
    
    # Get file from database
    file_record = get_file_from_db(tenant_id, filename=filename)
    
    if not file_record:
        flash("File not found", "danger")
        return redirect(url_for('myfiles'))
    
    file_info = {
        "name": file_record['file_name'],
        "size": file_record['file_size'],
        "url": url_for("download_file", filename=file_record['file_name'], tenant=tenant_id),
        "hash": file_record['file_hash'],
        "modified": file_record['updated_at'].strftime('%d %B %Y') if file_record.get('updated_at') else 'N/A',
        "owner": file_record['owner_email'],
        "uploaded_by": file_record['owner_email'],
        "sensitivity": file_record.get('sensitivity', 'Public'),
        "classification": file_record.get('classification', 'N/A'),
        "risk_level": file_record.get('risk_level', 'N/A'),
        "notes": file_record.get('notes', ''),
        "document_id": file_record['document_id']
    }
    
    # Get version history from database
    versions_raw = get_file_versions_from_db(tenant_id, file_record['document_id'])
    
    # Format versions for template
    versions = []
    for v in versions_raw:
        versions.append({
            "version": v['version_number'],
            "name": v['file_name'],
            "uploaded_by": v['uploaded_by'],
            "date": v['uploaded_at'].strftime('%d %B %Y') if v.get('uploaded_at') else 'N/A',
            "size": v['file_size'],
            "hash": v['file_hash'],
            "is_current": v.get('is_current', False),
            "document_id": file_record['document_id'],
            "version_number": v['version_number']
        })
    
    return render_template("users/file_detail.html", file=file_info, versions=versions)


@app.route('/upload/temp', methods=['POST'])
@csrf.exempt
def upload_temp():
    if 'file' not in request.files:
        log_tenant_event(
            action_type='FILE_UPLOAD_FAILED',
            description="File upload failed: No file part in request",
            category='FILE_MANAGEMENT',
            tenant_id=get_current_tenant(),
            success=False
        )
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['file']
    if not file or file.filename == "":
        log_tenant_event(
            action_type='FILE_UPLOAD_FAILED',
            description="File upload failed: No file selected",
            category='FILE_MANAGEMENT',
            tenant_id=get_current_tenant(),
            success=False
        )
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        log_tenant_event(
            action_type='FILE_UPLOAD_FAILED',
            description=f"File upload failed: Invalid file type - {file.filename}",
            category='FILE_MANAGEMENT',
            success=False,
            target_resource='FILE',
            tenant_id=get_current_tenant(),
            resource_id=file.filename
        )
        return jsonify({"error": "Invalid file type"}), 400

    tenant_id = get_current_tenant()
    from uuid import uuid4
    temp_id = str(uuid4())
    safe_name = sanitize_filename(file.filename)
    pending_name = f"{tenant_id}_{temp_id}__{safe_name}"
    pending_path = os.path.join(app.config['PENDING_FOLDER'], pending_name)

    file.save(pending_path)
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)

    log_tenant_event(
        action_type='FILE_UPLOAD_TEMP',
        description=f"File uploaded to temporary storage: {safe_name}",
        category='FILE_MANAGEMENT',
        target_resource='FILE',
        tenant_id=tenant_id,
        resource_id=safe_name,
        additional_data={'temp_id': temp_id, 'file_size': size, 'file_hash': file_hash[:16]}
    )

    return jsonify({
        "confirm_url": url_for('confirm_upload', temp_id=temp_id, tenant=tenant_id),
        "name": safe_name,
        "size": size,
        "hash": file_hash
    }), 200


@app.route('/upload/confirm/<temp_id>', methods=['GET', 'POST'])
@csrf.exempt
def confirm_upload(temp_id):
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    user_id = session.get('user_id', 0)

    pending_path = _pending_path(temp_id)
    if not pending_path or not os.path.exists(pending_path):
        flash("File timeout or not found.", "danger")
        return redirect(url_for('myfiles'))

    pending_file = os.path.basename(pending_path)
    original_name = pending_file.split("__", 1)[1] if "__" in pending_file else pending_file
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)
    modified = datetime.fromtimestamp(os.path.getmtime(pending_path)).strftime('%d %B %Y')

    if request.method == 'POST':
        # 1. ENFORCE DLP BASELINE CHECK
        action, message, risk_level, _ = check_dlp_enforcement(pending_path, tenant_id, original_name)

        # 🛑 2. IF BLOCKED
        if action == "BLOCK":
            log_tenant_event('DLP_UPLOAD_BLOCKED', f"Blocked {original_name} ({risk_level})", 'SECURITY',
                             tenant_id=tenant_id, user_id=user_id, success=False)
            try:
                os.remove(pending_path)
            except:
                pass

            return f"""
            <html><head><title>Blocked</title><style>
                body {{ font-family: sans-serif; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                .box {{ background: white; padding: 40px; border-radius: 12px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.5); max-width: 450px; width: 90%; }}
                h2 {{ color: #dc3545; margin-top: 10px; font-weight: 800; }}
                p {{ color: #333; font-size: 16px; font-weight: 500; margin-bottom: 25px; }}
                .sub {{ font-size: 13px; color: #6c757d; margin-bottom: 25px; }}
                .btn {{ background: #dc3545; color: white; border: none; padding: 14px 20px; border-radius: 6px; cursor: pointer; font-size: 16px; width: 100%; font-weight: bold; text-decoration: none; display: block; box-sizing: border-box; }}
                .btn:hover {{ background: #c82333; }}
            </style></head><body>
                <div class="box">
                    <div style="font-size: 60px; line-height: 1; margin-bottom: 15px;">⛔</div>
                    <h2>Upload Blocked</h2>
                    <p>{message}</p>
                    <div class="sub">This incident has been logged. Please contact your administrator if you believe this is an error.</div>
                    <a href="/myfiles" class="btn">OK, Return to My Files</a>
                </div>
            </body></html>
            """, 403

        # ⚠️ 3. IF WARN
        if action == "WARN" and request.form.get('confirmed_warning') != 'true':
            name_val = request.form.get('name', '').replace('"', '&quot;')
            sens_val = request.form.get('sensitivity', '').replace('"', '&quot;')
            owner_val = request.form.get('owner', '').replace('"', '&quot;')
            notes_val = request.form.get('notes', '').replace('"', '&quot;')
            risk_type_val = request.form.get('risk_type', '').replace('"', '&quot;')

            return f"""
            <html><head><title>Warning</title><style>
                body {{ font-family: sans-serif; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                .box {{ background: white; padding: 40px; border-radius: 12px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.5); max-width: 450px; width: 90%; }}
                h2 {{ color: #f57c00; margin-top: 10px; font-weight: 800; }}
                p {{ color: #333; font-size: 16px; font-weight: 500; margin-bottom: 15px; }}
                .sub {{ font-size: 14px; color: #6c757d; margin-bottom: 25px; }}
                .btn-container {{ display: flex; gap: 10px; }}
                .btn {{ flex: 1; border: none; padding: 14px 20px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; text-decoration: none; display: block; box-sizing: border-box; }}
                .btn-yes {{ background: #f57c00; color: white; }}
                .btn-yes:hover {{ background: #e65100; }}
                .btn-no {{ background: #6c757d; color: white; }}
                .btn-no:hover {{ background: #5a6268; }}
            </style></head><body>
                <div class="box">
                    <div style="font-size: 60px; line-height: 1; margin-bottom: 15px;">⚠️</div>
                    <h2>Security Warning</h2>
                    <p>{message}</p>
                    <div class="sub">Are you sure you want to proceed with uploading this sensitive file?</div>

                    <form method="POST" action="/upload/confirm/{temp_id}?tenant={tenant_id}" style="margin:0;">
                        <input type="hidden" name="name" value="{name_val}">
                        <input type="hidden" name="sensitivity" value="{sens_val}">
                        <input type="hidden" name="owner" value="{owner_val}">
                        <input type="hidden" name="notes" value="{notes_val}">
                        <input type="hidden" name="risk_type" value="{risk_type_val}">
                        <input type="hidden" name="confirmed_warning" value="true">

                        <div class="btn-container">
                            <a href="/myfiles" class="btn btn-no">No, Cancel</a>
                            <button type="submit" class="btn btn-yes">Yes, Upload</button>
                        </div>
                    </form>
                </div>
            </body></html>
            """, 200

        # Proceed to Save
        notes = request.form.get('notes', '').strip()

        try:
            with open(pending_path, 'rb') as f:
                file_data = f.read()

            import mimetypes
            mime_type, _ = mimetypes.guess_type(original_name)

            from werkzeug.utils import secure_filename
            result = store_file_in_db(
                tenant_id=tenant_id, file_data=file_data,
                filename=secure_filename(request.form.get('name') or original_name),
                owner_user_id=user_id, owner_email=user_email,
                file_hash=file_hash, mime_type=mime_type or 'application/octet-stream',
                sensitivity=request.form.get('sensitivity', 'Public'),
                classification=request.form.get('risk_type'), notes=notes
            )

            try:
                os.remove(pending_path)
            except:
                pass

            if result.get('success'):
                flash(f"✅ File uploaded successfully!", "success")
            else:
                flash(f"❌ Upload failed: {result.get('error')}", "danger")

            return redirect(url_for('myfiles'))

        except FileNotFoundError:
            flash("File processed or not found.", "danger")
            return redirect(url_for('myfiles'))

    # GET Request
    return render_template("users/confirm_upload.html", file={
        "temp_id": temp_id, "name": original_name, "size": size,
        "hash": file_hash, "modified": modified, "owner": user_email
    })

@app.route('/scan/dlp/<temp_id>', methods=['GET'])
@csrf.exempt
def scan_dlp_temp_file(temp_id):
    """Scan a temporary file with DLP scanner and apply Tenant Security Policies."""
    tenant_id = get_current_tenant()

    pending_path = _pending_path(temp_id)
    if not pending_path or not os.path.exists(pending_path):
        return jsonify({"error": "File not found"}), 404

    pending_file = os.path.basename(pending_path)
    original_name = pending_file.split("__", 1)[1] if "__" in pending_file else pending_file

    # 🔥 USE HELPER
    action, message, risk_level, risk_result = check_dlp_enforcement(pending_path, tenant_id, original_name)

    # Trigger Incident Logging immediately if policy requires it
    security_policy = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()
    if security_policy and security_policy.dlp_trigger_incident and risk_level in ["Critical", "High", "Medium"]:
        log_tenant_event(
            action_type='DLP_INCIDENT_TRIGGERED',
            description=f"🚨 DLP VIOLATION: {original_name} contains {risk_level} risk data.",
            category='SECURITY_INCIDENT',
            target_resource='FILE',
            resource_id=original_name,
            tenant_id=tenant_id,
            additional_data={'risk_score': risk_result.get("score", 0)}
        )

    # Return to Frontend
    risk_to_sensitivity = {
        "Critical": "Restricted", "High": "Confidential",
        "Medium": "Internal", "Low": "Public"
    }
    sensitivity = risk_to_sensitivity.get(risk_level, "Public")

    return jsonify({
        "success": True,
        "riskLevel": risk_level,
        "riskScore": risk_result.get("score", 0),
        "sensitivity": sensitivity,
        "totalMatches": risk_result.get("total_matches", 0),
        "severityBreakdown": risk_result.get("severity_breakdown", {}),

        # ACTION & MESSAGE for Frontend Logic
        "action": action,
        "message": message
    }), 200

@app.route('/upload/version/temp/<path:filename>', methods=['POST'])
@csrf.exempt
def upload_version_temp(filename):
    """Upload a new version to temp folder for confirmation."""
    from urllib.parse import unquote
    filename = unquote(filename)
    
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['file']
    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    # Get tenant ID and verify original file exists in database
    tenant_id = get_current_tenant()
    
    # Check if file exists in database
    existing_file = get_file_from_db(tenant_id, filename=filename)
    if not existing_file:
        return jsonify({"error": "Original file not found in database"}), 404
    
    # Save to temp folder
    from uuid import uuid4
    temp_id = str(uuid4())
    safe_name = sanitize_filename(file.filename)
    pending_name = f"{tenant_id}_{temp_id}__{safe_name}"
    pending_path = os.path.join(app.config['PENDING_FOLDER'], pending_name)

    file.save(pending_path)
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)

    return jsonify({
        "confirm_url": url_for('confirm_version_upload', temp_id=temp_id, original_filename=filename, tenant=tenant_id),
        "name": safe_name,
        "size": size,
        "hash": file_hash
    }), 200


@app.route('/upload/version/confirm/<temp_id>/<path:original_filename>', methods=['GET', 'POST'])
@csrf.exempt
def confirm_version_upload(temp_id, original_filename):
    """Confirm and finalize version upload to database."""
    from urllib.parse import unquote
    original_filename = unquote(original_filename)

    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')

    pending_path = _pending_path(temp_id)
    if not pending_path or not os.path.exists(pending_path):
        return "Pending file not found", 404

    pending_file = os.path.basename(pending_path)
    new_filename = pending_file.split("__", 1)[1]
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)
    modified = datetime.fromtimestamp(os.path.getmtime(pending_path)).strftime('%d %B %Y')

    if request.method == 'POST':
        # Get original file from database
        existing_file = get_file_from_db(tenant_id, filename=original_filename)
        if not existing_file:
            flash("Original file not found", "danger")
            return redirect(url_for('myfiles'))

        document_id = existing_file['document_id']

        # Read new version data
        with open(pending_path, 'rb') as f:
            file_data = f.read()

        # Determine MIME type
        import mimetypes
        mime_type, _ = mimetypes.guess_type(new_filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        # [cite_start]Add new version to database [cite: 325]
        result = add_file_version(
            tenant_id=tenant_id,
            document_id=document_id,
            file_data=file_data,
            filename=new_filename,
            uploaded_by=user_email,
            file_hash=file_hash,
            mime_type=mime_type
        )

        # 🔥 NEW: Save Justification if provided
        justification = request.form.get('justification', '').strip()
        if justification:
            try:
                # Append justification to the MAIN file's notes
                schema_name = f"tenant_{tenant_id}"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                note_entry = f"\n[v{result.get('version_number')} Justification {timestamp}]: {justification}"

                db.session.execute(text(f'''
                    UPDATE "{schema_name}".files 
                    SET notes = COALESCE(notes, '') || :note 
                    WHERE document_id = :did
                '''), {'note': note_entry, 'did': document_id})
                db.session.commit()
            except Exception as e:
                print(f"Error saving justification: {e}")

        # Clean up pending file
        try:
            os.remove(pending_path)
        except:
            pass

        if result.get('success'):
            flash(f"✅ Version {result['version_number']} uploaded successfully!", "success")
            return redirect(url_for('file_detail', filename=original_filename))
        else:
            flash(f"❌ Failed to upload version: {result.get('error')}", "danger")
            return redirect(url_for('file_detail', filename=original_filename))

    return render_template(
        "users/confirm_upload.html",
        file={
            "temp_id": temp_id,
            "name": new_filename,
            "size": size,
            "hash": file_hash,
            "modified": modified,
            "owner": user_email,
            "uploaded_by": user_email
        },
        is_version=True,
        original_filename=original_filename
    )

@app.route('/download/version/<document_id>/<int:version_number>')
def download_version(document_id, version_number):
    """Download a specific version from the database."""
    from io import BytesIO
    tenant_id = get_current_tenant()
    
    # Get specific version from database
    schema_name = f"tenant_{tenant_id}"
    try:
        from database import MasterSessionLocal, text
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        result = session.execute(text(f'''
            SELECT file_name, file_data, file_size, file_hash, mime_type
            FROM "{schema_name}".file_versions
            WHERE document_id = :document_id AND version_number = :version_number
        '''), {'document_id': document_id, 'version_number': version_number}).fetchone()
        
        session.close()
        
        if not result:
            flash("Version not found", "danger")
            return redirect(url_for('myfiles'))
        
        file_name, file_data, file_size, file_hash, mime_type = result
        
        # Create BytesIO from blob
        file_stream = BytesIO(file_data)
        
        # Determine download name
        import mimetypes
        ext = mimetypes.guess_extension(mime_type) or ''
        if not ext:
            _, ext = os.path.splitext(file_name)
        
        download_name = f"{os.path.splitext(file_name)[0]}_v{version_number}{ext}"
        
        return send_file(
            file_stream,
            as_attachment=True,
            download_name=download_name,
            mimetype=mime_type or 'application/octet-stream'
        )
        
    except Exception as e:
        print(f"❌ Error downloading version: {e}")
        flash("Error downloading version", "danger")
        return redirect(url_for('myfiles'))


@app.route('/rename', methods=['POST'])
@csrf.exempt
def rename_file():
    """Rename a file in the database"""
    tenant_id = get_current_tenant()
    data = request.get_json()
    old_name = data.get('old_name')
    new_name = data.get('new_name')

    if not old_name or not new_name:
        log_tenant_event(
            action_type='FILE_RENAME_FAILED',
            description="File rename failed: Missing filename",
            category='FILE_MANAGEMENT',
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": "Missing filename"}), 400

    # Check if old file exists in database
    old_file = get_file_from_db(tenant_id, filename=old_name)
    if not old_file:
        log_tenant_event(
            action_type='FILE_RENAME_FAILED',
            description=f"File rename failed: File not found - {old_name}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=old_name,
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": "File not found"}), 404

    # Check if new name already exists
    existing_new = get_file_from_db(tenant_id, filename=new_name)
    if existing_new:
        log_tenant_event(
            action_type='FILE_RENAME_FAILED',
            description=f"File rename failed: File with new name already exists - {old_name} to {new_name}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=old_name,
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": "File with that name already exists"}), 409

    try:
        # Update filename in database
        from database import MasterSessionLocal, text
        schema_name = f"tenant_{tenant_id}"
        session = MasterSessionLocal()
        session.execute(text(f'SET search_path TO "{schema_name}", public'))
        
        # Update main file record
        session.execute(text(f'''
            UPDATE "{schema_name}".files
            SET file_name = :new_name, updated_at = NOW()
            WHERE document_id = :document_id
        '''), {'new_name': sanitize_filename(new_name), 'document_id': old_file['document_id']})
        
        session.commit()
        session.close()
        
        log_tenant_event(
            action_type='FILE_RENAMED',
            description=f"File renamed: {old_name} to {new_name}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=new_name,
            additional_data={'old_name': old_name},
            tenant_id=tenant_id
        )
        return jsonify({"message": "File renamed successfully"}), 200
    except Exception as e:
        print(f"❌ Error renaming file: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
        log_tenant_event(
            action_type='FILE_RENAME_ERROR',
            description=f"File rename error: {old_name} to {new_name} - {str(e)}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=old_name,
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": str(e)}), 500


@app.route('/share', methods=['POST'])
@csrf.exempt
def share_file():
    tenant_id = get_current_tenant()
    data = request.get_json()
    filename = data.get('filename')
    email = data.get('email')

    if not filename or not email:
        return jsonify({"error": "Missing filename or email"}), 400

    tenant_folder = get_tenant_upload_folder(tenant_id)
    file_path = os.path.join(tenant_folder, sanitize_filename(filename))
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        # TODO: Implement email sharing logic
        # For now, just return success message
        return jsonify({"message": f"File {filename} shared with {email}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete', methods=['POST'])
@csrf.exempt
def delete_file():
    """Soft delete a file in the database (move to bin)"""
    tenant_id = get_current_tenant()
    data = request.get_json()
    filename = data.get('filename')

    if not filename:
        log_tenant_event(
            action_type='FILE_DELETE_FAILED',
            description="File delete failed: Missing filename",
            category='FILE_MANAGEMENT',
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": "Missing filename"}), 400

    # Get file from database
    file_record = get_file_from_db(tenant_id, filename=filename)
    if not file_record:
        log_tenant_event(
            action_type='FILE_DELETE_FAILED',
            description=f"File delete failed: File not found - {filename}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=filename,
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": "File not found"}), 404

    try:
        document_id = file_record['document_id']
        
        # Soft delete file in database (set is_deleted = TRUE)
        result = delete_file_from_db(tenant_id, document_id, soft_delete=True)
        
        if not result.get('success'):
            return jsonify({"error": "Failed to delete file"}), 500
        
        # TODO: Remove from shared_with_me for other users (update sharing table)
        # TODO: Deactivate share links pointing to this file (update file_sharing_links table)

        log_tenant_event(
            action_type='FILE_MOVED_TO_BIN',
            description=f"File moved to bin: {filename}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=filename,
            additional_data={'document_id': document_id},
            tenant_id=tenant_id
        )
        
        return jsonify({"message": "File moved to bin", "document_id": document_id}), 200
    except Exception as e:
        print(f"❌ Error deleting file: {e}")
        log_tenant_event(
            action_type='FILE_DELETE_ERROR',
            description=f"File delete error: {filename} - {str(e)}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=filename,
            success=False,
            tenant_id=tenant_id
        )
        return jsonify({"error": str(e)}), 500


@app.route('/bin', methods=['GET'])
def view_bin():
    """View all soft-deleted files in bin for current tenant"""
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    
    # Get all deleted files from database
    deleted_files = get_all_files_for_tenant(tenant_id, owner_email=user_email, include_deleted=True)
    
    tenant_bin_files = []
    for file_record in deleted_files:
        if file_record.get('is_deleted'):
            # Calculate days until auto-deletion (30 days from deleted_at)
            deleted_at = file_record.get('deleted_at')
            if deleted_at:
                from datetime import timezone
                if deleted_at.tzinfo is None:
                    deleted_at = deleted_at.replace(tzinfo=timezone.utc)
                days_remaining = 30 - (datetime.now(timezone.utc) - deleted_at).days
            else:
                days_remaining = 30
            
            tenant_bin_files.append({
                'document_id': file_record['document_id'],
                'original_filename': file_record['file_name'],
                'deleted_at': deleted_at.isoformat() if deleted_at else 'N/A',
                'days_remaining': max(0, days_remaining),
                'file_size': file_record['file_size'],
                'sensitivity': file_record.get('sensitivity', 'Public')
            })
    
    # Sort by deleted_at (newest first)
    tenant_bin_files.sort(key=lambda x: x['deleted_at'], reverse=True)
    
    return render_template("users/bin.html", files=tenant_bin_files, tenant_id=tenant_id, account_name=user_email)


@app.route('/bin/restore/<document_id>', methods=['POST'])
@csrf.exempt
def restore_bin_file(document_id):
    """Restore a soft-deleted file from bin"""
    tenant_id = get_current_tenant()
    
    # Verify file exists and belongs to current tenant
    file_record = get_file_from_db(tenant_id, document_id=document_id, include_deleted=True)
    
    if not file_record:
        return jsonify({"error": "File not found in bin"}), 404
    
    if not file_record.get('is_deleted'):
        return jsonify({"error": "File is not in bin"}), 400
    
    try:
        result = restore_file_from_db(tenant_id, document_id)
        if result.get('success'):
            return jsonify({"message": f"File '{file_record['file_name']}' restored successfully"}), 200
        else:
            return jsonify({"error": result.get('error', 'Failed to restore file')}), 500
    except Exception as e:
        print(f"❌ Error restoring file: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/bin/permanent-delete/<document_id>', methods=['POST'])
@csrf.exempt
def permanent_delete_bin_file(document_id):
    """Permanently delete a file from bin (hard delete from database)"""
    tenant_id = get_current_tenant()
    
    # Verify file exists and belongs to current tenant
    file_record = get_file_from_db(tenant_id, document_id=document_id, include_deleted=True)
    
    if not file_record:
        return jsonify({"error": "File not found in bin"}), 404
    
    if not file_record.get('is_deleted'):
        return jsonify({"error": "File is not in bin"}), 400
    
    try:
        result = delete_file_from_db(tenant_id, document_id, soft_delete=False)
        if result.get('success'):
            return jsonify({"message": f"File '{file_record['file_name']}' permanently deleted"}), 200
        else:
            return jsonify({"error": result.get('error', 'Failed to delete file')}), 500
    except Exception as e:
        print(f"❌ Error permanently deleting file: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/bin/cleanup', methods=['POST'])
@csrf.exempt
def cleanup_expired_bin_files():
    """Manually trigger cleanup of files older than 30 days (can also be scheduled)"""
    # Only super admins should be able to call this
    deleted_count = cleanup_bin()
    return jsonify({"message": f"Cleaned up {deleted_count} expired files from bin"}), 200


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['file']
    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    filename = sanitize_filename(file.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Avoid overwriting existing files by appending a counter
    if os.path.exists(save_path):
        name, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(save_path):
            filename = f"{name}_{counter}{ext}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            counter += 1

    file.save(save_path)
    size = os.path.getsize(save_path)
    file_hash = compute_sha256(save_path)
    file_url = url_for('download_file', filename=filename)

    return jsonify({"name": filename, "size": size, "url": file_url, "hash": file_hash}), 200


@app.route('/uploads/<path:filename>', methods=['GET'])
def download_file(filename):
    """Download file from database blob storage"""
    from urllib.parse import unquote
    from io import BytesIO
    tenant_id = get_current_tenant()
    user_email = session.get('email', 'Unknown')
    filename = unquote(filename)
    
    # Get file from database
    file_record = get_file_from_db(tenant_id, filename=filename)
    
    if not file_record:

        log_tenant_event(
            action_type='FILE_DOWNLOAD_FAILED',
            description=f"File download failed: File not found - {filename}",
            category='FILE_MANAGEMENT',
            target_resource='FILE',
            resource_id=filename,
            success=False,
            tenant_id=tenant_id,
            user_email=user_email
        )

        flash("File not found", "danger")
        return redirect(url_for('myfiles'))
    
    log_tenant_event(
        action_type='FILE_DOWNLOADED',
        description=f"File downloaded: {filename}",
        category='FILE_MANAGEMENT',
        target_resource='FILE',
        resource_id=filename,
        additional_data={'file_size': file_record['file_size']},
        tenant_id=tenant_id,
        user_email=user_email
    )
    
    
    # Create BytesIO object from blob data
    file_data = BytesIO(file_record['file_data'])
    
    # Determine download name with proper extension
    mime_type = file_record.get('mime_type', 'application/octet-stream')
    import mimetypes
    ext = mimetypes.guess_extension(mime_type) or ''
    if not ext:
        _, ext = os.path.splitext(filename)
    
    download_name = os.path.splitext(filename)[0] + ext
    
    return send_file(
        file_data,
        as_attachment=True,
        download_name=download_name,
        mimetype=mime_type
    )

#TODO JiaJun stuff -------------------------------------------------------------------------

scheduler = BackgroundScheduler()
scheduler.start()


@app.route('/tenant/<int:tenant_id>/cleanup-retention')
def run_retention_cleanup(tenant_id):
    if session.get('tenant_id') != tenant_id:
        return redirect(url_for('login'))

    # ✅ Now returns dict with logs/docs
    deleted = retention_cleanup(tenant_id)
    flash(f"✅ Cleanup complete: {deleted['logs']} logs, {deleted['docs']} docs deleted", "success")
    return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))


def daily_retention_cleanup():
    """Run retention cleanup for all tenants daily"""
    tenants = Tenant.query.all()
    for tenant in tenants:
        try:
            retention_cleanup(tenant.id)
        except Exception as e:
            print(f"❌ Cleanup failed for tenant_{tenant.id}: {e}")





def scheduled_tenant_backups():
    """Run scheduled backups for all tenants"""
    configs = TenantBackupConfig.query.filter_by(enable_scheduled=True).all()
    for config in configs:
        if should_run_backup(config):
            backup_file = backup_tenant(config.tenant_id)
            if backup_file:
                config.last_backup = datetime.now()
                config.next_backup = calculate_next_backup(config.frequency, config.backup_time)
                db.session.commit()

# ✅ NEW - Staggered schedule
scheduler.add_job(
    daily_retention_cleanup,
    'cron',
    hour=2, minute=0,  # 2:00 AM - Cleanup first
    id='retention_cleanup',
    replace_existing=True
)

scheduler.add_job(
    scheduled_tenant_backups,
    'cron',
    hour=2, minute=15,  # 2:15 AM - Backups after cleanup
    id='backup_scheduler',
    replace_existing=True
)
# Shutdown scheduler when app exits
atexit.register(lambda: scheduler.shutdown())


def get_tenant_session():
    """Get session with search_path set to tenant schema"""
    if "tenant_session" not in g:
        if not g.schema_name:
            raise RuntimeError("No tenant context - login required")

        session = MasterSessionLocal()
        session.execute(text(f"SET search_path TO {g.schema_name}, public"))
        g.tenant_session = session
    return g.tenant_session

@app.before_request
def set_tenant_context():
    """Safe tenant context loader"""
    # Skip ALL public routes (home, login, signup, etc.)
    public_routes = [
        'index', 'login', 'verify_2fa', 'company_signup', 'signup',
        'logout', 'verify_signup_email', 'reset_password', 'forget_password'
    ]

    if not request.endpoint or request.endpoint.split('.')[0] in public_routes:
        return  # Skip - no crash!

    # Only run for authenticated tenant routes
    tenant_id = session.get('tenant_id')
    if tenant_id:
        g.tenant_id = tenant_id
        g.schema_name = f"tenant_{tenant_id}"

# app.py - Add this route (REPLACE database.py version)
@app.route('/company-signup', methods=['GET', 'POST'])
def company_signup():
    form = CompanySignupForm()

    if form.validate_on_submit():
        try:
            log_tenant_event(
                action_type='COMPANY_SIGNUP_ATTEMPT',
                description=f"Company signup attempt: {form.company_name.data}",
                category='TENANT_MANAGEMENT',
                tenant_id=None
            )

            # 1. Create tenant record
            tenant = Tenant(company_name=form.company_name.data)
            db.session.add(tenant)
            db.session.flush()
            tenant_id = tenant.id
            schema_name = f"tenant_{tenant_id}"

            print(f"🔄 Creating {schema_name}...")

            # 2. Create schema
            db.session.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))

            # 3. Create tables - YOUR EXISTING CODE (unchanged)
            db.session.execute(text(f'''
                CREATE TABLE IF NOT EXISTS "{schema_name}".users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'user',
                    usb_mfa_enabled BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            '''))

            db.session.execute(text(f'''
                CREATE TABLE IF NOT EXISTS "{schema_name}".documents (
                    id SERIAL PRIMARY KEY,
                    owner_user_id INT REFERENCES "{schema_name}".users(id),
                    file_path TEXT NOT NULL,
                    classification VARCHAR(50) NOT NULL,
                    version INT DEFAULT 1,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            '''))

            db.session.execute(text(f'''
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

            # NEW: File management tables with blob storage
            db.session.execute(text(f'''
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
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_document_id ON "{schema_name}".files(document_id)'))
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_owner ON "{schema_name}".files(owner_user_id)'))
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_files_current ON "{schema_name}".files(is_current_version)'))

            db.session.execute(text(f'''
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
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_versions_document ON "{schema_name}".file_versions(document_id)'))

            db.session.execute(text(f'''
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
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_share_links_token ON "{schema_name}".file_sharing_links(share_token)'))
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_share_links_document ON "{schema_name}".file_sharing_links(document_id)'))

            db.session.execute(text(f'''
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
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_sharing_document ON "{schema_name}".sharing(document_id)'))
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_sharing_recipient ON "{schema_name}".sharing(shared_with_email)'))

            db.session.execute(text(f'''
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
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_activity_document ON "{schema_name}".sharing_activity(document_id)'))
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_activity_action ON "{schema_name}".sharing_activity(action)'))

            db.session.execute(text(f'''
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
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_exchange_id ON "{schema_name}".key_exchanges(exchange_id)'))
            db.session.execute(text(f'CREATE INDEX IF NOT EXISTS idx_exchange_status ON "{schema_name}".key_exchanges(status)'))

            # 4. Create admin user - YOUR EXISTING CODE (unchanged)
            import bcrypt
            password_hash = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt()).decode()
            email = form.email.data

            db.session.execute(text(f'''
                INSERT INTO "{schema_name}".users (email, password_hash, role) 
                VALUES ('{email}', '{password_hash}', 'admin')
            '''))

            db.session.commit()
            print(f"✅ tenant_{tenant_id} FULLY created with ALL tables!")

            log_tenant_event(
                action_type='COMPANY_SIGNUP_SUCCESS',
                description=f"Company '{form.company_name.data}' created successfully (tenant_{tenant_id})",
                category='TENANT_MANAGEMENT',
                target_resource='TENANT',
                tenant_id=tenant_id,
                resource_id=str(tenant_id),
                additional_data={
                    'company_name': form.company_name.data,
                    'admin_email': form.email.data,
                    'region': form.company_region.data
                }
            )

            # 🔥 NEW: ADD SECURITY BASELINE (INSERT THESE 12 LINES)
            security = TenantSecurity(
                tenant_id=tenant_id,
                mfa_enabled=True,
                dlp_enabled=True,
                dlp_monitor_only=True,  # Default on
                dlp_notify_user=False,
                dlp_require_approval=False,
                dlp_block_action=False,
                dlp_trigger_incident=False,
                data_retention_days=365,
                rls_enabled=True
            )
            db.session.add(security)
            db.session.commit()

            backup_config = TenantBackupConfig(
                tenant_id=tenant_id,
                frequency='daily',
                backup_time='02:00',
                enable_scheduled=False,  # Admin enables later
                scope_full=True,
                retention_days=30
            )
            db.session.add(backup_config)
            db.session.commit()
            print(f"✅ Backup config created for tenant_{tenant_id}")

            # Auto-apply RLS policies
            apply_rls_policies(tenant_id, security)
            print(f"✅ Security baseline + RLS applied to tenant_{tenant_id}")

            flash(f"✅ '{form.company_name.data}' created with security baselines!", "success")
            return redirect(url_for('login'))

        except Exception as e:
            log_tenant_event(
                action_type='COMPANY_SIGNUP_ERROR',
                description=f"Company signup error for '{form.company_name.data}': {str(e)}",
                category='TENANT_MANAGEMENT',
                success=False,
                tenant_id=None
            )
            db.session.rollback()
            print(f"❌ ERROR: {e}")
            flash(f"❌ Failed: {str(e)}", "danger")

    return render_template('company_signup.html', form=form)


@app.route('/tenant/<int:tenant_id>/dashboard')
def tenant_dashboard(tenant_id):
    if str(session.get('tenant_id')) != str(tenant_id):
        return redirect(url_for('login'))

    tenant = Tenant.query.get_or_404(tenant_id)
    stats = get_tenant_stats(tenant_id)
    security_status = get_tenant_security_status(tenant_id)

    # NEW: Instantiate the Add User Form
    adduser_form = AddTenantUserForm()

    return render_template('CompanyAdmin/dashboard.html',
                           tenant=tenant,
                           tenant_id=tenant_id,
                           stats=stats,
                           security_status=security_status,
                           company_name=tenant.company_name,
                           onboarding_date=tenant.created_at.strftime('%d/%m/%Y') if tenant.created_at else 'N/A',
                           adduser_form=adduser_form)  # <--- Pass form here


@app.route('/tenant/<int:tenant_id>/add-user', methods=['POST'])
@csrf.exempt
def add_tenant_user(tenant_id):
    if str(session.get('tenant_id')) != str(tenant_id):
        return redirect(url_for('login'))

    form = AddTenantUserForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        role = form.role.data

        try:
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            schema_name = f"tenant_{tenant_id}"

            # Check existing
            existing_user = db.session.execute(text(f'SELECT id FROM "{schema_name}".users WHERE email = :email'),
                                               {'email': email}).fetchone()
            if existing_user:
                flash(f"User {email} already exists!", "warning")
            else:
                # Insert User
                db.session.execute(text(f'''
                    INSERT INTO "{schema_name}".users (email, password_hash, role, created_at)
                    VALUES (:email, :pwd, :role, NOW())
                '''), {'email': email, 'pwd': password_hash, 'role': role})
                db.session.commit()

                log_tenant_event('USER_CREATED', f"Created user: {email}", category='USER_MANAGEMENT',
                                 tenant_id=tenant_id)
                flash(f"✅ User {email} added successfully!", "success")

        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error: {str(e)}", "danger")
    else:
        # Handle Form Errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", "danger")

    return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))

@app.teardown_appcontext
def close_sessions(exception=None):
    if hasattr(g, 'tenant_session'):
        g.tenant_session.close()


@app.route("/documents")
def list_documents():
    session = get_tenant_session()
    rows = session.execute("SELECT id, file_path, classification FROM documents").fetchall()
    return {"documents": [dict(r) for r in rows]}



# Deactivation of Tenant
@app.route('/tenant/<int:tenant_id>/deactivate', methods=['GET', 'POST'])
def tenant_deactivate(tenant_id):
    if session.get('tenant_id') != tenant_id:
        return redirect(url_for('login'))

    tenant = Tenant.query.get_or_404(tenant_id)
    stats = get_tenant_stats(tenant_id)
    form = TenantDeactivateForm()

    if form.validate_on_submit():
        retention_days = int(form.retention_days.data)
        archived = archive_tenant(tenant_id)  # ✅ This NOW WORKS

        if archived:
            flash(f"✅ Tenant '{tenant.company_name}' archived for {retention_days} days!", "success")
        else:
            flash("❌ Failed to archive tenant", "danger")

        return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))

    return render_template('CompanyAdmin/tenant_deactivate.html',
                           tenant=tenant, stats=stats, form=form, tenant_id=tenant_id)


#Setting Backup and Recovery customization settings


@app.route('/tenant/<int:tenant_id>/recovery', methods=['GET', 'POST'])
def tenant_recovery(tenant_id):
    if session.get('tenant_id') != tenant_id:
        return redirect(url_for('login'))

    tenant = Tenant.query.get_or_404(tenant_id)
    stats = get_tenant_stats(tenant_id)
    form = TenantRecoveryForm()  # ✅ Create form

    if form.validate_on_submit():
        reactivated = reactivate_tenant(tenant_id)
        if reactivated:
            flash("✅ Tenant reactivated!", "success")
        return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))

    return render_template('CompanyAdmin/Tenant_Recovery.html',
                           tenant=tenant, stats=stats, form=form, tenant_id=tenant_id)


def backup_tenant(tenant_id: int) -> str:
    """Create pg_dump backup of tenant schema"""
    schema = f"tenant_{tenant_id}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"backups/{schema}_{timestamp}.sql"

    os.makedirs('backups', exist_ok=True)

    # ✅ SUPABASE DIRECT CONNECTION (port 5432, IPv6 or IPv4 add-on)
    cmd = [
        'pg_dump',
        '-h', 'aws-1-ap-south-1.pooler.supabase.com',  # Your pooler
        '-p', '5432',
        '-U', 'postgres.ijbxuudpvxsjjdugewuj',
        '-d', 'postgres',
        f'--schema={schema}',
        '--no-owner',
        '--no-privileges',
        '--clean',
        '--if-exists',
        '-f', backup_file,
        '--verbose'  # 🔥 Debug output
    ]

    env = os.environ.copy()
    env['PGPASSWORD'] = 'SentinelSupport*2026'

    print(f"🔄 Running: {' '.join(cmd)}")  # Debug

    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)

    print(f"Return code: {result.returncode}")  # Debug
    print(f"STDOUT: {result.stdout[:300]}")  # Debug
    print(f"STDERR: {result.stderr[:300]}")  # Debug

    if result.returncode == 0 and os.path.exists(backup_file):
        print(f"✅ Backup created: {backup_file}")
        log_tenant_event('BACKUP_CREATED', f"Manual backup {backup_file}", tenant_id)
        return backup_file
    else:
        print(f"❌ Backup FAILED:")
        print(f"STDERR: {result.stderr}")
        flash(f"❌ Backup failed: {result.stderr[:100]}", "danger")
        return None


def restore_tenant_backup(tenant_id: int, backup_filename: str) -> str:
    """Restore tenant schema from backup file - FULL DEBUG"""
    schema = f"tenant_{tenant_id}"
    filepath = f"backups/{backup_filename}"

    print(f"🔍 RESTORE START: tenant_{tenant_id}")
    print(f"📁 File: {filepath}")

    # Step 1: Check file exists
    if not os.path.exists(filepath):
        print("❌ FILE NOT FOUND")
        return "❌ Backup file not found on server"

    print(f"✅ File found: {os.path.getsize(filepath)} bytes")

    # Step 2: Test psql availability
    try:
        psql_test = subprocess.run(['psql', '--version'],
                                   capture_output=True, text=True, timeout=10)
        print(f"✅ psql version: {psql_test.stdout.strip()}")
    except FileNotFoundError:
        print("❌ PSQL NOT INSTALLED")
        return "❌ psql not installed. Install PostgreSQL client tools."

    # Step 3: Build restore command
    cmd = [
        'psql',
        '-h', 'aws-1-ap-south-1.pooler.supabase.com',
        '-p', '5432',
        '-U', 'postgres.ijbxuudpvxsjjdugewuj',
        '-d', 'postgres',
        '-v', 'ON_ERROR_STOP=1',
        '-f', filepath,
        f"--single-transaction",  # Atomic restore
        f"--command=SET search_path={schema}"
    ]

    env = os.environ.copy()
    env['PGPASSWORD'] = 'SentinelSupport*2026'

    print(f"🚀 EXECUTING: {' '.join(cmd)}")

    # Step 4: Execute restore
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)

        print(f"📊 RETURN CODE: {result.returncode}")
        print(f"📤 STDOUT: {result.stdout[:500]}")
        print(f"📤 STDERR: {result.stderr[:500]}")

        if result.returncode == 0:
            print("🎉 RESTORE SUCCESS!")
            log_tenant_event('BACKUP_RESTORED', f"Restored {backup_filename}", tenant_id)
            return f"✅ SUCCESS! Restored {backup_filename} to tenant_{tenant_id}"
        else:
            print("❌ RESTORE FAILED")
            return f"❌ FAILED (code {result.returncode}): {result.stderr[:200]}"

    except subprocess.TimeoutExpired:
        print("⏰ TIMEOUT")
        return "❌ Restore timeout (5+ minutes)"
    except FileNotFoundError:
        print("❌ PSQL MISSING")
        return "❌ psql command not found - install PostgreSQL"
    except Exception as e:
        print(f"💥 EXCEPTION: {str(e)}")
        return f"❌ Error: {str(e)}"


def get_tenant_backups(tenant_id: int) -> list:
    """List backup files for tenant"""
    schema = f"tenant_{tenant_id}"
    backups = []
    backups_dir = 'backups'
    if os.path.exists(backups_dir):
        for file in os.listdir(backups_dir):
            if file.startswith(schema) and file.endswith('.sql'):
                backups.append({
                    'file': file,
                    'date': datetime.fromtimestamp(os.path.getmtime(f'{backups_dir}/{file}'))
                })
    return sorted(backups, key=lambda x: x['date'], reverse=True)


def calculate_next_backup(frequency: str, time_str: str) -> datetime:
    """Calculate next backup time"""
    now = datetime.now()
    hour, minute = map(int, time_str.split(':'))

    if frequency == 'daily':
        next_backup = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_backup <= now:
            next_backup += timedelta(days=1)
    elif frequency == 'weekly':
        next_backup = now + timedelta(days=7 - now.weekday())
        next_backup = next_backup.replace(hour=hour, minute=minute)
    else:  # monthly
        if now.day <= 1:
            next_backup = now.replace(day=1, hour=hour, minute=minute)
        else:
            next_month = now.month % 12 + 1
            next_year = now.year + (now.month // 12)
            next_backup = now.replace(year=next_year, month=next_month, day=1,
                                      hour=hour, minute=minute)

    return next_backup


@app.route('/tenant/<int:tenant_id>/security-baselines', methods=['GET', 'POST'])
def tenant_security_baselines(tenant_id):
    if str(session.get('tenant_id')) != str(tenant_id):
        log_tenant_event(
            action_type='SECURITY_BASELINES_ACCESS_DENIED',
            description=f"Unauthorized access to security baselines for tenant {tenant_id}",
            category='SECURITY',
            success=False,
            tenant_id=tenant_id
        )
        return redirect(url_for('login'))

    tenant_security = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()
    form = SecurityBaselineForm(obj=tenant_security)

    if form.validate_on_submit():
        log_tenant_event(
            action_type='SECURITY_BASELINES_UPDATE_ATTEMPT',
            description=f"Security baselines update attempt for tenant {tenant_id}",
            category='SECURITY',
            target_resource='SECURITY_POLICY',
            resource_id=str(tenant_id),
            tenant_id=tenant_id
        )

        if not tenant_security:
            tenant_security = TenantSecurity(tenant_id=tenant_id)

        form.populate_obj(tenant_security)
        db.session.add(tenant_security)
        db.session.commit()

        apply_rls_policies(tenant_id, tenant_security)

        log_tenant_event(
            action_type='SECURITY_BASELINES_UPDATED',
            description=f"Security baselines updated successfully for tenant {tenant_id}",
            category='SECURITY',
            target_resource='SECURITY_POLICY',
            resource_id=str(tenant_id),
            tenant_id=tenant_id,
            additional_data={
                'mfa_enabled': tenant_security.mfa_enabled,
                'dlp_enabled': tenant_security.dlp_enabled,
                'rls_enabled': tenant_security.rls_enabled,
                # NEW: Log specific DLP strategies
                'dlp_strategies': {
                    'monitor': tenant_security.dlp_monitor_only,
                    'notify': tenant_security.dlp_notify_user,
                    'require_approval': tenant_security.dlp_require_approval,
                    'block': tenant_security.dlp_block_action,
                    'incident_response': tenant_security.dlp_trigger_incident
                }
            }
        )

        flash("✅ Security baselines applied successfully!", "success")
        return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))

    return render_template('CompanyAdmin/security_baselines.html', form=form, tenant_id=tenant_id)

@app.route('/tenant/<int:tenant_id>/backup-recovery', methods=['GET', 'POST'])
def tenant_backup_recovery(tenant_id):
    if str(session.get('tenant_id')) != str(tenant_id):
        return redirect(url_for('login'))

    tenant = Tenant.query.get_or_404(tenant_id)
    config = TenantBackupConfig.query.filter_by(tenant_id=tenant_id).first()

    schedule_form = BackupScheduleForm(obj=config)
    action_form = BackupActionForm()
    backups = get_tenant_backups(tenant_id)

    # Form 1: Settings ✅
    if schedule_form.validate_on_submit() and schedule_form.save_settings.data:
        if not config:
            config = TenantBackupConfig(tenant_id=tenant_id)
        schedule_form.populate_obj(config)
        config.next_backup = calculate_next_backup(config.frequency, config.backup_time)
        db.session.add(config)
        db.session.commit()
        flash("✅ Schedule updated!", "success")
        return redirect(url_for('tenant_backup_recovery', tenant_id=tenant_id))

    # Form 2: Actions ✅ FIXED
    if action_form.validate_on_submit():
        if action_form.backup_submit.data:
            backup_file = backup_tenant(tenant_id)
            if backup_file:
                flash(f"✅ Backup created!", "success")
            else:
                flash("❌ Backup failed", "danger")

        elif action_form.restore_submit.data and action_form.backup_file.data:
            uploaded_file = action_form.backup_file.data

            if uploaded_file and uploaded_file.filename:
                # SAVE UPLOADED FILE
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                saved_filename = f"tenant_{tenant_id}_restore_{timestamp}.sql"
                saved_path = f"backups/{saved_filename}"

                os.makedirs('backups', exist_ok=True)
                uploaded_file.save(saved_path)

                print(f"💾 SAVED: {saved_path}")

                # RESTORE FROM SAVED FILE
                result = restore_tenant_backup(tenant_id, saved_filename)
                print(f"🔍 RESULT: {result}")
                flash(result, "info")
            else:
                flash("❌ No file selected", "danger")

        return redirect(url_for('tenant_backup_recovery', tenant_id=tenant_id))

    return render_template('CompanyAdmin/backup_recovery.html',
                           schedule_form=schedule_form,
                           action_form=action_form,
                           tenant=tenant, backups=backups, tenant_id=tenant_id)


# 🔥 DOWNLOAD ROUTE (add this)
@app.route('/tenant/<int:tenant_id>/backup-download/<path:filename>')
def backup_download(tenant_id, filename):
    if str(session.get('tenant_id')) != str(tenant_id):
        return redirect(url_for('login'))

    # Security: Only tenant's own backups
    if filename.startswith(f'tenant_{tenant_id}'):
        try:
            return send_from_directory('backups', filename, as_attachment=True)
        except FileNotFoundError:
            flash("❌ Backup file not found", "danger")
    return "Unauthorized", 403


# 🔥 DELETE ROUTE (add this)
@app.route('/tenant/<int:tenant_id>/backup-delete/<path:filename>', methods=['POST'])
@csrf.exempt  # 🔥 DISABLE CSRF FOR THIS ROUTE ONLY
def backup_delete(tenant_id, filename):
    if str(session.get('tenant_id')) != str(tenant_id):
        return redirect(url_for('login'))

    if filename.startswith(f'tenant_{tenant_id}'):
        filepath = f'backups/{filename}'
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                flash(f"✅ Deleted: {filename}", "success")
            else:
                flash("❌ File not found", "danger")
        except Exception as e:
            flash(f"❌ Delete failed: {str(e)}", "danger")

    return redirect(url_for('tenant_backup_recovery', tenant_id=tenant_id))


#TODO tristan stuff -------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 1. Clean up any previous failed transactions
    try:
        db.session.rollback()
    except:
        pass

    form = Loginform()

    if form.validate_on_submit():
        email_input = form.email.data.strip()
        password_input = form.password.data.strip()

        print(f"🔍 Login attempt: {email_input}")

        # ✅ PATH 0: SUPERADMIN (System Level)
        superadmin = authenticate_superadmin(email_input, password_input)
        if superadmin:
            session.clear()
            session['user_type'] = 'superadmin'
            session['superadmin_id'] = 'SYSTEM'
            session['email'] = 'System Admin'
            session['user_role'] = "System Administrator"
            session.permanent = True

            log_system_admin_event(
                action_type='SYSTEM_ADMIN_LOGIN_SUCCESS',
                description="System admin logged in successfully",
                category='AUTHENTICATION',
                severity="info",
                ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                user_agent=request.headers.get('User-Agent')
            )

            flash("🛡️ Superadmin access granted", "success")
            return redirect(url_for('superadmincontrolpanel'))

        # ✅ UNIFIED PATH: TENANT USERS & ADMINS
        user_location = find_user_by_email(email_input)

        if user_location:
            tenant_id = user_location['tenant_id']
            print(f"🔍 Found email in tenant_{tenant_id}")

            # 1. Authenticate Password
            auth_result = authenticate_user(tenant_id, email_input, password_input)

            if auth_result:
                # 🔥 2. CHECK TENANT SECURITY POLICY
                security_policy = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()
                # Default to False if no policy, otherwise respect DB setting
                mfa_enabled = security_policy.mfa_enabled if security_policy else False

                mfa_passed = False

                # 3. MFA CHECK (Only if enabled in baseline)
                if mfa_enabled:
                    from usb_mfa import USBMFAManager

                    # Check USB MFA first
                    if USBMFAManager.find_and_validate_usb_mfa(auth_result['user_id'], tenant_id, email_input):
                        mfa_passed = True
                        log_tenant_event('LOGIN_SUCCESS_USB_MFA', f"User logged in via USB MFA: {email_input}",
                                         'AUTHENTICATION', tenant_id=tenant_id, user_id=auth_result['user_id'])
                    else:
                        # Fallback to Email 2FA (Redirect to verify page)
                        print(f"🔄 No USB MFA found, falling back to email 2FA for {email_input}")
                        session.clear()
                        session['temp_user_email'] = email_input
                        session['temp_user_id'] = auth_result['user_id']
                        session['temp_tenant_id'] = tenant_id
                        session['tenant_id'] = tenant_id
                        session['user_type'] = 'tenant_admin' if auth_result['role'] == 'admin' else 'user'
                        session['needs_2fa'] = True
                        session.permanent = True

                        send_2fa_email(email_input)
                        flash("🔑 MFA Enabled: Enter the 2FA code sent to your email.", "info")
                        return redirect(url_for('verify_2fa'))
                else:
                    # MFA Disabled by Policy -> Pass immediately
                    mfa_passed = True
                    log_tenant_event('LOGIN_SUCCESS_NO_MFA', f"User logged in (MFA Policy Disabled): {email_input}",
                                     'AUTHENTICATION', tenant_id=tenant_id, user_id=auth_result['user_id'])

                # 4. FINALIZE LOGIN (If MFA passed or was disabled)
                if mfa_passed:
                    session.clear()
                    session['user_id'] = auth_result['user_id']
                    session['email'] = auth_result['email']
                    session['tenant_id'] = auth_result['tenant_id']
                    session['tenant_schema'] = auth_result['schema_name']
                    session['user_role'] = auth_result['role']
                    session['user_type'] = 'tenant_admin' if auth_result['role'] == 'admin' else 'user'
                    session['logged_in'] = True
                    session.permanent = True

                    if auth_result['role'] == 'admin':
                        flash(f"✅ Welcome Admin! (Tenant {tenant_id})", "success")
                        return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))
                    else:
                        flash(f"✅ Welcome back! (Tenant {tenant_id})", "success")
                        return redirect(url_for('myfiles'))

            else:
                log_tenant_event('LOGIN_FAILED', f"Login failed (password): {email_input}", 'AUTHENTICATION',
                                 success=False, tenant_id=tenant_id)
                flash("❌ Invalid email or password.", "danger")
        else:
            flash("❌ User not found.", "danger")

    return render_template('login/login_page.html', form=form)
# ==================== USB MFA MANAGEMENT ROUTES ====================

@app.route('/settings/usb-mfa/generate', methods=['POST'])
@csrf.exempt
def generate_usb_mfa():
    """Generate and download MFA key file for USB"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    tenant_id = session.get('tenant_id')
    user_id = session.get('user_id')
    email = session.get('email')
    
    try:
        from usb_mfa import USBMFAManager, create_mfa_key_file
        import tempfile
        
        # Generate key
        manager = USBMFAManager()
        key_info = manager.generate_mfa_key(user_id, tenant_id, email)
        
        # Store in session for download
        session['usb_mfa_key'] = key_info['key_data']
        session['usb_mfa_hash'] = key_info['key_hash']
        
        log_tenant_event(
            action_type='USB_MFA_KEY_GENERATED',
            description=f"USB MFA key generated for user {email}",
            category='SECURITY',
            tenant_id=tenant_id,
            user_id=user_id
        )
        
        return jsonify({
            'success': True,
            'message': 'USB MFA key generated. Ready to download.',
            'key_data': key_info['key_data']
        }), 200
    
    except Exception as e:
        print(f"❌ Error generating USB MFA key: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/settings/usb-mfa/download', methods=['GET'])
def download_usb_mfa_key():
    """Download the MFA key file to put on USB"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    try:
        from io import BytesIO
        import json
        
        key_data = session.get('usb_mfa_key')
        if not key_data:
            flash("❌ No MFA key in session. Generate one first.", "danger")
            return redirect(url_for('myfiles'))
        
        # Create file content
        file_content = json.dumps(key_data, indent=2).encode('utf-8')
        file_obj = BytesIO(file_content)
        
        # Generate filename with timestamp to support multiple downloads
        # Format: mfa_key_YYYYMMDD_HHMMSS.json
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        download_filename = f'mfa_key_{timestamp}.json'
        
        return send_file(
            file_obj,
            mimetype='application/json',
            as_attachment=True,
            download_name=download_filename
        )
    
    except Exception as e:
        print(f"❌ Error downloading MFA key: {e}")
        flash(f"❌ Download error: {str(e)}", "danger")
        return redirect(url_for('myfiles'))


@app.route('/settings/usb-mfa/enable', methods=['POST'])
@csrf.exempt
def enable_usb_mfa():
    """Enable USB MFA for current user"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    tenant_id = session.get('tenant_id')
    user_id = session.get('user_id')
    email = session.get('email')
    
    try:
        schema_name = f"tenant_{tenant_id}"
        
        # Update user record to enable USB MFA
        db.session.execute(text(f'''
            UPDATE "{schema_name}".users
            SET usb_mfa_enabled = TRUE
            WHERE id = :user_id
        '''), {'user_id': user_id})
        
        db.session.commit()
        
        log_tenant_event(
            action_type='USB_MFA_ENABLED',
            description=f"USB MFA enabled for user {email}",
            category='SECURITY',
            tenant_id=tenant_id,
            user_id=user_id
        )
        
        return jsonify({
            'success': True,
            'message': '✅ USB MFA enabled successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error enabling USB MFA: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/settings/usb-mfa/disable', methods=['POST'])
@csrf.exempt
def disable_usb_mfa():
    """Disable USB MFA for current user"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    tenant_id = session.get('tenant_id')
    user_id = session.get('user_id')
    email = session.get('email')
    
    try:
        schema_name = f"tenant_{tenant_id}"
        
        # Update user record to disable USB MFA
        db.session.execute(text(f'''
            UPDATE "{schema_name}".users
            SET usb_mfa_enabled = FALSE
            WHERE id = :user_id
        '''), {'user_id': user_id})
        
        db.session.commit()
        
        log_tenant_event(
            action_type='USB_MFA_DISABLED',
            description=f"USB MFA disabled for user {email}",
            category='SECURITY',
            tenant_id=tenant_id,
            user_id=user_id
        )
        
        return jsonify({
            'success': True,
            'message': '✅ USB MFA disabled'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error disabling USB MFA: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/settings/usb-mfa/status', methods=['GET'])
def get_usb_mfa_status():
    """Get current USB MFA status for user"""
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    tenant_id = session.get('tenant_id')
    user_id = session.get('user_id')
    
    try:
        schema_name = f"tenant_{tenant_id}"
        
        result = db.session.execute(text(f'''
            SELECT usb_mfa_enabled FROM "{schema_name}".users WHERE id = :user_id
        '''), {'user_id': user_id}).fetchone()
        
        usb_mfa_enabled = result[0] if result else False
        
        return jsonify({
            'success': True,
            'usb_mfa_enabled': usb_mfa_enabled
        }), 200
    
    except Exception as e:
        print(f"❌ Error getting USB MFA status: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/settings/usb-mfa', methods=['GET'])
def usb_mfa_settings():
    """USB MFA settings page"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('users/usb_mfa_settings.html')


@app.route('/logout')
def logout():
    # Audit Log Entry ===========================
    if session.get('user_type') == 'tenant_admin' and session.get('tenant_id'):
        SysLogService.logTenantEvent(
            tenant_id=session['tenant_id'],
            action_type='TENANT_USER_LOGOUT',
            description=f"Tenant admin logout for {session.get('temp_user_email', 'unknown')}",
            category='USER_ACTIVITY'
        )
    elif session.get('temp_user_email'):
        SysLogService.logSystemAdminEvent(
            action_type='SYSTEM_ADMIN_LOGOUT',
            description=f"System admin logout for {session.get('temp_user_email', 'unknown')}"
        )
    # =============================================

    # Invalidate session token if it exists
    session_token = request.cookies.get('session_token')
    if session_token:
        # In production: invalidate token in database
        pass
    
    session.clear()
    flash("You have been logged out.", "info")
    
    response = redirect(url_for('login'))
    response.delete_cookie('session_token')
    return response

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    tenants = db.session.query(Tenant).all()
    
    # Populate tenant_id choices dynamically
    form.tenant_id.choices = [(t.id, t.company_name) for t in tenants]
    
    if form.validate_on_submit():
        email = escape(form.email.data.strip())
        password = escape(form.password.data)
        tenant_id = form.tenant_id.data
        
        # Optional: bypass global cross-tenant uniqueness to allow same email in multiple tenants
        existing_user = find_user_by_email(email)
        if existing_user:
            flash(f"Email already exists in tenant {existing_user['tenant_id']} – continuing anyway.", "warning")
        
        # Make sure tenant exists
        tenant = db.session.query(Tenant).filter_by(id=tenant_id).first()
        if not tenant:
            flash("Invalid tenant selected.", "danger")
            return render_template('login/tmpsignup.html', form=form, tenants=tenants)
        
        # Hash password using bcrypt (matches authenticate_user)
        password_bytes = password.encode()
        password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode()
        
        # Create user in tenant schema
        new_user = create_user_in_tenant(tenant_id, email, password_hash, role='user')
        
        if not new_user:
            flash("Failed to create account in tenant schema. Check logs.", "danger")
            return render_template('login/tmpsignup.html', form=form, tenants=tenants)
        
        flash(
            f"✅ Account created successfully in tenant_{tenant_id}.users (id={new_user['user_id']}, email={new_user['email']})",
            "success"
        )
        return redirect(url_for('login'))
    
    return render_template('login/tmpsignup.html', form=form, tenants=tenants)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forget_password():
    
    form = ForgetPasswordForm()

    if form.validate_on_submit():
        email = escape(form.email.data)
        user = True #User.query.filter_by(email=email).first()

        if user:
            token = s.dumps(email, salt='password-reset')

            reset_url = url_for('reset_password', token=token, _external=True)

            try:
                send_password_reset_email(email, reset_url)
                flash("Please check your email for password reset instructions.", "success")
            except Exception as e:
                flash(f"Error sending email: {str(e)}", "danger")

        else:
            flash("No user found with that email address.", "danger")

        return redirect(url_for('forget_password'))

    return render_template('login/forget_password_page.html', form=form)


def send_verification_email(user_email):
    token = s.dumps(user_email, salt='email-confirm')
    verify_url = url_for('verify_email', token=token, _external=True)

    subject = "Please confirm your email"
    body = render_template('email/verify_email.txt', verify_url=verify_url)

    msg = MIMEMultipart()
    msg['From'] = 'sagesuppor@gmail.com'
    msg['To'] = user_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('sagesuppor@gmail.com', os.environ.get('EMAIL_PASSWORD'))
            server.sendmail('sagesuppor@gmail.com', user_email, msg.as_string())
    except Exception as e:
        raise Exception(f"Failed to send verification email: {str(e)}")


def send_password_reset_email(to_email, reset_url):
    from_address = 'sagesuppor@gmail.com'
    to_address = to_email
    subject = "Password Reset Request"

    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Subject'] = subject

    body = render_template('email/reset_password.txt', reset_url=reset_url)
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_address, os.environ.get('EMAIL_PASSWORD'))
            server.sendmail(from_address, to_address, msg.as_string())
    except Exception as e:
        raise Exception(f"Failed to send email: {str(e)}")


@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=86400)  # 24 hours
        user = True #User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            #db.session.commit()
            flash("Email verified successfully! You can now log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Verification failed: User not found.", "danger")
    except SignatureExpired:
        flash("Verification link expired.", "danger")
    except Exception:
        flash("Invalid verification link.", "danger")

    return redirect(url_for('login'))


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using token from email link"""
    form = ResetPasswordForm()
    
    if request.method == 'GET':
        try:
            email = s.loads(token, salt='password-reset', max_age=3600)  # 1 hour
            session['reset_email'] = email
        except SignatureExpired:
            flash("The password reset link has expired.", "danger")
            return redirect(url_for('forget_password'))
        except Exception:
            flash("Invalid or expired token.", "danger")
            return redirect(url_for('forget_password'))
        
        return render_template('login/reset_password.html', form=form)
    
    if request.method == 'POST':
        email = session.get('reset_email')
        if not email:
            flash("Session expired. Please request password reset again.", "danger")
            return redirect(url_for('forget_password'))
        
        if form.validate_on_submit():
            new_password = escape(form.password.data)
            
            # In production: update user password in database
            # For now: just confirm password was changed
            session.pop('reset_email', None)
            flash("Your password has been updated successfully.", "success")
            return redirect(url_for('login'))
        else:
            # Form validation failed - show errors
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    
    return render_template('login/reset_password.html', form=form)


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if not session.get('needs_2fa'):
        flash("No active login session.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        email = session.get('temp_user_email')

        if validate_2fa_code_format(code) and code == session.get('2fa_code'):
            # ✅ LOGIN SUCCESS - Route by user_type
            tenant_id = session.get('tenant_id')
            
            if not tenant_id:
                flash("❌ Session error: No tenant ID found. Please log in again.", "danger")
                return redirect(url_for('login'))
            
            # Mark user as logged in
            session['logged_in'] = True
            
            # 🔥 Critical: Set email and user_id for post-login operations (USB MFA, settings, etc.)
            session['email'] = email
            session['user_id'] = session.get('temp_user_id')
            
            if session.get('user_type') == 'tenant_admin':
                # Tenant admin → Company dashboard

                # For Audit Log Entry ====================
                SysLogService.logTenantEvent(
                    tenant_id=tenant_id,
                    action_type='TENANT_USER_LOGIN',
                    description=f"Tenant admin login successful for {email}",
                    admin_email=email,
                    category='USER_ACTIVITY'
                )
                #=============================================
                

                return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))
            else:
                # Regular user → My Files page

                # Audit Log Entry ============================
                SysLogService.logTenantEvent(
                    tenant_id=tenant_id,
                    action_type='TENANT_USER_LOGIN',
                    description=f"Tenant user login successful for {email}",
                    admin_email=email,
                    category='USER_ACTIVITY'
                )
                #=============================================

                return redirect(url_for('myfiles'))
        # Audit Log Entry ============================
        if session.get('user_type') == 'tenant_admin':
            SysLogService.logTenantEvent(
                tenant_id=session.get('tenant_id'),
                action_type='TENANT_USER_LOGIN',
                description=f"Failed 2FA attempt for {email}",
                admin_email=email,
                success=False,
                category='USER_ACTIVITY'
            )
        else:
            SysLogService.logSystemAdminEvent(
                action_type='SYSTEM_ADMIN_LOGIN',
                description=f"Failed 2FA attempt for {email}",
                admin_email=email,
                success=False
            )
        #=============================================
                

        flash("Invalid 2FA code.", "danger")

    return render_template('login/verify_2fa.html')


@app.route('/resend-2fa', methods=['POST'])
def resend_2fa():
    """Resend 2FA code"""
    email = session.get('temp_user_email')
    if not email:
        return jsonify({'success': False, 'error': 'Session expired'}), 400
    
    send_2fa_email(email)
    return jsonify({'success': True, 'message': 'Code resent to email'}), 200


@app.route('/verify-signup-email/<token>', methods=['GET', 'POST'])
def verify_signup_email(token=None):
    """Verify email during signup with token and create user account"""
    if request.method == 'GET' and token:
        try:
            email = s.loads(token, salt='signup-confirm', max_age=3600)  # 1 hour
            
            # Get signup info from session
            signup_email = session.get('signup_email')
            tenant_id = session.get('signup_tenant_id')
            password_hash = session.get('signup_password_hash')
            code_id = session.get('signup_code_id')
            
            # Verify token matches session email
            if email != signup_email:
                flash("Email mismatch. Please sign up again.", "danger")
                return redirect(url_for('signup'))
            
            if not all([signup_email, tenant_id, password_hash, code_id]):
                flash("Session expired. Please sign up again.", "danger")
                return redirect(url_for('signup'))
            
            # Create user in tenant schema
            new_user = create_user_in_tenant(tenant_id, signup_email, password_hash, role='user')
            
            if not new_user:
                flash("Failed to create account. Please try again.", "danger")
                return redirect(url_for('signup'))
            
            # Mark signup code as used
            mark_verification_code_used(code_id)
            
            # Clear session
            session.pop('signup_email', None)
            session.pop('signup_tenant_id', None)
            session.pop('signup_password_hash', None)
            session.pop('signup_code_id', None)
            session.pop('signup_company', None)
            session.pop('pending_signup', None)
            
            flash(f"✅ Account created successfully! You can now log in.", "success")
            return redirect(url_for('login'))
        
        except SignatureExpired:
            flash("Verification link expired. Please sign up again.", "danger")
            return redirect(url_for('signup'))
        except Exception as e:
            print(f"Signup verification error: {e}")
            flash("Invalid verification link.", "danger")
            return redirect(url_for('signup'))
    
    # POST: Resend verification email
    if request.method == 'POST':
        email = session.get('signup_email')
        signup_code = session.get('signup_code')
        if email and signup_code:
            send_signup_verification_email(email, signup_code)
            return jsonify({'success': True, 'message': 'Verification email resent'}), 200
        else:
            return jsonify({'success': False, 'error': 'Session expired'}), 400
    
    return render_template('login/verify_signup_email.html')


# ==================== HELPER FUNCTIONS ====================

def validate_signup_code_format(code):
    """Validate signup code format"""
    import re
    if not code:
        return False
    # Accept: INVITE_XXXXXX or similar alphanumeric patterns
    return bool(re.match(r'^[A-Z0-9_]{6,20}$', code))


def validate_2fa_code_format(code):
    """Validate 2FA code is 6 digits"""
    return bool(code.isdigit() and len(code) == 6)


def send_2fa_email(user_email):
    """Generate and send 2FA code via email"""
    import random
    
    # Generate 6-digit code
    code = ''.join(random.choices('0123456789', k=6))
    
    # Store in session (in production: store in DB with expiration)
    session['2fa_code'] = code
    session['2fa_expires'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    
    subject = "Your 2-Factor Authentication Code"
    body = f"""
    Your 2FA code is: {code}
    This code expires in 10 minutes.
    If you didn't request this, please ignore this email.
    """
    
    msg = MIMEMultipart()
    msg['From'] = 'sagesuppor@gmail.com'
    msg['To'] = user_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('sagesuppor@gmail.com', os.environ.get('EMAIL_PASSWORD'))
            server.sendmail('sagesuppor@gmail.com', user_email, msg.as_string())
        return True
    except Exception as e:
        print(f"❌ 2FA email error: {str(e)}")
        return False


def send_signup_verification_email(user_email, signup_code):
    """Send email verification for signup"""
    token = s.dumps(user_email, salt='signup-confirm')
    verify_url = url_for('verify_signup_email', token=token, _external=True)
    
    subject = "Verify Your Email - Signup"
    body = render_template('email/verify_email.txt', verify_url=verify_url, signup_code=signup_code)
    
    msg = MIMEMultipart()
    msg['From'] = 'sagesuppor@gmail.com'
    msg['To'] = user_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('sagesuppor@gmail.com', os.environ.get('EMAIL_PASSWORD'))
            server.sendmail('sagesuppor@gmail.com', user_email, msg.as_string())
        return True
    except Exception as e:
        print(f"❌ Signup email error: {str(e)}")
        return False

#super admin codes-----------------------------------------------------------------------------------------
#DLP Scanner-----------------------------------------------------------------------------------------------


@csrf.exempt
def policyEngine(file):
    try:
        if not fileProcessor.passedProcessing(file):
            return {'status': 'error', 'message': 'File type not supported for DLP scanning.'}
        ext = fileProcessor.getFileExtension(file.filename)
        if ext in fileProcessor.supported_extensions.get("image_files", set()):
            extractResult = fileProcessor.readTextFromFile(file)
            decision_result = dlpScanner.scan_ocr_and_decide(extractResult)
        else:
            extractResult = fileProcessor.readTextFromFile(file)
            decision_result = dlpScanner.scan_and_decide(extractResult)
        return {'status': 'success',
                'decision': decision_result['decision'],
                'reasons': decision_result['reasons'],
                'fileName': fileProcessor.getFileInfo(file),
                'riskLevel': decision_result.get('riskLevel')
            }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


@csrf.exempt
@app.route('/autodlp', methods=['GET', 'POST'])
def autodlp():
    result = None 
    savedFilePath = None
    if request.method == 'POST':

        log_system_admin_event(
            action_type='DLP_SCAN_INITIATED',
            description="DLP scan initiated from admin panel",
            category='SECURITY'
        )

        if 'file' not in request.files:

            log_system_admin_event(
                action_type='DLP_SCAN_FAILED',
                description="DLP scan failed: No file part",
                category='SECURITY',
                success=False
            )

            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':

            log_system_admin_event(
                action_type='DLP_SCAN_FAILED',
                description="DLP scan failed: No file selected",
                category='SECURITY',
                success=False
            )

            flash('No selected file', 'error')
            return redirect(request.url)
        if file and file.filename:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            uniqueFilename = f"{timestamp}_{filename}"
            filePath = os.path.join(current_app.config['UPLOAD_FOLDER'], uniqueFilename)
            
            try:
                file.save(filePath)
                savedFilePath = filePath
                flash(f'File uploaded successfully: {uniqueFilename}', 'success')
                file.seek(0)
                result = policyEngine(file)
                if 'status' in result and result['status'] == 'error':

                    log_system_admin_event(
                        action_type='DLP_SCAN_ERROR',
                        description=f"DLP scan error for file {filename}: {result['message']}",
                        category='SECURITY',
                        target_resource='FILE',
                        resource_id=filename,
                        success=False
                    )

                    flash(result['message'], 'error')
                    return redirect(request.url)
                else:
                    decision = result.get('decision')
                    reasons = result.get('reasons', [])

                    log_system_admin_event(
                        action_type='DLP_SCAN_COMPLETED',
                        description=f"DLP scan completed for {filename}: {decision.upper()}",
                        category='SECURITY',
                        target_resource='FILE',
                        resource_id=filename,
                        additional_data={
                            'decision': decision,
                            'reasons': result.get('reasons', [])
                        }
                    )

                    if decision == 'deny':
                        flash(f'File DENIED - {"; ".join(reasons)}', 'error') 
                    else:
                        flash(f'File ALLOWED - {"; ".join(reasons)}', 'success')   
            except Exception as e:

                log_system_admin_event(
                    action_type='DLP_SCAN_ERROR',
                    description=f"DLP scan system error: {str(e)}",
                    category='SECURITY',
                    success=False
                )

                flash(f'Error saving file: {str(e)}', 'error')
                return redirect(request.url)
    return render_template("SuperAdmin/autodlp.html",
                            decision=result.get('decision') if result else None,
                            reasons=result.get('reasons') if result else None,
                            filename=file.filename if 'file' in locals() and file.filename else None,
                            riskLevel=result.get('riskLevel') if result else None,
                            savedFilePath=savedFilePath)

@csrf.exempt
@app.route('/tenant-dlpscanning', methods=['GET', 'POST'])
def tenant_dlpscanning():
    result = None 
    savedFilePath = None
    if request.method == 'POST':      
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and file.filename:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            uniqueFilename = f"{timestamp}_{filename}"
            filePath = os.path.join(current_app.config['UPLOAD_FOLDER'], uniqueFilename)
            try:
                file.save(filePath)
                savedFilePath = filePath
                flash(f'File uploaded successfully: {uniqueFilename}', 'success')
                file.seek(0)
                result = policyEngine(file)
                if 'status' in result and result['status'] == 'error':
                    flash(result['message'], 'error')
                    return redirect(request.url)
                else:
                    decision = result.get('decision')
                    reasons = result.get('reasons', [])
                    if decision == 'deny':
                        flash(f'File DENIED - {"; ".join(reasons)}', 'error') 
                    else:
                        flash(f'File ALLOWED - {"; ".join(reasons)}', 'success')   
            except Exception as e:
                flash(f'Error saving file: {str(e)}', 'error')
                return redirect(request.url)
    return render_template("CompanyAdmin/tenant_dlpscanning.html",
                         scan_result=result,
                         filename=file.filename if 'file' in locals() and file.filename else None,
                         last_scan_time=datetime.now(),
                         database_progress=85,
                         export_progress=92)


@csrf.exempt
@app.route('/debug')
def debug():
    try:
        test_text = "My SSN is 123-45-6789 and my password is secret123"
        matches = dlpScanner.scan_text(test_text)
        return {
            'dlp_scanner_working': True,
            'matches_found': len(matches),
            'supported_extensions': list(fileProcessor.getAllSupportedExtensions()),
            'pdf_available': hasattr(fileProcessor, 'PDF_AVAILABLE') and fileProcessor.PDF_AVAILABLE,
            'config_paths': {
                'dlp_config': dlpScanner.config_path,
                'file_config': fileProcessor.config_path
            }
        }
    except Exception as e:
        import traceback
        return {
            'error': str(e),
            'traceback': traceback.format_exc(),
            'dlp_scanner_working': False
        }
    
#SYS HP Monitor-----------------------------------------------------------------------------------------------

@csrf.exempt
@app.route('/systemhealthmonitor')
def systemHealthMonitor():
    try:

        log_system_admin_event(
            action_type='SYSTEM_HEALTH_ACCESSED',
            description="System health monitor accessed",
            category='SYSTEM'
        )

        healthData = getSystemHealth()

        log_system_admin_event(
            action_type='SYSTEM_HEALTH_CHECK_COMPLETED',
            description="System health check completed",
            category='SYSTEM',
            additional_data={
                'app_health': healthData.get('appHP', 0),
                'database_status': healthData.get('databaseStatus', 0),
                'system_status': healthData.get('systemStatus', 0)
            }
        )

        return render_template('SuperAdmin/systemhealthmonitor.html', **healthData)
    except Exception as e:

        log_system_admin_event(
            action_type='SYSTEM_HEALTH_ERROR',
            description=f"System health monitor error: {str(e)}",
            category='SYSTEM',
            success=False
        )

        error_data = {
            'systemStatus': 0,
            'databaseStatus': 0, 
            'appHP': 1,
            'database_message': f'Error retrieving system health: {str(e)}',
            'database_details': {},
            'system_info': {}
        }

        flash(f'Error retrieving system health: {str(e)}', 'error')
        return render_template('SuperAdmin/systemhealthmonitor.html', **error_data)

def calculate_performance_metrics():
    try:
        metrics = {}
        response_times = list(performance_metrics['response_times'])
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            metrics['averageResponseTime'] = f"{avg_response_time:.1f}ms"
        else:
            metrics['averageResponseTime'] = "0ms"
        total_api_requests = sum(performance_metrics['api_requests'].values())
        total_api_errors = sum(performance_metrics['api_errors'].values())
        if total_api_requests > 0:
            error_rate = (total_api_errors / total_api_requests) * 100
            metrics['apiErrorRate'] = f"{error_rate:.1f}%"
        else:
            metrics['apiErrorRate'] = "0%"
        metrics['totalAPIRequests'] = str(total_api_requests)
        metrics['totalRequests'] = str(performance_metrics['total_requests'])
        metrics['uptime'] = calculate_uptime()
        return metrics
    except Exception as e:
        print(f"Error calculating performance metrics: {e}")
        return {
            'averageResponseTime': 'Error',
            'apiErrorRate': 'Error',
            'totalAPIRequests': 'Error'
        }

def calculate_uptime():
    try:
        uptime_seconds = time.time() - performance_metrics['start_time']
        if uptime_seconds < 60:
            return f"{uptime_seconds:.0f}s"
        elif uptime_seconds < 3600:
            minutes = uptime_seconds / 60
            return f"{minutes:.1f}m"
        elif uptime_seconds < 86400:
            hours = uptime_seconds / 3600
            return f"{hours:.1f}h"
        else:
            days = uptime_seconds / 86400
            return f"{days:.1f}d"
    except:
        return "Unknown"


def getSystemHealth():
    try:
        db_health = checkDatabaseHealth()
        database_status = db_health['status']
        app_health = 100
        try:
            import psutil
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            if memory.percent > 90 or cpu_percent > 90:
                system_health = 25
            elif memory.percent > 80 or cpu_percent > 80:
                system_health = 50
            elif memory.percent > 70 or cpu_percent > 70:
                system_health = 75
            else:
                system_health = 100
        except:
            system_health = 50
            memory = None
            cpu_percent = None
        error_logs = getRecentErrorLogs(limit=20, hours=24)
        tenant_alerts = getRecentTenantAlerts(limit=10)
        db_metrics = db_health.get('metrics', {})
        perf_metrics = calculate_performance_metrics()
        db_perf_metrics = get_database_performance_metrics(hours=24)
        total_api_requests = int(perf_metrics.get('totalAPIRequests', 0)) + db_perf_metrics.get('database_api_requests', 0)
        if perf_metrics.get('averageResponseTime', '0ms') != '0ms':
            avg_response = perf_metrics['averageResponseTime']
        else:
            avg_response = db_perf_metrics.get('database_avg_response', '25ms')
        
        if perf_metrics.get('apiErrorRate', '0%') != '0%':
            error_rate = perf_metrics['apiErrorRate']
        else:
            error_rate = db_perf_metrics.get('database_error_rate', '0.2%')
        
        return {
            'systemStatus': 1 if system_health > 50 else 0,
            'databaseStatus': database_status,
            'appHP': 1,
            'system_health_percentage': system_health,
            'database_health_percentage': db_health.get('health_percentage', 0),
            'app_health_percentage': app_health,
            'webserverStatus': app_health,
            'database_details': db_health.get('details', {}),
            'database_message': db_health.get('message', ''),
            'databaseQueryLatency': f"{db_metrics.get('query_latency_ms', 'Unknown')}ms",
            'active_db_connections': db_metrics.get('active_connections', 'Unknown'),
            'databaseSize': db_metrics.get('database_size', 'Unknown'),
            'total_db_connections': db_metrics.get('total_connections', 'Unknown'),
            'idle_db_connections': db_metrics.get('idle_connections', 'Unknown'),
            'active_queries': db_metrics.get('active_queries', 'Unknown'),
            'error_logs': error_logs,
            'tenant_alerts': tenant_alerts,
            'system_info': {
                'memory_percent': memory.percent if memory else 'Unknown',
                'cpu_percent': cpu_percent if cpu_percent else 'Unknown',
                'available_memory_gb': round(memory.available / (1024**3), 2) if memory else 'Unknown'
            },
            'averageResponseTime': avg_response,
            'apiErrorRate': error_rate,
            'totalAPIRequests': str(total_api_requests),
            'uptime': perf_metrics.get('uptime', 'Unknown'),
            'totalRequests': perf_metrics.get('totalRequests', '0'),
            'requestsLast24h': str(db_perf_metrics.get('total_events_24h', 0))
        }
    except Exception as e:
        return {
            'systemStatus': 0,
            'databaseStatus': 0,
            'appHP': 1,
            'system_health_percentage': 0,
            'database_health_percentage': 0,
            'app_health_percentage': 50,
            'webserverStatus': 50,
            'error': str(e),
            'database_details': {},
            'database_message': f'System health check error: {str(e)}',
            'databaseQueryLatency': 'Error',
            'active_db_connections': 'Error',
            'databaseSize': 'Error',
            'error_logs': [],
            'tenant_alerts': [],
            'averageResponseTime': 'Error',
            'apiErrorRate': 'Error', 
            'totalAPIRequests': 'Error'
        }
    
def get_database_performance_metrics(hours=24):
    try:
        from datetime import datetime, timedelta, timezone
        SGT = timezone(timedelta(hours=8))
        cutoff_time = datetime.now(SGT) - timedelta(hours=hours)
        audit_metrics = SysLogService.getSysStats(filters={
            'start_date': cutoff_time
        })
        api_actions = [
            'FILE_UPLOAD', 'FILE_DOWNLOAD', 'FILE_DELETE', 'FILE_RENAME',
            'SHARE_LINK_GENERATED', 'DLP_SCAN', 'LOGIN_ATTEMPT'
        ]
        
        try:
            recent_logs = SysLogService.getSysLogs(
                limit=1000,
                filters={'start_date': cutoff_time}
            )
            api_requests = 0
            api_errors = 0
            response_times = []
            for log in recent_logs.get('logs', []):
                action_type = log.get('action_type', '')
                if any(action in action_type for action in api_actions):
                    api_requests += 1
                    if not log.get('success', True):
                        api_errors += 1
                    if 'UPLOAD' in action_type:
                        response_times.append(250)
                    elif 'DOWNLOAD' in action_type:
                        response_times.append(150)
                    elif 'DLP_SCAN' in action_type:
                        response_times.append(500)
                    else:
                        response_times.append(50)   
            avg_response = sum(response_times) / len(response_times) if response_times else 0
            error_rate = (api_errors / api_requests * 100) if api_requests > 0 else 0
            return {
                'database_api_requests': api_requests,
                'database_api_errors': api_errors,
                'database_error_rate': f"{error_rate:.1f}%",
                'database_avg_response': f"{avg_response:.1f}ms",
                'total_events_24h': audit_metrics.get('total_events', 0)
            }
        except Exception as e:
            print(f"Error analyzing audit logs: {e}")
            return {}
    except Exception as e:
        print(f"Error getting database performance metrics: {e}")
        return {}

@csrf.exempt
def checkDatabaseHealth():
    try:
        from sqlalchemy import create_engine, text
        import time
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if not db_uri:
            return {
                'status': 0,
                'message': 'Database URI not configured',
                'details': {},
                'metrics': {}
            }
        engine = create_engine(db_uri, pool_timeout=5, pool_recycle=300)
        start_time = time.time()
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1 as health_check"))
            health_result = result.fetchone()
            end_time = time.time()
            query_latency_ms = round((end_time - start_time) * 1000, 2)
            if health_result and health_result[0] == 1:
                db_info = connection.execute(text("""
                    SELECT 
                        version() as postgres_version,
                        current_database() as database_name,
                        current_user as current_user,
                        inet_server_addr() as server_ip
                """)).fetchone()
                try:
                    conn_info = connection.execute(text("""
                        SELECT count(*) as active_connections
                        FROM pg_stat_activity 
                        WHERE state = 'active'
                    """)).fetchone()
                    active_connections = conn_info[0] if conn_info else 0
                except:
                    active_connections = "Permission denied"
                try:
                    size_info = connection.execute(text("""
                        SELECT pg_size_pretty(pg_database_size(current_database())) as db_size
                    """)).fetchone()
                    database_size = size_info[0] if size_info else "Unknown"
                except:
                    database_size = "Permission denied"
                try:
                    perf_info = connection.execute(text("""
                        SELECT 
                            (SELECT count(*) FROM pg_stat_activity WHERE state != 'idle') as active_queries,
                            (SELECT count(*) FROM pg_stat_activity) as total_connections,
                            (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle') as idle_connections
                    """)).fetchone()
                    active_queries = perf_info[0] if perf_info else 0
                    total_connections = perf_info[1] if perf_info else 0
                    idle_connections = perf_info[2] if perf_info else 0
                except:
                    active_queries = 0
                    total_connections = 0
                    idle_connections = 0
                if query_latency_ms < 1200:
                    health_percentage = 100
                elif query_latency_ms < 1300:
                    health_percentage = 90
                elif query_latency_ms < 1400:
                    health_percentage = 75
                elif query_latency_ms < 1600:
                    health_percentage = 50
                else:
                    health_percentage = 25
                raw_server_ip = db_info[3] if db_info else "Unknown"
                if raw_server_ip and raw_server_ip != "Unknown":
                    try:
                        ip_parts = raw_server_ip.split('.')
                        if len(ip_parts) == 4:
                            masked_ip = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx"
                        else:
                            masked_ip = "xxx.xxx.xxx.xxx"
                    except:
                        masked_ip = "xxx.xxx.xxx.xxx"
                else:
                    masked_ip = "xxx.xxx.xxx.xxx"
                return {
                    'status': 1,
                    'health_percentage': health_percentage,
                    'message': 'Database connection successful',
                    'details': {
                        'postgres_version': db_info[0] if db_info else "Unknown",
                        'database_name': db_info[1] if db_info else "Unknown", 
                        'current_user': db_info[2] if db_info else "Unknown",
                        'server_ip': masked_ip,
                        'provider': 'Supabase PostgreSQL'
                    },
                    'metrics': {
                        'query_latency_ms': query_latency_ms,
                        'active_connections': active_connections,
                        'total_connections': total_connections,
                        'idle_connections': idle_connections,
                        'active_queries': active_queries,
                        'database_size': database_size
                    }
                }
            else:
                return {
                    'status': 0,
                    'health_percentage': 0,
                    'message': 'Database query failed',
                    'details': {},
                    'metrics': {}
                }
                
    except Exception as e:
        error_message = str(e)
        if "timeout" in error_message.lower():
            details = "Connection timeout - check Supabase connection limits"
        elif "authentication" in error_message.lower():
            details = "Authentication failed - check credentials"
        elif "ssl" in error_message.lower():
            details = "SSL connection issue - Supabase requires SSL"
        elif "host" in error_message.lower():
            details = "Host connection issue - check Supabase URL"
        else:
            details = f"Database error: {error_message}"
        return {
            'status': 0,
            'health_percentage': 0,
            'message': 'Database connection failed',
            'details': {'error': details},
            'metrics': {}
        }
    
@csrf.exempt
def checkAppHP():
    try:
        db_health = checkDatabaseHealth()
        database_status = db_health['status']
        app_health = 100
        try:
            import psutil
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            if memory.percent > 90 or cpu_percent > 90:
                system_health = 25
            elif memory.percent > 80 or cpu_percent > 80:
                system_health = 50
            elif memory.percent > 70 or cpu_percent > 70:
                system_health = 75
            else:
                system_health = 100
        except:
            system_health = 50 
            memory = None
            cpu_percent = None
        db_metrics = db_health.get('metrics', {})
        
        return {
            'systemStatus': 1 if system_health > 50 else 0,
            'databaseStatus': database_status,
            'appHP': 1,
            'system_health_percentage': system_health,
            'database_health_percentage': db_health.get('health_percentage', 0),
            'app_health_percentage': app_health,
            'webserverStatus': app_health,  
            'database_details': db_health.get('details', {}),
            'database_message': db_health.get('message', ''),
            'databaseQueryLatency': f"{db_metrics.get('query_latency_ms', 'Unknown')}ms",
            'active_db_connections': db_metrics.get('active_connections', 'Unknown'),
            'databaseSize': db_metrics.get('database_size', 'Unknown'),
            'total_db_connections': db_metrics.get('total_connections', 'Unknown'),
            'idle_db_connections': db_metrics.get('idle_connections', 'Unknown'),
            'active_queries': db_metrics.get('active_queries', 'Unknown'),
            'system_info': {
                'memory_percent': memory.percent if memory else 'Unknown',
                'cpu_percent': cpu_percent if cpu_percent else 'Unknown',
                'available_memory_gb': round(memory.available / (1024**3), 2) if memory else 'Unknown'
            },
            'averageResponseTime': '17ms',  
            'apiErrorRate': '0.4%',        
            'totalAPIRequests': '6776'     
        }
    except Exception as e:
        return {
            'systemStatus': 0,
            'databaseStatus': 0,
            'appHP': 1,
            'system_health_percentage': 0,
            'database_health_percentage': 0,
            'app_health_percentage': 50,
            'webserverStatus': 50,
            'error': str(e),
            'database_details': {},
            'database_message': f'System health check error: {str(e)}',
            'databaseQueryLatency': 'Error',
            'active_db_connections': 'Error',
            'databaseSize': 'Error'
        }

@csrf.exempt
def checkSystemHealth():
    try:
        webserverStatus = 100
        systemStatus = 100
        return {
            'systemStatus': systemStatus,
            'webserverStatus': webserverStatus
        }
    except Exception as e:
        print(f"System health check error: {str(e)}")
        return {
            'systemStatus': 0,
            'webserverStatus': 0
        }
    
def getRecentErrorLogs(limit=10, hours=24):
    try:
        from datetime import datetime, timedelta, timezone
        SGT = timezone(timedelta(hours=8))
        cutoff_time = datetime.now(SGT) - timedelta(hours=hours)
        error_logs = []
        try:
            system_error_result = SysLogService.getSysLogs(
                limit=limit//2,
                offset=0,
                filters={
                    'success': False,
                    'start_date': cutoff_time,
                    'tenant_id': 'SYSTEM' 
                }
            )
            system_errors = system_error_result.get('logs', [])
            for error in system_errors:
                error_logs.append({
                    'timestamp': error.get('created_at', datetime.now(SGT)), 
                    'code': 'SYS_' + str(error.get('id', '000')),
                    'description': error.get('action_description', 'System error'),
                    'category': error.get('action_category', 'SYSTEM'),
                    'severity': 'CRITICAL' if 'CRITICAL' in str(error.get('risk_level', '')) else 'HIGH',
                    'source': 'System Admin'
                })
        except Exception as e:
            print(f"Error fetching system admin logs: {e}")
        try:
            tenant_error_result = SysLogService.getSysLogs(
                limit=limit//2,
                offset=0,
                filters={
                    'success': False,
                    'start_date': cutoff_time
                }
            )
            tenant_errors = tenant_error_result.get('logs', [])
            for error in tenant_errors:
                if error.get('target_tenant_id') == 'SYSTEM':
                    continue
                tenant_id = error.get('target_tenant_id', 'Unknown')
                error_logs.append({
                    'timestamp': error.get('created_at', datetime.now(SGT)),
                    'code': f"T{tenant_id}_" + str(error.get('id', '000')),
                    'description': error.get('action_description', 'Tenant error'),
                    'category': error.get('action_category', 'TENANT'),
                    'severity': 'CRITICAL' if 'CRITICAL' in str(error.get('risk_level', '')) else 'HIGH',
                    'source': f"Tenant {tenant_id}"
                })
        except Exception as e:
            print(f"Error fetching tenant logs: {e}")
        db_health = checkDatabaseHealth()
        if db_health['status'] == 0:
            error_logs.append({
                'timestamp': datetime.now(SGT),
                'code': 'DB_001',
                'description': db_health.get('message', 'Database connection failed'),
                'category': 'DATABASE',
                'severity': 'CRITICAL',
                'source': 'Database Health Check'
            })
        try:
            recent_file_errors = getRecentFileErrors(hours=hours)
            error_logs.extend(recent_file_errors)
        except Exception as e:
            print(f"Error fetching file operation errors: {e}")
        try:
            last_scan_time = session.get('last_dlp_scan')
            if last_scan_time:
                if isinstance(last_scan_time, str):
                    last_scan = datetime.fromisoformat(last_scan_time)
                    if last_scan.tzinfo is None:
                        last_scan = last_scan.replace(tzinfo=timezone.utc).astimezone(SGT)
                else:
                    last_scan = last_scan_time
                    if last_scan.tzinfo is None:
                        last_scan = last_scan.replace(tzinfo=timezone.utc).astimezone(SGT)
                if (datetime.now(SGT) - last_scan).total_seconds() > 7200: 
                    error_logs.append({
                        'timestamp': datetime.now(SGT) - timedelta(hours=1),
                        'code': 'DLP_001',
                        'description': 'DLP scanning service may be offline - no recent scans detected',
                        'category': 'SECURITY',
                        'severity': 'HIGH',
                        'source': 'DLP Monitor'
                    })
        except Exception as e:
            print(f"Error checking DLP status: {e}")
        error_logs.sort(key=lambda x: x.get('timestamp', datetime.min.replace(tzinfo=SGT)), reverse=True)
        error_logs = error_logs[:limit]
        return error_logs
    except Exception as e:
        print(f"Error in getRecentErrorLogs: {e}")
        return [
            {
                'timestamp': datetime.now(SGT),
                'code': 'LOG_ERROR',
                'description': f'Failed to retrieve error logs: {str(e)}',
                'category': 'SYSTEM',
                'severity': 'HIGH',
                'source': 'Error Log System'
            }
        ]

def getRecentFileErrors(hours=24):
    try:
        from datetime import datetime, timedelta, timezone
        SGT = timezone(timedelta(hours=8))
        file_errors = []
        cutoff_time = datetime.now(SGT) - timedelta(hours=hours)
        temp_folder = app.config.get('PENDING_FOLDER', 'pending_uploads')
        
        if os.path.exists(temp_folder):
            try:
                abandoned_files = 0
                corrupted_files = 0
                for filename in os.listdir(temp_folder):
                    file_path = os.path.join(temp_folder, filename)
                    if os.path.isfile(file_path):
                        try:
                            file_created = datetime.fromtimestamp(os.path.getctime(file_path), tz=SGT)
                            file_age = datetime.now(SGT) - file_created  
                            if file_age.total_seconds() > 3600:
                                abandoned_files += 1
                            if os.path.getsize(file_path) == 0:
                                corrupted_files += 1
                        except Exception as e:
                            print(f"Error checking file {filename}: {e}")
                if abandoned_files > 0:
                    file_errors.append({
                        'timestamp': datetime.now(SGT) - timedelta(minutes=30),
                        'code': 'FILE_001',
                        'description': f'{abandoned_files} abandoned temporary upload files detected',
                        'category': 'FILE_MANAGEMENT',
                        'severity': 'MEDIUM',
                        'source': 'File Upload System'
                    })
                if corrupted_files > 0:
                    file_errors.append({
                        'timestamp': datetime.now(SGT) - timedelta(minutes=15),
                        'code': 'FILE_002',
                        'description': f'{corrupted_files} corrupted/empty files found in temp directory',
                        'category': 'FILE_MANAGEMENT',
                        'severity': 'HIGH',
                        'source': 'File Integrity Check'
                    })
            except Exception as e:
                file_errors.append({
                    'timestamp': datetime.now(SGT),
                    'code': 'FILE_003',
                    'description': f'Error scanning temp directory: {str(e)}',
                    'category': 'FILE_MANAGEMENT',
                    'severity': 'LOW',
                    'source': 'File System Scanner'
                })
        upload_base = app.config.get('UPLOAD_FOLDER', 'uploads')
        if os.path.exists(upload_base):
            try:
                for item in os.listdir(upload_base):
                    if item.startswith('tenant_'):
                        tenant_path = os.path.join(upload_base, item)
                        if os.path.isdir(tenant_path):
                            try:
                                test_file = os.path.join(tenant_path, '.write_test')
                                try:
                                    with open(test_file, 'w') as f:
                                        f.write('test')
                                    os.remove(test_file)
                                except PermissionError:
                                    file_errors.append({
                                        'timestamp': datetime.now(SGT),
                                        'code': 'FILE_004',
                                        'description': f'Write permission denied for {item}',
                                        'category': 'FILE_MANAGEMENT',
                                        'severity': 'HIGH',
                                        'source': 'Permission Check'
                                    })
                                try:
                                    total_size = 0
                                    file_count = 0
                                    for root, dirs, files in os.walk(tenant_path):
                                        for file in files:
                                            if not file.startswith('.'):
                                                file_path = os.path.join(root, file)
                                                if os.path.exists(file_path):
                                                    total_size += os.path.getsize(file_path)
                                                    file_count += 1
                                    if total_size > 1024**3:
                                        file_errors.append({
                                            'timestamp': datetime.now(SGT) - timedelta(minutes=5),
                                            'code': 'FILE_005',
                                            'description': f'{item} storage usage high: {total_size/(1024**3):.1f}GB',
                                            'category': 'FILE_MANAGEMENT',
                                            'severity': 'MEDIUM',
                                            'source': 'Storage Monitor'
                                        })
                                    if file_count > 1000:
                                        file_errors.append({
                                            'timestamp': datetime.now(SGT) - timedelta(minutes=10),
                                            'code': 'FILE_006',
                                            'description': f'{item} has excessive files: {file_count} files',
                                            'category': 'FILE_MANAGEMENT',
                                            'severity': 'MEDIUM',
                                            'source': 'File Count Monitor'
                                        })
                                except Exception as e:
                                    print(f"Error calculating size for {item}: {e}")
                            except Exception as e:
                                print(f"Error checking tenant directory {item}: {e}")
            except Exception as e:
                file_errors.append({
                    'timestamp': datetime.now(SGT),
                    'code': 'FILE_007',
                    'description': f'Error scanning upload directories: {str(e)}',
                    'category': 'FILE_MANAGEMENT',
                    'severity': 'MEDIUM',
                    'source': 'Directory Scanner'
                })
        try:
            failed_file_ops_result = SysLogService.getSysLogs(
                limit=50,
                offset=0,
                filters={
                    'success': False,
                    'category': 'FILE_MANAGEMENT',
                    'start_date': cutoff_time
                }
            )
            failed_file_ops = failed_file_ops_result.get('logs', [])
            error_groups = {}
            for op in failed_file_ops:
                action_type = op.get('action_type', 'UNKNOWN_FILE_ERROR')
                if action_type not in error_groups:
                    error_groups[action_type] = {
                        'count': 0,
                        'latest': op.get('created_at', datetime.now(SGT)),
                        'description': op.get('action_description', 'File operation failed')
                    }
                error_groups[action_type]['count'] += 1
            for action_type, data in error_groups.items():
                if data['count'] > 1:
                    file_errors.append({
                        'timestamp': data['latest'],
                        'code': 'AUDIT_' + action_type.replace('_', '')[:6],
                        'description': f"{data['count']} {action_type.lower().replace('_', ' ')} failures in last {hours}h",
                        'category': 'FILE_MANAGEMENT',
                        'severity': 'HIGH' if data['count'] > 10 else 'MEDIUM',
                        'source': 'Audit Log Analysis'
                    })
        except Exception as e:
            print(f"Error checking audit logs for file errors: {e}")
        try:
            metadata_file = FILE_METADATA_JSON  
            if os.path.exists(metadata_file):
                try:
                    import json
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    orphaned_count = 0
                    for tenant_key, files in metadata.items():
                        if tenant_key.startswith('tenant_'):
                            tenant_id = tenant_key.split('_')[1]
                            tenant_folder = get_tenant_upload_folder(tenant_id)
                            for filename in files.keys():
                                file_path = os.path.join(tenant_folder, filename)
                                if not os.path.exists(file_path):
                                    orphaned_count += 1
                    if orphaned_count > 0:
                        file_errors.append({
                            'timestamp': datetime.now(SGT) - timedelta(minutes=20),
                            'code': 'META_001',
                            'description': f'{orphaned_count} orphaned metadata entries found',
                            'category': 'FILE_MANAGEMENT',
                            'severity': 'MEDIUM',
                            'source': 'Metadata Integrity Check'
                        })
                except Exception as e:
                    file_errors.append({
                        'timestamp': datetime.now(SGT),
                        'code': 'META_002',
                        'description': f'Error reading metadata file: {str(e)}',
                        'category': 'FILE_MANAGEMENT',
                        'severity': 'MEDIUM',
                        'source': 'Metadata System'
                    })
        except Exception as e:
            print(f"Error checking metadata: {e}")
        return file_errors
    except Exception as e:
        return [{
            'timestamp': datetime.now(SGT),
            'code': 'FILE_SYSTEM_ERROR',
            'description': f'File error monitoring system failed: {str(e)}',
            'category': 'FILE_MANAGEMENT',
            'severity': 'HIGH',
            'source': 'File Error Monitor'
        }]

def getRecentTenantAlerts(limit=10):

    """coconut"""
    
    try:
        from datetime import datetime, timedelta, timezone
        SGT = timezone(timedelta(hours=8)) 
        tenant_alerts = []

        try:
            tenants_result = db.session.execute(text("SELECT id, company_name FROM tenants WHERE is_active = true")).fetchall()
            for tenant in tenants_result:
                tenant_id = tenant[0]
                company_name = tenant[1]
                try:
                    stats = get_tenant_stats(tenant_id)
                    total_events = stats.get('total_events', 0)
                    failed_events = stats.get('failed_events', 0)
                    if total_events > 0:
                        error_rate = (failed_events / total_events) * 100
                        if error_rate > 10:
                            tenant_alerts.append({
                                'tenant_id': tenant_id,
                                'company_name': company_name,
                                'status': 'Warning',
                                'cpu': f"{min(error_rate * 2, 100):.1f}",
                                'storage': f"{min(total_events / 10, 100):.1f}",
                                'errors': f"{error_rate:.1f}",
                                'description': f'High error rate detected: {error_rate:.1f}% failure rate',
                                'timestamp': datetime.now(SGT)
                            })
                        if total_events > 100:
                            tenant_alerts.append({
                                'tenant_id': tenant_id,
                                'company_name': company_name,
                                'status': 'Warning',
                                'cpu': '93',
                                'storage': '45',
                                'errors': '5.4',
                                'description': 'Bulk download pattern detected',
                                'timestamp': datetime.now(SGT) - timedelta(minutes=15)
                            })
                except Exception as e:
                    print(f"Error checking tenant {tenant_id}: {e}")
        except Exception as e:
            print(f"Error fetching tenant alerts: {e}")
        tenant_alerts.sort(key=lambda x: x.get('timestamp', datetime.min.replace(tzinfo=SGT)), reverse=True)
        return tenant_alerts[:limit]
    except Exception as e:
        print(f"Error in getRecentTenantAlerts: {e}")
        from datetime import datetime, timezone, timedelta
        SGT = timezone(timedelta(hours=8))
        return [
            {
                'tenant_id': 'ERR',
                'company_name': 'System Error',
                'status': 'Error',
                'cpu': '0',
                'storage': '0', 
                'errors': '100',
                'description': f'Failed to load tenant alerts: {str(e)}',
                'timestamp': datetime.now(SGT)
            }
        ]

@csrf.exempt
@app.route('/debug/syshpstatus')
def debug_status():
    try:
        health_metrics = getSystemHealth()
        
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'flask_status': 'Running',
            'dlp_scanner': 'Active' if dlpScanner else 'Inactive',
            'file_processor': 'Active' if fileProcessor else 'Inactive',
            'database_connection': 'Connected' if health_metrics.get('database_status', 0) > 0 else 'Failed',
            'system_health': health_metrics
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'status': 'Error'
        }), 500

@csrf.exempt
@app.route('/system-admin/audit-logs')
def system_admin_audit_dashboard():
    try:
        category = request.args.get('category')
        admin_email = request.args.get('admin_email')
        start_date = request.args.get('start_date')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        filters = {'tenant_id': 'SYSTEM'}  
        if category:
            filters['category'] = category
        if admin_email:
            filters['admin_email'] = admin_email
        if start_date:
            filters['start_date'] = datetime.fromisoformat(start_date)
        offset = (page - 1) * per_page
        result = SysLogService.getSysLogs(
            limit=per_page, 
            offset=offset, 
            filters=filters
        )
        stats = SysLogService.getSysStats(filters)
        SysLogService.logTheEvent(
            action_type='SYSTEM_ADMIN_LOGIN',
            description="System admin accessed audit logs dashboard"
        )
        return render_template('SuperAdmin/auditlogs.html',
                             logs=result['logs'],
                             total_count=result['total_count'],
                             has_more=result['has_more'],
                             current_page=page,
                             per_page=per_page,
                             stats=stats,
                             categories=SysLogService.CATEGORIES,
                             action_types=SysLogService.ACTION_TYPES)
    except Exception as e:
        SysLogService.logTheEvent(
            action_type='SYSTEM_ADMIN_ACCESS_DENIED',
            description=f"Failed to access system admin dashboard: {str(e)}",
            success=False
        )
        flash(f"Error loading system audit logs: {str(e)}", "error")
        return render_template('SuperAdmin/auditlogs.html', logs=[], total_count=0)

@app.route('/tenant/<int:tenant_id>/audit-logs')
def tenant_audit_logs(tenant_id):
    try:
        if str(session.get('tenant_id')) != str(tenant_id):
            return redirect(url_for('login'))

        page = int(request.args.get('page', 1))
        per_page = 20
        offset = (page - 1) * per_page
        filters = {'tenant_id': str(tenant_id)}
        if request.args.get('user_email'):
            filters['admin_email'] = request.args.get('user_email')
        if request.args.get('category'):
            filters['category'] = request.args.get('category')
        if request.args.get('start_date'):
            filters['start_date'] = request.args.get('start_date')
        result = SysLogService.getSysLogs(limit=per_page, offset=offset, filters=filters)
        stats = SysLogService.getSysStats(filters={'tenant_id': str(tenant_id)})
        tenant = Tenant.query.get(tenant_id)
        tenant_name = tenant.company_name if tenant else f'Tenant {tenant_id}'
        return render_template(
            'CompanyAdmin/tenant_auditlogs.html',
            logs=result['logs'],        
            stats=stats,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            categories=SysLogService.CATEGORIES,
            total_count=result['total_count'],
            current_page=page,
            per_page=per_page,
            has_more=result['has_more']
        )
    except Exception as e:
        print(f"Tenant audit log error: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Error loading audit logs: {str(e)}", "danger")
        return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))

def log_system_admin_event(action_type, description, category='GENERAL', **kwargs):
    try:
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))
        
        SysLogService.logSystemAdminEvent(
            action_type=action_type,
            description=description,
            admin_id = "SYSTEM",
            admin_email="System Admin",
            category=category,
            ip_address=ip_address,
            **kwargs
        )
    except Exception as e:
        current_app.logger.error(f"System admin audit logging error: {e}")

def log_tenant_event(action_type, description, category='GENERAL', tenant_id=None, **kwargs):
    try:
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))
        user_email = (
            kwargs.pop('user_email', None) or
            session.get('email') or 
            session.get('temp_user_email') or
            'Unknown'
        )
        tenant_id = tenant_id or session.get('tenant_id')
        if not tenant_id:
            raise ValueError("No tenant_id provided for tenant event")
        SysLogService.logTenantEvent(
            tenant_id=tenant_id,
            action_type=action_type,
            description=description,
            admin_email=user_email,
            category=category,
            ip_address=ip_address,
            **kwargs
        )
    except Exception as e:
        current_app.logger.error(f"Tenant audit logging error: {e}")

def log_audit_event(action_type, description, category='GENERAL', force_system=False, force_tenant=False, **kwargs):
    try:
        user_email = session.get('email') or session.get('temp_user_email') or 'Unknown'
        user_id = session.get('user_id') or 'Unknown'
        if 'user_email' not in kwargs:
            kwargs['user_email'] = user_email
        if 'user_id' not in kwargs:
            kwargs['user_id'] = user_id
        if force_system:
            return log_system_admin_event(action_type, description, category, **kwargs)
        if force_tenant:
            return log_tenant_event(action_type, description, category, **kwargs)
        
        user_type = session.get('user_type')
        tenant_id = session.get('tenant_id')
        current_route = request.endpoint or ''
        if (user_type == 'system_admin' or 
            current_route.startswith('system_') or 
            'SuperAdmin' in current_route or
            (not tenant_id and user_type != 'user')):
            return log_system_admin_event(action_type, description, category, **kwargs)
        elif tenant_id and (user_type in ['tenant_admin', 'user']):
            return log_tenant_event(action_type, description, category, tenant_id=tenant_id, **kwargs)
        else:
            return log_system_admin_event(action_type, f"[AUTO_DETECT] {description}", category, **kwargs)
            
    except Exception as e:
        current_app.logger.error(f"Audit logging error: {e}")

def get_current_user_info():
    return {
        'user_email': session.get('email', 'Unknown'),
        'user_id': session.get('user_id', 'Unknown'),
        'tenant_id': session.get('tenant_id'),
        'user_role': session.get('user_role', 'Unknown'),
        'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    }

def log_user_activity(action_type, description, category='USER_ACTIVITY', **kwargs):
    user_info = get_current_user_info()
    log_data = {**user_info, **kwargs}
    
    return log_audit_event(
        action_type=action_type,
        description=description,
        category=category,
        **log_data
    )

# Dashboard ===========================================================

@app.route('/superadmincontrolpanel')
def superadmincontrolpanel():
    SysLogService.logTheEvent(
        action_type='SYSTEM_DASHBOARD_ACCESS',
        description=f'System admin accessed control panel',
        category='SYSTEM_ADMIN',
        admin_email=session.get('email'),
        success=True
    )
    return render_template('/SuperAdmin/superadmincontrolpanel.html')

@app.route('/system/dashboard')
def system_dashboard():
    if session.get('user_type') != 'superadmin':
        flash('Access denied. System admin privileges required.', 'error')
        return redirect(url_for('home'))

    SysLogService.logTheEvent(
        action_type='SYSTEM_DASHBOARD_ACCESS',
        description=f'System admin accessed monitoring dashboard',
        category='SYSTEM_ADMIN',
        admin_email=session.get('email'),
        success=True
    )
    
    return render_template('SuperAdmin/system_dashboard_redirect.html')

EVENTS_TOTAL = Counter('events_total', 'Total events', ['type', 'severity'])
CLIENT_DATABASES = Gauge('client_databases_total', 'Number of client databases', ['status'])
COMPLIANCE_SCORE = Gauge('compliance_score', 'System compliance score')

def update_real_metrics():
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        with MasterSessionLocal() as session:
            query = text("""
                SELECT 
                    COUNT(CASE WHEN action_type LIKE '%LOGIN%' AND success = true THEN 1 END) as successful_logins,
                    COUNT(CASE WHEN action_type LIKE '%LOGIN%' AND success = false THEN 1 END) as failed_logins,
                    COUNT(CASE WHEN action_type LIKE '%UPLOAD%' THEN 1 END) as file_uploads,
                    COUNT(CASE WHEN action_type LIKE '%DOWNLOAD%' THEN 1 END) as file_downloads,
                    COUNT(CASE WHEN action_type LIKE '%DLP%' THEN 1 END) as dlp_scans,
                    COUNT(CASE WHEN action_category = 'SECURITY' THEN 1 END) as security_events,
                    COUNT(CASE WHEN success = false THEN 1 END) as failed_operations,
                    COUNT(DISTINCT target_tenant_id) as active_tenants,
                    COUNT(*) as total_events
                FROM system_audit_logs 
                WHERE created_at >= :start_date AND created_at <= :end_date
            """)
            
            result = session.execute(query, {
                'start_date': start_date,
                'end_date': end_date
            }).fetchone()
            
            if result:
                EVENTS_TOTAL.labels(type='login_success', severity='info')._value._value = result.successful_logins
                EVENTS_TOTAL.labels(type='login_failed', severity='warning')._value._value = result.failed_logins
                EVENTS_TOTAL.labels(type='file_upload', severity='info')._value._value = result.file_uploads
                EVENTS_TOTAL.labels(type='file_download', severity='info')._value._value = result.file_downloads
                EVENTS_TOTAL.labels(type='dlp_scan', severity='info')._value._value = result.dlp_scans
                EVENTS_TOTAL.labels(type='security_event', severity='warning')._value._value = result.security_events
                
                CLIENT_DATABASES.labels(status='active').set(result.active_tenants or 0)
                
                success_rate = ((result.total_events - result.failed_operations) / result.total_events * 100) if result.total_events > 0 else 100
                COMPLIANCE_SCORE.set(success_rate)
                
                print(f"Updated metrics: {result.total_events} events, {success_rate:.1f}% compliance")
            else:
                CLIENT_DATABASES.labels(status='active').set(0)
                COMPLIANCE_SCORE.set(100)
                print("No audit data found, using defaults")
                
    except Exception as e:
        print(f"Error updating metrics: {e}")
        CLIENT_DATABASES.labels(status='active').set(0)
        COMPLIANCE_SCORE.set(0)

def background_metric_updater():
    while True:
        try:
            update_real_metrics()
            time.sleep(30)
        except Exception as e:
            print(f"Background metric updater error: {e}")
            time.sleep(30)

@app.route('/metrics')
def metrics():
    update_real_metrics()
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.route('/dashboard_data')
def dashboard_data():
    with MasterSessionLocal() as session:
        recent_events_query = text("""
            SELECT 
                created_at,
                admin_email,
                action_type,
                action_description,
                ip_address,
                success,
                target_tenant_id
            FROM system_audit_logs 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        
        events_result = session.execute(recent_events_query)
        
        real_events = []
        for event in events_result:
            real_events.append({
                'timestamp': event.created_at.strftime('%Y-%m-%d %H:%M') if event.created_at else 'Unknown',
                'user_id': event.admin_email or 'System',
                'action': event.action_type or 'UNKNOWN_ACTION',
                'details': event.action_description or 'No description',
                'ip': event.ip_address or 'Unknown IP',
                'success': event.success,
                'tenant': event.target_tenant_id or 'System'
            })
        
        tenant_query = text("""
            SELECT 
                target_tenant_id,
                COUNT(*) as activity_count,
                MAX(created_at) as last_activity,
                ROUND(AVG(CASE WHEN success THEN 100.0 ELSE 0.0 END), 1) as success_rate
            FROM system_audit_logs 
            WHERE created_at >= NOW() - INTERVAL '7 days'
            AND target_tenant_id IS NOT NULL
            GROUP BY target_tenant_id
            ORDER BY activity_count DESC
        """)
        
        tenant_result = session.execute(tenant_query)
        
        client_databases = []
        for tenant in tenant_result:
            status = 'Active' if tenant.success_rate > 90 else 'Warning' if tenant.success_rate > 70 else 'Critical'
            
            client_databases.append({
                'name': f'Tenant {tenant.target_tenant_id}',
                'status': status,
                'last_backup': tenant.last_activity.strftime('%Y-%m-%d') if tenant.last_activity else 'No Activity',
                'compliance': f'{tenant.success_rate}% Success Rate',
                'activity_count': tenant.activity_count
            })
        
        return jsonify({
            'client_databases': client_databases,
            'events': real_events,
            'system_status': {
                'overall': 'Healthy' if len([e for e in real_events if e.get('success', True)]) > len(real_events) * 0.8 else 'Warning',
                'dlp_status': 'Active' if any('DLP' in e['action'] for e in real_events) else 'Idle',
                'last_scan': datetime.now().strftime('%m-%d-%Y %H:%M:%S'),
                'total_events_today': len([e for e in real_events if datetime.now().date().strftime('%Y-%m-%d') in e['timestamp']])
            }
        })


if __name__ == "__main__":
# Just comment if it doesnt work
    try:
        update_real_metrics()
        print("Prometheus metrics initialized")
    except Exception as e:
        print(f"Could not initialize metrics: {e}")
    try:
        updater_thread = threading.Thread(target=background_metric_updater, daemon=True)
        updater_thread.start()
        print("Started background metric updater")
    except Exception as e:
        print(f"Could not start background updater: {e}")
    print("Metrics available at: http://localhost:5000/metrics")
    print("Dashboard data at: http://localhost:5000/dashboard_data")
    print("Starting Flask app...")
#===============================


    app.run(debug=True, use_reloader=False)
