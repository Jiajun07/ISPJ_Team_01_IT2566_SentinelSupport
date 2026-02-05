# app.py
import bcrypt
import os
import hashlib
import base64
import secrets
from dotenv import load_dotenv
from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, jsonify, session, flash, flash, current_app, send_file
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from sqlalchemy.orm import sessionmaker
from database import (db, MasterSessionLocal, list_backups, restore_backup, get_last_backup, authenticate_tenant_admin,
                      TenantSecurity, apply_rls_policies, authenticate_user, find_user_by_email, get_verification_code,
                      mark_verification_code_used, validate_signup_code, create_user_in_tenant, create_signup_code, retention_cleanup,
                      store_file_in_db, add_file_version, get_file_from_db, get_all_files_for_tenant, 
                      get_file_versions_from_db, delete_file_from_db, restore_file_from_db, update_file_metadata,
                      create_share_link, get_share_link_by_token, update_share_link_access,
                      create_key_exchange, get_key_exchange, update_key_exchange, log_sharing_activity)
from tenant_service import get_db_name_for_company
from markupsafe import escape
from forms import Loginform, SignUpForm, ForgetPasswordForm, ResetPasswordForm, TenantDeactivateForm, CompanySignupForm, SecurityBaselineForm
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from DLPScannerModules.DLPScanner import DLPScanner
from DLPScannerModules.FileProcessor import FileProcessor
from datetime import datetime, timedelta
from sqlalchemy import text
import smtplib
import re
import json
from database import archive_tenant, get_tenant_stats, Tenant
import subprocess
from forms import BackupRecoveryForm
import zipfile
import shutil
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

configPath = os.path.join(app.root_path, "config", "keywords.json")
fileConfigPath = os.path.join(app.root_path, "config", "supportedfiles.json")

dlpScanner = DLPScanner(configPath)
fileProcessor = FileProcessor(fileConfigPath)

@app.route("/", methods=["GET", "POST"])
def home():
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
                if row[6]:  # require_key_exchange
                    if row[7]:  # exchange_id
                        exchange = get_key_exchange(tenant_id, row[7])
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
                    'owner': row[5],
                    'sensitivity': 'Shared',
                    'url': f"/download/shared/{row[1]}?share={row[4]}&tenant={tenant_id}",
                    'share_token': row[4],
                    'owner_tenant_id': tenant_id,
                    'require_key_exchange': row[6],
                    'exchange_id': row[7],
                    'verification_status': verification_status,
                    'date_shared': row[8].strftime('%Y-%m-%d') if row[8] else 'N/A'
                })
            
            return render_template("users/shared_with_me.html", files=tenant_shares, tenant_id=tenant_id, account_name=user_email)
    
    except Exception as e:
        print(f"❌ Error loading shared files: {e}")
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


def create_key_exchange(sharer_id, sharer_tenant, recipient_email, filename, recipient_tenant):
    """Create a key exchange request"""
    exchange_id = secrets.token_urlsafe(32)
    sharer_public_key = get_or_create_user_key(sharer_id, sharer_tenant)

    key_exchanges = load_key_exchanges()
    key_exchanges[exchange_id] = {
        "exchange_id": exchange_id,
        "sharer_id": sharer_id,
        "sharer_tenant": sharer_tenant,
        "sharer_public_key": sharer_public_key,
        "recipient_email": recipient_email,
        "recipient_tenant": recipient_tenant,
        "filename": filename,
        "status": "pending",
        "created": datetime.now().isoformat(),
        "recipient_verified": False,
        "sharer_verified": False,
        "recipient_confirmed": False,
        "recipient_public_key": None
    }
    save_key_exchanges(key_exchanges)

    return exchange_id, sharer_public_key


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
    
    return render_template("file_detail.html", file=file_info, versions=versions)


@app.route('/upload/temp', methods=['POST'])
@csrf.exempt
def upload_temp():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['file']
    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
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
        return "Pending file not found", 404

    pending_file = os.path.basename(pending_path)
    original_name = pending_file.split("__", 1)[1]
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)
    modified = datetime.fromtimestamp(os.path.getmtime(pending_path)).strftime('%d %B %Y')

    if request.method == 'POST':
        target_name = request.form.get('name') or original_name
        target_safe = sanitize_filename(target_name)
        
        # Read file data for database storage
        with open(pending_path, 'rb') as f:
            file_data = f.read()
        
        # Get metadata from form
        sensitivity = (request.form.get('sensitivity') or 'Public').strip()
        notes = (request.form.get('notes') or '').strip()
        risk_type = (request.form.get('risk_type') or '').strip()
        
        # Determine MIME type
        import mimetypes
        mime_type, _ = mimetypes.guess_type(target_safe)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # Store file in database
        result = store_file_in_db(
            tenant_id=tenant_id,
            file_data=file_data,
            filename=target_safe,
            owner_user_id=user_id,
            owner_email=user_email,
            file_hash=file_hash,
            mime_type=mime_type,
            sensitivity=sensitivity,
            classification=risk_type if risk_type else None,
            notes=notes
        )
        
        # Clean up pending file
        try:
            os.remove(pending_path)
        except:
            pass
        
        if result.get('success'):
            flash(f"✅ File '{target_safe}' uploaded successfully!", "success")
            return redirect(url_for('file_detail', filename=target_safe, tenant=tenant_id))
        else:
            flash(f"❌ Failed to upload file: {result.get('error')}", "danger")
            return redirect(url_for('myfiles'))

    return render_template(
        "users/confirm_upload.html",
        file={
            "temp_id": temp_id,
            "name": original_name,
            "size": size,
            "hash": file_hash,
            "modified": modified,
            "owner": user_email,
            "uploaded_by": user_email
        }
    )


@app.route('/scan/dlp/<temp_id>', methods=['GET'])
@csrf.exempt
def scan_dlp_temp_file(temp_id):
    """Scan a temporary file with DLP scanner and return sensitivity level."""
    pending_path = _pending_path(temp_id)
    if not pending_path or not os.path.exists(pending_path):
        return jsonify({"error": "File not found"}), 404
    
    try:
        pending_file = os.path.basename(pending_path)
        original_name = pending_file.split("__", 1)[1] if "__" in pending_file else pending_file

        with open(pending_path, "rb") as f:
            from werkzeug.datastructures import FileStorage
            file = FileStorage(stream=f, filename=original_name)

            if not fileProcessor.passedProcessing(file):
                return jsonify({"error": "File type not supported for DLP scanning."}), 400

            extracted_text = fileProcessor.readTextFromFile(file)

        if extracted_text:
            matches = dlpScanner.scan_text(extracted_text)
            risk_result = dlpScanner.calculateRisk(matches)

            risk_to_sensitivity = {
                "Critical": "Restricted",
                "High": "Confidential",
                "Medium": "Internal",
                "Low": "Public"
            }

            risk_level = risk_result.get("level", "Low")
            sensitivity = risk_to_sensitivity.get(risk_level, "Public")

            return jsonify({
                "success": True,
                "riskLevel": risk_level,
                "riskScore": risk_result.get("score", 0),
                "sensitivity": sensitivity,
                "totalMatches": risk_result.get("total_matches", 0),
                "severityBreakdown": risk_result.get("severity_breakdown", {})
            }), 200

        return jsonify({
            "success": True,
            "riskLevel": "Low",
            "riskScore": 0,
            "sensitivity": "Public",
            "totalMatches": 0,
            "severityBreakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        }), 200

    except Exception as e:
        return jsonify({"error": f"DLP scanning failed: {str(e)}"}), 500


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
        
        # Add new version to database
        result = add_file_version(
            tenant_id=tenant_id,
            document_id=document_id,
            file_data=file_data,
            filename=new_filename,
            uploaded_by=user_email,
            file_hash=file_hash,
            mime_type=mime_type
        )
        
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
        return jsonify({"error": "Missing filename"}), 400

    # Check if old file exists in database
    old_file = get_file_from_db(tenant_id, filename=old_name)
    if not old_file:
        return jsonify({"error": "File not found"}), 404

    # Check if new name already exists
    existing_new = get_file_from_db(tenant_id, filename=new_name)
    if existing_new:
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
        
        return jsonify({"message": "File renamed successfully"}), 200
    except Exception as e:
        print(f"❌ Error renaming file: {e}")
        try:
            session.rollback()
            session.close()
        except:
            pass
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
        return jsonify({"error": "Missing filename"}), 400

    # Get file from database
    file_record = get_file_from_db(tenant_id, filename=filename)
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    try:
        document_id = file_record['document_id']
        
        # Soft delete file in database (set is_deleted = TRUE)
        result = delete_file_from_db(tenant_id, document_id, soft_delete=True)
        
        if not result.get('success'):
            return jsonify({"error": "Failed to delete file"}), 500
        
        # TODO: Remove from shared_with_me for other users (update sharing table)
        # TODO: Deactivate share links pointing to this file (update file_sharing_links table)
        
        return jsonify({"message": "File moved to bin", "document_id": document_id}), 200
    except Exception as e:
        print(f"❌ Error deleting file: {e}")
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
    filename = unquote(filename)
    
    # Get file from database
    file_record = get_file_from_db(tenant_id, filename=filename)
    
    if not file_record:
        flash("File not found", "danger")
        return redirect(url_for('myfiles'))
    
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

# Schedule daily at 2AM
scheduler.add_job(
    daily_retention_cleanup,
    'cron',
    hour=2, minute=0,
    id='retention_cleanup',
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

            # 🔥 NEW: ADD SECURITY BASELINE (INSERT THESE 12 LINES)
            security = TenantSecurity(
                tenant_id=tenant_id,
                mfa_enabled=True,
                dlp_enabled=True,
                dlp_rule_count=3,
                data_retention_days=365,
                rls_enabled=True
            )
            db.session.add(security)
            db.session.commit()

            # Auto-apply RLS policies
            apply_rls_policies(tenant_id, security)
            print(f"✅ Security baseline + RLS applied to tenant_{tenant_id}")

            flash(f"✅ '{form.company_name.data}' created with security baselines!", "success")
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            print(f"❌ ERROR: {e}")
            flash(f"❌ Failed: {str(e)}", "danger")

    return render_template('company_signup.html', form=form)


@app.route('/tenant/<int:tenant_id>/dashboard')
def tenant_dashboard(tenant_id):
    if not session.get('tenant_id') or session['tenant_id'] != tenant_id:
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    # ✅ DYNAMIC TENANT DATA
    tenant = db.session.execute(
        text("SELECT * FROM tenants WHERE id = :id"), {"id": tenant_id}
    ).first()

    if not tenant:
        flash("Tenant not found.", "danger")
        return redirect(url_for('login'))

    # Company name, onboarding date, etc.
    company_name = tenant.company_name
    onboarding_date = tenant.created_at.strftime('%d/%m/%Y') if tenant.created_at else 'N/A'

    # Security baselines (from our new table)
    security = db.session.execute(
        text("SELECT * FROM tenant_security WHERE tenant_id = :id"), {"id": tenant_id}
    ).first()

    security_status = {
        'mfa_enabled': security.mfa_enabled if security else False,
        'dlp_enabled': security.dlp_enabled if security else False,
        'dlp_rule_count': security.dlp_rule_count if security else 0,
        'retention_days': security.data_retention_days if security else 365
    }

    # Tenant stats (users, documents, etc.)
    tenant_stats = {
        'total_users': db.session.execute(
            text(f'SELECT COUNT(*) FROM "tenant_{tenant_id}".users')
        ).scalar(),
        'total_documents': db.session.execute(
            text(f'SELECT COUNT(*) FROM "tenant_{tenant_id}".documents')
        ).scalar(),
        'backups': get_last_backup(tenant_id)  # Your existing function
    }

    return render_template('CompanyAdmin/dashboard.html',
                           tenant_id=tenant_id,
                           tenant=tenant,
                           company_name=company_name,
                           onboarding_date=onboarding_date,
                           security_status=security_status,
                           stats=tenant_stats)


@app.teardown_appcontext
def close_sessions(exception=None):
    if hasattr(g, 'tenant_session'):
        g.tenant_session.close()


@app.route("/documents")
def list_documents():
    session = get_tenant_session()
    rows = session.execute("SELECT id, file_path, classification FROM documents").fetchall()
    return {"documents": [dict(r) for r in rows]}

#Setting Backup and Recovery customization settings
@app.route('/admin/backup-recovery/<int:tenant_id>', methods=['GET', 'POST'])
def backup_recovery_page(tenant_id):
    """Backup & Recovery settings page"""
    tenant = Tenant.query.get_or_404(tenant_id)
    stats = get_tenant_stats(tenant_id)
    form = BackupRecoveryForm()

    last_backup = get_last_backup(tenant_id)  # Your function
    backups = list_backups(tenant_id)  # Your function

    if form.validate_on_submit():
        if form.backup_submit.data:
            # Create backup
            backup_file = backup_tenant(tenant_id)
            flash(f"Backup created: {backup_file}", "success")

        elif form.restore_submit.data:
            # Handle restore
            if form.backup_file.data:
                filename = secure_filename(form.backup_file.data.filename)
                restore_path = f"restores/{filename}"
                form.backup_file.data.save(restore_path)

                success = restore_backup(tenant_id, restore_path)
                if success:
                    flash("Restore completed successfully!", "success")
                else:
                    flash("Restore failed", "danger")

    return render_template('admin/backup_recovery.html',
                           tenant=tenant, stats=stats, form=form,
                           last_backup=last_backup, backups=backups)

# Deactivation of Tenant
@app.route('/admin/tenant/<int:tenant_id>/deactivate', methods=['GET', 'POST'])
def tenant_deactivate_page(tenant_id):
    """Tenant deactivation page with WTForms"""
    tenant = Tenant.query.get_or_404(tenant_id)
    stats = get_tenant_stats(tenant_id)
    form = TenantDeactivateForm()

    if form.validate_on_submit():
        # Form passed validation - process deactivation
        retention_days = int(form.retention_days.data)
        archive_date = datetime.now() + timedelta(days=retention_days)

        # Archive tenant
        archived = archive_tenant(tenant_id)

        if archived:
            # Create backup
            backup_file = backup_tenant(tenant_id)

            flash(f"""
                Tenant '{tenant.company_name}' archived successfully!<br>
                Retention period: {retention_days} days<br>
                Backup saved: {backup_file}
            """, "success")
            return redirect(url_for('admin_tenants'))
        else:
            flash("Failed to archive tenant", "danger")

    return render_template('admin/tenant_deactivate.html',
                           tenant=tenant, stats=stats, form=form)
def backup_tenant(tenant_id: int):
    """Create backup before archiving"""
    schema = f"tenant_{tenant_id}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"backups/{schema}_archive_{timestamp}.sql"

    cmd = [
        'pg_dump', '-h', 'localhost', '-p', '5432', '-U', 'postgres',
        f'--schema={schema}', '--no-owner', '--no-privileges',
        '-f', backup_file, 'sdsm_master'
    ]
    subprocess.run(cmd, env={"PGPASSWORD": "Jiajun07@@2025"})
    return backup_file


@app.route('/tenant/<int:tenant_id>/security-baselines', methods=['GET', 'POST'])
def tenant_security_baselines(tenant_id):
    if session.get('tenant_id') != tenant_id:
        return redirect(url_for('login'))

    tenant_security = TenantSecurity.query.filter_by(tenant_id=tenant_id).first()
    form = SecurityBaselineForm(obj=tenant_security)

    if form.validate_on_submit():
        if not tenant_security:
            tenant_security = TenantSecurity(tenant_id=tenant_id)

        # Update settings
        form.populate_obj(tenant_security)
        db.session.add(tenant_security)
        db.session.commit()

        # ✅ APPLY RLS POLICIES TO TENANT SCHEMA
        apply_rls_policies(tenant_id, tenant_security)

        flash("✅ Security baselines applied successfully!", "success")
        return redirect(url_for('tenant_dashboard', tenant_id=tenant_id))

    return render_template('CompanyAdmin/security_baselines.html', form=form, tenant_id=tenant_id)


#TODO tristan stuff -------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clean up any previous failed transactions
    try:
        db.session.rollback()
    except:
        pass
    
    form = Loginform()

    if request.method == 'POST' and form.validate_on_submit():
        email_input = escape(form.email.data)
        password_input = escape(form.password.data)

        try:
            # ✅ Try tenant admin login FIRST (if you have admin users)
            tenant_admin = authenticate_tenant_admin(email_input, password_input)
            if tenant_admin:
                print(f"✅ Admin login for tenant {tenant_admin['tenant_id']}")
                session['tenant_id'] = tenant_admin['tenant_id']
                session['tenant_schema'] = tenant_admin['schema_name']
                session['user_type'] = 'tenant_admin'
                session['company_name'] = tenant_admin['company_name']
                session['email'] = email_input
                session['temp_user_email'] = email_input
                session['needs_2fa'] = False  # Disable for now

                # Skip 2FA for debugging
                flash(f"✅ Admin login successful! tenant_{tenant_admin['tenant_id']}", "success")
                return redirect(url_for('tenant_dashboard', tenant_id=tenant_admin['tenant_id']))

            # ✅ Try regular user login across all tenants
            user = find_user_by_email(email_input)
            print(f"🔍 Found user in tenant: {user['tenant_id'] if user else 'NONE'}")

            if user:
                # Authenticate user in their tenant
                authenticated = authenticate_user(user['tenant_id'], email_input, password_input)
                
                if authenticated:
                    # ✅ Skip email verification check (no column exists)
                    print(f"✅ User login for {email_input} in tenant {authenticated['tenant_id']}")
                    session['tenant_id'] = authenticated['tenant_id']
                    session['tenant_schema'] = authenticated['schema_name']
                    session['user_id'] = authenticated['user_id']
                    session['user_type'] = 'user'
                    session['email'] = email_input
                    session['temp_user_email'] = email_input
                    session['needs_2fa'] = False  # Disable 2FA for now

                    # Direct login without 2FA (your tenant_14.users has no 2FA column)
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(hours=24)
                    flash(f"✅ Welcome back, {email_input}! (tenant_{authenticated['tenant_id']})", "success")
                    return redirect(url_for('myfiles'))

            flash("❌ Invalid email or password.", "danger")
            print(f"❌ Login failed for {email_input}")
        
        except Exception as e:
            db.session.rollback()
            print(f"❌ Login error: {e}")
            flash("❌ An error occurred during login. Please try again.", "danger")

    return render_template('login/login_page.html', form=form)


@app.route('/logout')
def logout():
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
            if session.get('user_type') == 'tenant_admin':
                # Tenant admin → Company dashboard
                return redirect(url_for('tenant_dashboard', tenant_id=session['tenant_id']))
            else:
                # Regular user → Their dashboard
                return redirect(url_for('dashboard'))  # Your existing dashboard

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

@app.route('/autodlp', methods=['GET', 'POST'])
@csrf.exempt
def autodlp():
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
    return render_template("SuperAdmin/autodlp.html",
                            decision=result.get('decision') if result else None,
                            reasons=result.get('reasons') if result else None,
                            filename=file.filename if 'file' in locals() and file.filename else None,
                            riskLevel=result.get('riskLevel') if result else None,
                            savedFilePath=savedFilePath)

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

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
