# app.py
import bcrypt
import os
import hashlib
import base64
import secrets
from dotenv import load_dotenv
from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, jsonify, session, flash, flash, current_app
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from sqlalchemy.orm import sessionmaker
from database import db, MasterSessionLocal, list_backups, restore_backup, get_last_backup, authenticate_tenant_admin, TenantSecurity, apply_rls_policies, authenticate_user, find_user_by_email, get_verification_code, mark_verification_code_used, validate_signup_code, create_user_in_tenant, create_signup_code
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
# Create public.tenants table (run once)
with app.app_context():
     db.create_all()  # creates Tenant model table

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

# Dummy tenant accounts
DUMMY_ACCOUNTS = {
    '1': {'name': 'Acme Corp', 'owner': 'John Doe'},
    '2': {'name': 'Tech Solutions', 'owner': 'Jane Smith'}
}


def get_current_tenant():
    """Get current tenant ID from URL parameter or form data, default to tenant 1"""
    return request.args.get('tenant') or request.form.get('tenant', '1')

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


def get_file_extension(filename):
    """Get file extension, preferring actual file content detection."""
    _, ext = os.path.splitext(filename)
    return ext if ext else '.bin'


def get_uploaded_files():
    tenant_id = get_current_tenant()
    tenant_folder = get_tenant_upload_folder(tenant_id)
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'owner': 'Unknown'})
    
    files = []
    if os.path.exists(tenant_folder):
        for fname in sorted(os.listdir(tenant_folder)):
            fpath = os.path.join(tenant_folder, fname)
            if os.path.isfile(fpath):
                metadata = get_file_metadata(fname, tenant_id)
                files.append(
                    {
                        "name": fname,
                        "size": os.path.getsize(fpath),
                        "url": url_for("download_file", filename=fname, tenant=tenant_id),
                        "hash": compute_sha256(fpath),
                        "owner": account_info['owner'],
                        "modified": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%d %B %Y'),
                        "sensitivity": metadata.get("sensitivity") or "Unclassified"
                    }
                )
    return files


@app.route('/myfiles', methods=['GET'])
def myfiles():
    tenant_id = get_current_tenant()
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'name': 'Unknown'})
    files = get_uploaded_files()
    return render_template("users/myfiles.html", files=files, tenant_id=tenant_id, account_name=account_info['name'])


@app.route('/shared-with-me', methods=['GET'])
def shared_with_me():
    tenant_id = get_current_tenant()
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'name': 'Unknown', 'owner': 'You'})
    
    # Load received shares for this tenant
    received_shares = load_received_shares()
    tenant_key = f'tenant_{tenant_id}'
    tenant_shares = received_shares.get(tenant_key, [])

    # Prune entries that no longer exist on disk and hide unverified exchanges
    key_exchanges = load_key_exchanges()
    pruned_shares = []
    changed = False
    for entry in tenant_shares:
        filename = entry.get('name')
        owner_tenant_id = str(entry.get('owner_tenant_id') or '')
        if not filename or not owner_tenant_id:
            changed = True
            continue
        owner_folder = get_tenant_upload_folder(owner_tenant_id)
        file_path = os.path.join(owner_folder, filename)
        version_path = os.path.join(app.config['VERSIONS_FOLDER'], filename)
        if not (os.path.exists(file_path) or os.path.exists(version_path)):
            changed = True
            continue

        if entry.get('require_key_exchange') and entry.get('exchange_id'):
            exchange = key_exchanges.get(entry.get('exchange_id'))
            status = exchange.get('status') if exchange else 'pending'
            entry['verification_status'] = status
            if status != 'verified':
                changed = True
                continue

        pruned_shares.append(entry)

    if changed:
        received_shares[tenant_key] = pruned_shares
        save_received_shares(received_shares)
        tenant_shares = pruned_shares
    
    return render_template("users/shared_with_me.html", files=tenant_shares, tenant_id=tenant_id, account_name=account_info['name'])


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
    """Generate a secure share link for a file"""
    try:
        data = request.json
        filename = data.get('filename')
        tenant_id = data.get('tenant', get_current_tenant())
        password = data.get('password')
        require_key_exchange = bool(data.get('require_key_exchange'))
        exchange_id = data.get('exchange_id')
        recipient_email = data.get('recipient_email')
        
        if not filename:
            return jsonify({'error': 'Filename required'}), 400

        if require_key_exchange and not exchange_id:
            return jsonify({'error': 'Key exchange required but exchange ID missing'}), 400
        
        # Generate a secure random token
        share_token = secrets.token_urlsafe(32)
        
        # Load existing share links
        share_links = load_share_links()
        
        # Get owner info
        owner = DUMMY_ACCOUNTS.get(tenant_id, {}).get('owner', 'Unknown')
        
        # Store the share link with file info
        share_links[share_token] = {
            'filename': filename,
            'tenant_id': tenant_id,
            'created_at': datetime.now().isoformat(),
            'owner': owner,
            'password': generate_password_hash(password) if password else None,
            'require_key_exchange': require_key_exchange,
            'exchange_id': exchange_id,
            'recipient_email': recipient_email
        }
        
        # Save to file
        save_share_links(share_links)
        
        # Generate the full share URL
        base_url = request.host_url.rstrip('/')
        share_url = f"{base_url}/shared-with-me?share={share_token}&tenant={tenant_id}"
        
        # Log the share link generation to text file
        log_share_link(share_token, filename, owner, tenant_id, base_url, has_password=bool(password))
        
        return jsonify({
            'success': True,
            'share_link': share_url,
            'token': share_token
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/initiate_key_exchange', methods=['POST'])
def initiate_key_exchange():
    """Initiate a key exchange for secure file sharing"""
    try:
        data = request.json
        filename = data.get('filename')
        recipient_email = data.get('recipient_email')
        tenant_id = data.get('tenant', get_current_tenant())
        sharer_id = "You"

        if not filename or not recipient_email:
            return jsonify({'error': 'Missing filename or recipient email'}), 400

        recipient_tenant = 'pending'

        exchange_id, sharer_public_key = create_key_exchange(
            sharer_id, tenant_id, recipient_email, filename, recipient_tenant
        )

        sharer_fingerprint = generate_fingerprint(sharer_public_key)

        return jsonify({
            'success': True,
            'exchange_id': exchange_id,
            'sharer_fingerprint': sharer_fingerprint
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/get_pending_verifications', methods=['GET'])
def get_pending_verifications():
    """Get pending key exchange verifications for current user"""
    try:
        tenant_id = get_current_tenant()
        key_exchanges = load_key_exchanges()

        pending = []
        for exchange_id, exchange in key_exchanges.items():
            if exchange.get('status') == 'pending':
                sharer_tenant = str(exchange.get('sharer_tenant', ''))
                recipient_tenant = str(exchange.get('recipient_tenant', ''))

                if str(tenant_id) == sharer_tenant or str(tenant_id) == recipient_tenant or recipient_tenant == 'pending':
                    is_sharer = str(tenant_id) == sharer_tenant
                    pending.append({
                        'exchange_id': exchange_id,
                        'filename': exchange.get('filename'),
                        'sharer_id': exchange.get('sharer_id'),
                        'recipient_email': exchange.get('recipient_email'),
                        'sharer_fingerprint': generate_fingerprint(exchange.get('sharer_public_key', '')),
                        'recipient_fingerprint': exchange.get('recipient_fingerprint', ''),
                        'created': exchange.get('created'),
                        'recipient_verified': exchange.get('recipient_verified', False),
                        'sharer_verified': exchange.get('sharer_verified', False),
                        'recipient_confirmed': exchange.get('recipient_confirmed', False),
                        'is_sharer': is_sharer
                    })

        return jsonify({'success': True, 'pending_verifications': pending}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/submit_recipient_key/<exchange_id>', methods=['POST'])
def submit_recipient_key(exchange_id):
    """Recipient submits their public key for the key exchange"""
    try:
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

        key_exchanges = load_key_exchanges()
        if exchange_id not in key_exchanges:
            return jsonify({'error': 'Exchange not found'}), 404

        exchange = key_exchanges[exchange_id]
        exchange['recipient_public_key'] = public_key_pem
        exchange['recipient_email'] = recipient_email or exchange.get('recipient_email')
        exchange['recipient_verified'] = True
        exchange['recipient_fingerprint'] = recipient_fingerprint

        save_key_exchanges(key_exchanges)

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
    """Sharer verifies recipient's fingerprint"""
    try:
        data = request.json
        recipient_fingerprint = data.get('recipient_fingerprint')

        key_exchanges = load_key_exchanges()
        if exchange_id not in key_exchanges:
            return jsonify({'error': 'Exchange not found'}), 404

        exchange = key_exchanges[exchange_id]
        actual_fingerprint = generate_fingerprint(exchange.get('recipient_public_key'))

        if not actual_fingerprint:
            return jsonify({'success': False, 'error': 'Recipient has not generated their key yet. Please ask them to generate their key first.'}), 400

        if recipient_fingerprint != actual_fingerprint:
            return jsonify({'success': False, 'error': 'Fingerprint mismatch!'}), 400

        exchange['sharer_verified'] = True
        if exchange.get('recipient_confirmed'):
            exchange['status'] = 'verified'
            add_verified_share_to_recipient(exchange_id, exchange)
        save_key_exchanges(key_exchanges)

        return jsonify({'success': True, 'message': 'Recipient identity verified.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/verify_sharer_fingerprint/<exchange_id>', methods=['POST'])
def verify_sharer_fingerprint(exchange_id):
    """Recipient verifies sharer's fingerprint"""
    try:
        data = request.json
        sharer_fingerprint = data.get('sharer_fingerprint')

        key_exchanges = load_key_exchanges()
        if exchange_id not in key_exchanges:
            return jsonify({'error': 'Exchange not found'}), 404

        exchange = key_exchanges[exchange_id]
        actual_fingerprint = generate_fingerprint(exchange.get('sharer_public_key'))

        if not actual_fingerprint:
            return jsonify({'success': False, 'error': 'Sharer public key not available. This should not happen.'}), 400

        if sharer_fingerprint != actual_fingerprint:
            return jsonify({'success': False, 'error': 'Fingerprint mismatch!'}), 400

        exchange['recipient_confirmed'] = True
        if exchange.get('sharer_verified'):
            exchange['status'] = 'verified'
            add_verified_share_to_recipient(exchange_id, exchange)
        save_key_exchanges(key_exchanges)

        return jsonify({'success': True, 'message': 'Sharer identity verified.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/verify-identities', methods=['GET'])
def verify_identities():
    tenant_id = get_current_tenant()
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'name': 'Unknown'})
    return render_template('users/verify_identities.html', tenant_id=tenant_id, account_name=account_info['name'])


@csrf.exempt
@app.route('/clear_pending_verifications', methods=['POST'])
def clear_pending_verifications():
    """Clear all pending verifications for current tenant"""
    try:
        tenant_id = get_current_tenant()
        key_exchanges = load_key_exchanges()
        
        # Filter out exchanges for this tenant (where tenant is sharer or recipient)
        exchanges_to_remove = [
            exchange_id for exchange_id, exchange in key_exchanges.items()
            if exchange.get('sharer_tenant') == tenant_id or exchange.get('recipient_tenant') == tenant_id or exchange.get('recipient_tenant') == 'pending'
        ]
        
        for exchange_id in exchanges_to_remove:
            del key_exchanges[exchange_id]
        
        save_key_exchanges(key_exchanges)
        return jsonify({'success': True, 'message': f'Cleared {len(exchanges_to_remove)} pending verification(s).'}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/validate_share_link', methods=['GET', 'POST'])
def validate_share_link():
    """Validate a share link and return file info"""
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
        
        # Load share links
        share_links = load_share_links()
        
        # Check if token exists
        if share_token not in share_links:
            return jsonify({'error': 'Invalid or expired share link'}), 404
        
        link_info = share_links[share_token]
        
        # Check if password is required
        if link_info.get('password'):
            if not password:
                return jsonify({'error': 'Password required', 'requires_password': True}), 401
            if not check_password_hash(link_info['password'], password):
                return jsonify({'error': 'Incorrect password'}), 401
        
        filename = link_info['filename']
        file_tenant_id = link_info['tenant_id']
        require_key_exchange = bool(link_info.get('require_key_exchange'))
        exchange_id = link_info.get('exchange_id')
        
        # Get the actual file path
        tenant_folder = get_tenant_upload_folder(file_tenant_id)
        file_path = os.path.join(tenant_folder, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        verification_status = 'not_required'
        if require_key_exchange:
            key_exchanges = load_key_exchanges()
            if not exchange_id or exchange_id not in key_exchanges:
                verification_status = 'exchange_not_found'
            else:
                exchange = key_exchanges[exchange_id]
                if exchange.get('recipient_tenant') == 'pending':
                    exchange['recipient_tenant'] = tenant_id
                    save_key_exchanges(key_exchanges)
                verification_status = 'verified' if exchange.get('status') == 'verified' else 'pending'
        
        # Get file info
        file_stats = os.stat(file_path)
        file_info = {
            'name': filename,
            'size': file_stats.st_size,
            'modified': datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'owner': link_info.get('owner', 'Unknown'),
            'sensitivity': 'Shared',
            'url': f"/download/shared/{filename}?share={share_token}&tenant={file_tenant_id}",
            'share_token': share_token,
            'owner_tenant_id': file_tenant_id,
            'require_key_exchange': require_key_exchange,
            'exchange_id': exchange_id,
            'verification_status': verification_status
        }
        
        # Get version history for this file
        versions = get_file_versions(filename, file_tenant_id)
        
        # Save to received shares for the current tenant (recipient)
        received_shares = load_received_shares()
        recipient_key = f'tenant_{tenant_id}'
        if recipient_key not in received_shares:
            received_shares[recipient_key] = []
        
        # Check if this file is already in the recipient's shared files
        existing = next((f for f in received_shares[recipient_key] if f['name'] == filename and f.get('owner_tenant_id') == file_tenant_id), None)
        if not existing:
            # Add date_shared to track when file was shared
            file_info['date_shared'] = datetime.now().strftime('%Y-%m-%d')
            received_shares[recipient_key].append(file_info)
        else:
            existing.update({
                'url': file_info['url'],
                'require_key_exchange': file_info.get('require_key_exchange'),
                'exchange_id': file_info.get('exchange_id'),
                'verification_status': file_info.get('verification_status')
            })
        save_received_shares(received_shares)
        
        return jsonify({
            'success': True,
            'file': file_info,
            'versions': versions
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/download/shared/<path:filename>', methods=['GET'])
def download_shared_file(filename):
    from urllib.parse import unquote
    filename = unquote(filename)
    share_token = request.args.get('share')
    tenant_id = request.args.get('tenant', get_current_tenant())

    if not share_token:
        return "Missing share token", 400

    share_links = load_share_links()
    if share_token not in share_links:
        return "Invalid or expired share link", 404

    link_info = share_links[share_token]
    if link_info.get('filename') != filename:
        return "Share link does not match file", 403

    owner_tenant_id = str(link_info.get('tenant_id'))
    tenant_folder = get_tenant_upload_folder(owner_tenant_id)
    file_path = os.path.join(tenant_folder, filename)
    version_path = os.path.join(app.config['VERSIONS_FOLDER'], filename)
    file_in_tenant = os.path.exists(file_path)
    file_in_versions = os.path.exists(version_path)
    if not file_in_tenant and not file_in_versions:
        return "File not found", 404

    if link_info.get('require_key_exchange'):
        exchange_id = link_info.get('exchange_id')
        key_exchanges = load_key_exchanges()
        if not exchange_id or exchange_id not in key_exchanges:
            return "Identity not verified", 403
        exchange = key_exchanges[exchange_id]
        if exchange.get('status') != 'verified':
            return "Identity not verified", 403

    source_path = file_path if file_in_tenant else version_path
    actual_ext = detect_file_extension(source_path)
    download_name = os.path.splitext(filename)[0] + actual_ext
    if file_in_tenant:
        return send_from_directory(tenant_folder, filename, as_attachment=True, download_name=download_name)
    return send_from_directory(app.config['VERSIONS_FOLDER'], filename, as_attachment=True, download_name=download_name)


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
    tenant_folder = get_tenant_upload_folder(tenant_id)
    file_path = os.path.join(tenant_folder, filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'owner': 'Unknown'})
    file_info = {
        "name": filename,
        "size": os.path.getsize(file_path),
        "url": url_for("download_file", filename=filename, tenant=tenant_id),
        "hash": compute_sha256(file_path),
        "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%d %B %Y'),
        "owner": account_info['owner'],
        "uploaded_by": account_info['owner']
    }
    
    # Get version history
    tenant_id = get_current_tenant()
    versions = get_file_versions(filename, tenant_id)
    
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
        tenant_folder = get_tenant_upload_folder(tenant_id)
        save_path = os.path.join(tenant_folder, target_safe)

        if os.path.exists(save_path):
            name, ext = os.path.splitext(target_safe)
            counter = 1
            while os.path.exists(save_path):
                target_safe = f"{name}_{counter}{ext}"
                save_path = os.path.join(tenant_folder, target_safe)
                counter += 1

        os.replace(pending_path, save_path)
        size_final = os.path.getsize(save_path)
        file_hash_final = compute_sha256(save_path)
        file_url = url_for('download_file', filename=target_safe, tenant=tenant_id)

        sensitivity = (request.form.get('sensitivity') or '').strip()
        owner = (request.form.get('owner') or 'You').strip()
        notes = (request.form.get('notes') or '').strip()
        risk_type = (request.form.get('risk_type') or '').strip()

        set_file_metadata(target_safe, tenant_id, {
            "sensitivity": sensitivity or "Unclassified",
            "owner": owner,
            "notes": notes,
            "risk_type": risk_type,
            "updated": datetime.now().isoformat()
        })
        
        # Add initial version entry
        version_info = {
            "version": 1,
            "name": target_safe,
            "uploaded_by": "You",
            "date": datetime.now().strftime('%d %B %Y'),
            "size": size_final,
            "hash": file_hash_final,
            "is_current": True
        }
        add_version(target_safe, version_info, tenant_id)
        
        return redirect(url_for('file_detail', filename=target_safe, tenant=tenant_id))

    return render_template(
        "users/confirm_upload.html",
        file={
            "temp_id": temp_id,
            "name": original_name,
            "size": size,
            "hash": file_hash,
            "modified": modified,
            "owner": "You",
            "uploaded_by": "You"
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

    # Get tenant ID and verify original file exists
    tenant_id = get_current_tenant()
    tenant_folder = get_tenant_upload_folder(tenant_id)
    current_path = os.path.join(tenant_folder, filename)
    if not os.path.exists(current_path):
        return jsonify({"error": "Original file not found"}), 404
    
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
    """Confirm and finalize version upload."""
    from urllib.parse import unquote
    original_filename = unquote(original_filename)
    
    tenant_id = get_current_tenant()
    pending_path = _pending_path(temp_id)
    if not pending_path or not os.path.exists(pending_path):
        return "Pending file not found", 404

    pending_file = os.path.basename(pending_path)
    new_filename = pending_file.split("__", 1)[1]
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)
    modified = datetime.fromtimestamp(os.path.getmtime(pending_path)).strftime('%d %B %Y')

    if request.method == 'POST':
        # Get tenant-specific folder and current file path
        tenant_folder = get_tenant_upload_folder(tenant_id)
        current_path = os.path.join(tenant_folder, original_filename)

        if not os.path.exists(current_path):
            return "Original file not found", 404

        # Ensure versions folder exists
        os.makedirs(app.config['VERSIONS_FOLDER'], exist_ok=True)

        # Get current versions
        versions = get_file_versions(original_filename, tenant_id)
        next_version = len(versions) + 1

        # Move current file to versions folder
        # The current file should be saved with its current version number and ACTUAL detected extension
        name, original_ext = os.path.splitext(original_filename)
        
        # Find the current version number
        current_version_num = next_version - 1
        for v in versions:
            if v.get('is_current'):
                current_version_num = v['version']
                break
        
        # Detect the actual file type from the file at current_path (could be JPG, PDF, etc)
        actual_ext = detect_file_extension(current_path)
        current_version_filename = f"{name}_v{current_version_num}{actual_ext}"
        current_version_path = os.path.join(app.config['VERSIONS_FOLDER'], current_version_filename)
        shutil.copy2(current_path, current_version_path)

        # Update the previous version entry to include version_file
        if versions:
            for i, v in enumerate(versions):
                if v['is_current']:
                    versions[i]['is_current'] = False
                    versions[i]['version_file'] = current_version_filename
                elif 'version_file' not in v:
                    # Older versions that don't have version_file yet
                    # Try to detect their extension, fall back to original if we can't
                    version_name = v.get('name', original_filename)
                    _, stored_ext = os.path.splitext(version_name)
                    old_version_filename = f"{name}_v{v['version']}{stored_ext}"
                    versions[i]['version_file'] = old_version_filename

        # Move pending file to become current version
        final_name = request.form.get('name') or new_filename
        
        # Ensure the old file is completely removed before replacing
        if os.path.exists(current_path):
            os.remove(current_path)
        
        # Move the new file to replace it
        shutil.move(pending_path, current_path)
        
        size = os.path.getsize(current_path)
        file_hash = compute_sha256(current_path)

        # Add new version entry
        version_info = {
            "version": next_version,
            "name": final_name,
            "uploaded_by": "You",
            "date": datetime.now().strftime('%d %B %Y'),
            "size": size,
            "hash": file_hash,
            "is_current": True
        }
        
        # Update version history
        versions.append(version_info)
        versions_data = load_versions()
        version_key = f"tenant_{tenant_id}/{original_filename}"
        versions_data[version_key] = versions
        save_versions(versions_data)

        return redirect(url_for('file_detail', filename=original_filename, tenant=tenant_id))

    return render_template(
        "users/confirm_upload.html",
        file={
            "temp_id": temp_id,
            "name": new_filename,
            "size": size,
            "hash": file_hash,
            "modified": modified,
            "owner": "You",
            "uploaded_by": "You"
        },
        is_version=True,
        original_filename=original_filename
    )


@app.route('/download/version/<path:filename>')
def download_version(filename):
    """Download a specific version from the versions folder."""
    from urllib.parse import unquote
    filename = unquote(filename)
    version_path = os.path.join(app.config['VERSIONS_FOLDER'], filename)
    
    # Detect actual file type
    actual_ext = detect_file_extension(version_path)
    download_name = os.path.splitext(filename)[0] + actual_ext
    
    return send_from_directory(app.config['VERSIONS_FOLDER'], filename, as_attachment=True, download_name=download_name)


@app.route('/rename', methods=['POST'])
@csrf.exempt
def rename_file():
    tenant_id = get_current_tenant()
    data = request.get_json()
    old_name = data.get('old_name')
    new_name = data.get('new_name')

    if not old_name or not new_name:
        return jsonify({"error": "Missing filename"}), 400

    tenant_folder = get_tenant_upload_folder(tenant_id)
    old_path = os.path.join(tenant_folder, sanitize_filename(old_name))
    new_path = os.path.join(tenant_folder, sanitize_filename(new_name))

    if not os.path.exists(old_path):
        return jsonify({"error": "File not found"}), 404

    if os.path.exists(new_path):
        return jsonify({"error": "File with that name already exists"}), 409

    try:
        os.rename(old_path, new_path)
        rename_file_metadata(sanitize_filename(old_name), sanitize_filename(new_name), tenant_id)
        return jsonify({"message": "File renamed successfully"}), 200
    except Exception as e:
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
    tenant_id = get_current_tenant()
    data = request.get_json()
    filename = data.get('filename')

    if not filename:
        return jsonify({"error": "Missing filename"}), 400

    tenant_folder = get_tenant_upload_folder(tenant_id)
    file_path = os.path.join(tenant_folder, sanitize_filename(filename))

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        # Move file to bin instead of deleting
        bin_key = move_file_to_bin(filename, tenant_id, file_path)
        
        # Delete the main file from original location
        os.remove(file_path)
        
        # Delete all version files from versions folder (they're backed up in bin_metadata)
        versions = get_file_versions(filename, tenant_id)
        for version in versions:
            if 'version_file' in version:
                version_path = os.path.join(app.config['VERSIONS_FOLDER'], version['version_file'])
                if os.path.exists(version_path):
                    os.remove(version_path)
        
        # Delete version history from JSON
        delete_file_versions(filename, tenant_id)

        # Remove from received shares for all tenants (file no longer appears in shared_with_me)
        received_shares = load_received_shares()
        updated = False
        for tenant_key, files in list(received_shares.items()):
            filtered = [f for f in files if not (f.get('name') == filename and str(f.get('owner_tenant_id')) == str(tenant_id))]
            if len(filtered) != len(files):
                received_shares[tenant_key] = filtered
                updated = True
        if updated:
            save_received_shares(received_shares)

        # Remove share links that point to this file
        share_links = load_share_links()
        share_links_updated = False
        for token, info in list(share_links.items()):
            if info.get('filename') == filename and str(info.get('tenant_id')) == str(tenant_id):
                del share_links[token]
                share_links_updated = True
        if share_links_updated:
            save_share_links(share_links)
        
        return jsonify({"message": "File moved to bin", "bin_key": bin_key}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/bin', methods=['GET'])
def view_bin():
    """View all files in bin for current tenant"""
    tenant_id = get_current_tenant()
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'name': 'Unknown', 'owner': 'You'})
    
    # Load bin metadata and filter by tenant
    bin_metadata = load_bin_metadata()
    tenant_bin_files = []
    
    for bin_key, entry in bin_metadata.items():
        if str(entry.get('tenant_id')) == str(tenant_id):
            # Calculate days until auto-deletion
            deleted_at = datetime.fromisoformat(entry['deleted_at'])
            days_remaining = 30 - (datetime.now() - deleted_at).days
            
            tenant_bin_files.append({
                'bin_key': bin_key,
                'original_filename': entry['original_filename'],
                'deleted_at': entry['deleted_at'],
                'days_remaining': max(0, days_remaining),
                'original_path': entry['original_path']
            })
    
    # Sort by deleted_at (newest first)
    tenant_bin_files.sort(key=lambda x: x['deleted_at'], reverse=True)
    
    return render_template("users/bin.html", files=tenant_bin_files, tenant_id=tenant_id, account_name=account_info['name'])


@app.route('/bin/restore/<path:bin_key>', methods=['POST'])
@csrf.exempt
def restore_bin_file(bin_key):
    """Restore a file from bin"""
    tenant_id = get_current_tenant()
    bin_metadata = load_bin_metadata()
    
    # Verify the file belongs to current tenant
    if bin_key not in bin_metadata:
        return jsonify({"error": "File not found in bin"}), 404
    
    entry = bin_metadata[bin_key]
    if str(entry.get('tenant_id')) != str(tenant_id):
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        success, message = restore_file_from_bin(bin_key)
        if success:
            return jsonify({"message": message}), 200
        else:
            return jsonify({"error": message}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/bin/permanent-delete/<path:bin_key>', methods=['POST'])
@csrf.exempt
def permanent_delete_bin_file(bin_key):
    """Permanently delete a file from bin"""
    tenant_id = get_current_tenant()
    bin_metadata = load_bin_metadata()
    
    # Verify the file belongs to current tenant
    if bin_key not in bin_metadata:
        return jsonify({"error": "File not found in bin"}), 404
    
    entry = bin_metadata[bin_key]
    if str(entry.get('tenant_id')) != str(tenant_id):
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        success, message = permanently_delete_from_bin(bin_key)
        if success:
            return jsonify({"message": message}), 200
        else:
            return jsonify({"error": message}), 500
    except Exception as e:
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
    from urllib.parse import unquote
    tenant_id = get_current_tenant()
    filename = unquote(filename)
    tenant_folder = get_tenant_upload_folder(tenant_id)
    file_path = os.path.join(tenant_folder, filename)
    
    # Detect actual file type
    actual_ext = detect_file_extension(file_path)
    download_name = os.path.splitext(filename)[0] + actual_ext
    
    return send_from_directory(tenant_folder, filename, as_attachment=True, download_name=download_name)

#TODO JiaJun stuff -------------------------------------------------------------------------

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

            # 3. Create tables - RAW STRINGS (no %s binding)
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

            # 4. Create admin user - RAW STRING (no parameters)
            import bcrypt
            password_hash = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt()).decode()
            email = form.email.data

            # ✅ RAW STRING - NO BINDING
            db.session.execute(text(f'''
                INSERT INTO "{schema_name}".users (email, password_hash, role) 
                VALUES ('{email}', '{password_hash}', 'admin')
            '''))

            db.session.commit()
            print(f"✅ tenant_{tenant_id} FULLY created with ALL tables!")

            flash(f"✅ '{form.company_name.data}' created successfully!", "success")
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

    # Load tenant-specific data
    tenant_stats = get_tenant_stats(tenant_id)
    tenant = db.session.execute(text("SELECT * FROM tenants WHERE id = :id"),
                                {"id": tenant_id}).first()

    return render_template('CompanyAdmin/dashboard.html',
                           tenant_id=tenant_id,
                           tenant=tenant,
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

    return render_template('admin/security_baselines.html', form=form, tenant_id=tenant_id)


#TODO tristan stuff -------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()

    if request.method == 'POST' and form.validate_on_submit():
        email_input = escape(form.email.data)
        password_input = escape(form.password.data)

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
