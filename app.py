# app.py
import os
import hashlib
import secrets
from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, jsonify, session
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from sqlalchemy.orm import sessionmaker
from database import create_tenant, db, MasterSessionLocal
from tenant_service import get_db_name_for_company
from markupsafe import escape
from forms import Loginform, SignUpForm, ForgetPasswordForm, ResetPasswordForm, TenantDeactivateForm
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

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

app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
# db.init_app(app)
# s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Create public.tenants table (run once)
# with app.app_context():
#     db.create_all()  # creates Tenant model table


# 🔑 TENANT CONTEXT (SCHEMA SWITCHING) - CRITICAL FIX
@app.before_request
def set_tenant_context():
    """Automatically switch to tenant schema based on company/session"""
    g.schema_name = None
    company_name = request.headers.get("X-Company-Name") or session.get('company_name')
    if company_name:
        schema_name = get_db_name_for_company(company_name)
        if schema_name:
            g.schema_name = schema_name
            g.company_name = company_name


app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads")
app.config['PENDING_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads_pending")
app.config['VERSIONS_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads", "versions")
VERSIONS_JSON = os.path.join(os.path.dirname(__file__), "file_versions.json")
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
                files.append(
                    {
                        "name": fname,
                        "size": os.path.getsize(fpath),
                        "url": url_for("download_file", filename=fname, tenant=tenant_id),
                        "hash": compute_sha256(fpath),
                        "owner": account_info['owner'],
                        "modified": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%d %B %Y'),
                        "sensitivity": "Confidential"
                    }
                )
    return files

def get_tenant_session():
    """Get session with search_path set to tenant schema"""
    if "tenant_session" not in g:
        if not g.schema_name:
            raise RuntimeError("No tenant context - login required")

        session = MasterSessionLocal()
        session.execute(text(f"SET search_path TO {g.schema_name}, public"))
        g.tenant_session = session
    return g.tenant_session


#@app.route("/login", methods=["GET", "POST"])
#def login():
#
#    return render_template("login.html")
#

@app.route('/myfiles', methods=['GET'])
def myfiles():
    tenant_id = get_current_tenant()
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'name': 'Unknown'})
    files = get_uploaded_files()
    return render_template("myfiles.html", files=files, tenant_id=tenant_id, account_name=account_info['name'])


@app.route('/shared-with-me', methods=['GET'])
def shared_with_me():
    tenant_id = get_current_tenant()
    account_info = DUMMY_ACCOUNTS.get(tenant_id, {'name': 'Unknown', 'owner': 'You'})
    
    # Load received shares for this tenant
    received_shares = load_received_shares()
    tenant_shares = received_shares.get(f'tenant_{tenant_id}', [])
    
    return render_template("shared_with_me.html", files=tenant_shares, tenant_id=tenant_id, account_name=account_info['name'])


# Share link storage (in production, use database)
SHARE_LINKS_FILE = os.path.join(os.path.dirname(__file__), "share_links.json")
SHARE_LINKS_LOG = os.path.join(os.path.dirname(__file__), "share_links_log.txt")
RECEIVED_SHARES_FILE = os.path.join(os.path.dirname(__file__), "received_shares.json")

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
        
        if not filename:
            return jsonify({'error': 'Filename required'}), 400
        
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
            'password': generate_password_hash(password) if password else None
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
        
        # Get the actual file path
        tenant_folder = get_tenant_upload_folder(file_tenant_id)
        file_path = os.path.join(tenant_folder, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Get file info
        file_stats = os.stat(file_path)
        file_info = {
            'name': filename,
            'size': file_stats.st_size,
            'modified': datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'owner': link_info.get('owner', 'Unknown'),
            'sensitivity': 'Shared',
            'url': f"/download/{filename}?tenant={file_tenant_id}",
            'share_token': share_token,
            'owner_tenant_id': file_tenant_id
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
            save_received_shares(received_shares)
        
        return jsonify({
            'success': True,
            'file': file_info,
            'versions': versions
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        "confirm_upload.html",
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
        "confirm_upload.html",
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
        # Delete the main file
        os.remove(file_path)
        
        # Delete all version files from versions folder
        versions = get_file_versions(filename, tenant_id)
        for version in versions:
            if 'version_file' in version:
                version_path = os.path.join(app.config['VERSIONS_FOLDER'], version['version_file'])
                if os.path.exists(version_path):
                    os.remove(version_path)
        
        # Delete version history from JSON
        delete_file_versions(filename, tenant_id)
        
        return jsonify({"message": "File deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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


@app.route('/login', methods=['GET', 'POST'])
def login():

        form = Loginform()

        if request.method == 'POST' and form.validate_on_submit():
            email_input = escape(form.email.data)
            password_input = escape(form.password.data)
            user = True#User.query.filter_by(email=email_input).first()

            if user and check_password_hash(user.password, password_input):
                if not user.is_verified:
                    flash("Please verify your email before logging in.", "warning")
                    return redirect(url_for('login'))
                session['user_id'] = user.id
                session['username'] = user.username
                session['user_type'] = user.user_type

                if user.user_type == 'elderly':
                    return redirect(url_for('elderly_home'))
                elif user.user_type == 'volunteer':
                    return redirect(url_for('volunteer_dashboard'))
                elif user.user_type == 'admin':
                    return redirect(url_for('adminDashboard'))

            else:
                flash("Invalid username or password.", "danger")
                return redirect(url_for('login'))

        return render_template('login/login_page.html', form=form)

@app.route('/logout')
def logout():

    session.clear()
    flash("You have been logged out.", "info")

    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()

    return render_template('login/tmpsignup.html', form=form)

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     username = session.get('username', 'Anonymous')
#     form = SignUpForm()

#     if request.method == 'POST' and form.validate_on_submit():
#         existing_user = User.query.filter(
#             (User.username == form.username.data) | (User.email == form.email.data)
#         ).first()

#         if existing_user:
#             flash("Username or email already in use. Please choose another.", "danger")
#             return render_template('login/signup_page.html', form=form)

#         hashed_password = generate_password_hash(escape(form.password.data))

#         new_user = User(
#             username=escape(form.username.data),
#             email=escape(form.email.data),
#             password=hashed_password,
#             user_type=escape(form.user_type.data)
#         )
#         if new_user.user_type == 'volunteer':
#             db.session.add(new_user)
#             db.session.commit()
#             volunteer_table_join(new_user)# for joining user data to volunteer database if usertype = volunteer
#         elif new_user.user_type == 'elderly':
#             db.session.add(new_user)
#             db.session.commit()
#             elderly_table_join(new_user)
#         send_verification_email(new_user.email)
#         flash(f"Please Verify Your Email!", "success")
#         return redirect(url_for('login'))

#     return render_template('login/signup_page.html', form=form)

#TODO sign up, html, css, connect email application
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


# @app.route('/reset-password', methods=['GET', 'POST'])
# def reset_password():
# #     try:
# #         email = s.loads(token, salt='password-reset', max_age=3600)
# #     except SignatureExpired:
# #         flash("The password reset link has expired.", "danger")
# #         return redirect(url_for('forget_password'))
# #     except Exception:
# #         flash("Invalid or expired token.", "danger")
# #         return redirect(url_for('forget_password'))

#     form = ResetPasswordForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=email).first()
#         if user:
#             user.set_password(form.password.data)
#             db.session.commit()
#             flash("Your password has been updated successfully.", "success")
#             return redirect(url_for('login'))
#         else:
#             flash("User not found.", "danger")
#             return redirect(url_for('forget_password'))

#     return render_template('reset_password.html', form=form)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    return render_template('login/reset_password.html', form=form)

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
