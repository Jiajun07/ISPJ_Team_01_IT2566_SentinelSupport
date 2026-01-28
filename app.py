# app.py
import os
import hashlib
from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from sqlalchemy.orm import sessionmaker
from database import create_tenant, db, get_tenant_engine
from tenant_service import get_db_name_for_company
from markupsafe import escape
from forms import Loginform, SignUpForm, ForgetPasswordForm, ResetPasswordForm
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from DLPScannerModules.DLPScanner import DLPScanner
from DLPScannerModules.FileProcessor import FileProcessor
from datetime import datetime
import os
import smtplib
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

csrf = CSRFProtect(app)

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

db.init_app(app)

# Create public.tenants table (run once)
with app.app_context():
    db.create_all()  # creates Tenant model table

@app.route('/test-tenant', methods=['GET'])
def test_tenant():
    with app.app_context():
        tenant_id, schema_name = create_tenant(
            "Test Company", "admin@test.com", "pass123"
        )
        return f"Created tenant {tenant_id} with schema {schema_name}"

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads")
app.config['PENDING_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads_pending")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg", "txt"}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PENDING_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def compute_sha256(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def get_uploaded_files():
    files = []
    for fname in sorted(os.listdir(app.config['UPLOAD_FOLDER'])):
        fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        if os.path.isfile(fpath):
            files.append(
                {
                    "name": fname,
                    "size": os.path.getsize(fpath),
                    "url": url_for("download_file", filename=fname),
                    "hash": compute_sha256(fpath),
                }
            )
    return files

def get_tenant_session():
    if "tenant_session" not in g:
        # Example: company name stored in session or token
        company_name = request.headers.get("X-Company-Name")  # or from login/session
        db_name = get_db_name_for_company(company_name)
        if not db_name:
            raise RuntimeError("Unknown or inactive tenant")
        engine = get_tenant_engine(db_name)
        SessionLocal = sessionmaker(bind=engine)
        g.tenant_session = SessionLocal()
    return g.tenant_session

@app.route("/", methods=["GET", "POST"])

#@app.route("/login", methods=["GET", "POST"])
#def login():
#
#    return render_template("login.html")
#

@app.route('/myfiles', methods=['GET'])
def myfiles():
    files = get_uploaded_files()
    return render_template("myfiles.html", files=files)


def _pending_path(temp_id):
    for fname in os.listdir(app.config['PENDING_FOLDER']):
        if fname.startswith(f"{temp_id}__"):
            return os.path.join(app.config['PENDING_FOLDER'], fname)
    return None


@app.route('/file/<path:filename>', methods=['GET'])
def file_detail(filename):
    from urllib.parse import unquote
    filename = unquote(filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    file_info = {
        "name": filename,
        "size": os.path.getsize(file_path),
        "url": url_for("download_file", filename=filename),
        "hash": compute_sha256(file_path),
        "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%d %B %Y'),
        "owner": "You",
        "uploaded_by": "You"
    }
    
    return render_template("file_detail.html", file=file_info)


@app.route('/upload/temp', methods=['POST'])
def upload_temp():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['file']
    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    from uuid import uuid4
    temp_id = str(uuid4())
    safe_name = sanitize_filename(file.filename)
    pending_name = f"{temp_id}__{safe_name}"
    pending_path = os.path.join(app.config['PENDING_FOLDER'], pending_name)

    file.save(pending_path)
    size = os.path.getsize(pending_path)
    file_hash = compute_sha256(pending_path)

    return jsonify({
        "confirm_url": url_for('confirm_upload', temp_id=temp_id),
        "name": safe_name,
        "size": size,
        "hash": file_hash
    }), 200


@app.route('/upload/confirm/<temp_id>', methods=['GET', 'POST'])
def confirm_upload(temp_id):
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
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], target_safe)

        if os.path.exists(save_path):
            name, ext = os.path.splitext(target_safe)
            counter = 1
            while os.path.exists(save_path):
                target_safe = f"{name}_{counter}{ext}"
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], target_safe)
                counter += 1

        os.replace(pending_path, save_path)
        size_final = os.path.getsize(save_path)
        file_hash_final = compute_sha256(save_path)
        file_url = url_for('download_file', filename=target_safe)
        return redirect(url_for('file_detail', filename=target_safe))

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


@app.route('/rename', methods=['POST'])
def rename_file():
    data = request.get_json()
    old_name = data.get('old_name')
    new_name = data.get('new_name')

    if not old_name or not new_name:
        return jsonify({"error": "Missing filename"}), 400

    old_path = os.path.join(app.config['UPLOAD_FOLDER'], sanitize_filename(old_name))
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], sanitize_filename(new_name))

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
def share_file():
    data = request.get_json()
    filename = data.get('filename')
    email = data.get('email')

    if not filename or not email:
        return jsonify({"error": "Missing filename or email"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], sanitize_filename(filename))
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        # TODO: Implement email sharing logic
        # For now, just return success message
        return jsonify({"message": f"File {filename} shared with {email}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete', methods=['POST'])
def delete_file():
    data = request.get_json()
    filename = data.get('filename')

    if not filename:
        return jsonify({"error": "Missing filename"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], sanitize_filename(filename))

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        os.remove(file_path)
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
    filename = unquote(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.teardown_appcontext
def remove_session(exception=None):
    sess = g.pop("tenant_session", None)
    if sess is not None:
        sess.close()

@app.route("/documents")
def list_documents():
    session = get_tenant_session()
    rows = session.execute("SELECT id, file_path, classification FROM documents").fetchall()
    return {"documents": [dict(r) for r in rows]}

@app.route('/login', methods=['GET', 'POST'])
def login():

        form = Loginform()

        if request.method == 'POST' and form.validate_on_submit():
            username_input = escape(form.username.data)
            password_input = escape(form.password.data)
            user = True#User.query.filter_by(username=username_input).first()

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



def policyEngine(file):
    try:
        if not fileProcessor.passedProcessing(file):
            return {'status': 'error', 'message': 'File type not supported for DLP scanning.'}
        extractResult = fileProcessor.readTextFromFile(file)
        textContent = extractResult
        dlpMatches = dlpScanner.scan_text(textContent)
        riskAssessment = dlpScanner.calculateRisk(dlpMatches)
        scanResult = {
            'timestamp': datetime.now().isoformat(),
            'matches': dlpMatches,
            'riskAssessment': riskAssessment,
            'textPreview': textContent[:500] + '...' if len(textContent) > 500 else textContent,
            'fileInformation': fileProcessor.getFileInfo(file)
        }
        return {'status': 'success', 'data': scanResult}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@app.route('/autodlp', methods=['GET', 'POST'])
def autodlp():
    if request.method == 'POST':      
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        result = policyEngine(file)
        if result['status'] == 'success':
            # DEBUG: Print all matches found
            print(f"\n=== DLP SCAN DEBUG ===")
            print(f"Total matches: {len(result['data']['matches'])}")
            for match in result['data']['matches']:
                print(f"  - {match.closestDetectedRule}: '{match.matchedText}' (confidence: {match.scanConfidence})")
            print(f"======================\n")
            return render_template("SuperAdmin/autodlp.html", result=result['data'], filename=file.filename)
        else:
            flash(result['message'], 'error')
            return redirect(request.url)
    return render_template("SuperAdmin/autodlp.html")


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
