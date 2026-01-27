# app.py
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, current_app
from sqlalchemy.orm import sessionmaker
from database import master_engine, MasterSessionLocal, create_tenant, db
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

configPath = os.path.join(app.root_path, "config", "keywords.json")
fileConfigPath = os.path.join(app.root_path, "config", "supportedfiles.json")

dlpScanner = DLPScanner(configPath)
fileProcessor = FileProcessor(fileConfigPath)

@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

@app.route('/create-tenant', methods=['POST'])
def register_tenant():
    data = request.json
    tenant_id, schema_name = create_tenant(
        company_name=data['company_name'],
        admin_email=data['admin_email'],
        admin_password=data['admin_password']
    )
    return {'tenant_id': tenant_id, 'schema_name': schema_name}

if __name__ == '__main__':
    with app.app_context():
        # Create public.tenants table (run once)
        db.create_all()
    app.run(debug=True)


@app.before_request
def set_tenant_context():
    """Set tenant schema for this request"""
    company_name = request.headers.get("X-Company-Name")  # or from session/JWT
    if not company_name:
        g.schema_name = None
        return

    schema_name = get_db_name_for_company(company_name)  # returns 'tenant_1'
    if not schema_name:
        g.schema_name = None
        return

    g.schema_name = schema_name


def get_tenant_session():
    if "tenant_session" not in g:
        if not hasattr(g, 'schema_name') or g.schema_name is None:
            raise RuntimeError("No tenant context set")

        # Create session with search_path set to tenant schema
        engine = master_engine  # same engine for all tenants
        session = sessionmaker(bind=engine)()

        # Set search_path for this session to the tenant's schema
        session.execute(f"SET search_path TO {g.schema_name}, public;")
        g.tenant_session = session

    return g.tenant_session


@app.teardown_appcontext
def remove_session(exception=None):
    if hasattr(g, 'tenant_session'):
        g.tenant_session.close()

@app.route("/users")
def list_users():
    session = get_tenant_session()
    users = session.execute("SELECT * FROM users;").fetchall()  # auto uses tenant_X.users
    return {"users": [dict(u) for u in users]}


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


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash("The password reset link has expired.", "danger")
        return redirect(url_for('forget_password'))
    except Exception as e:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('forget_password'))

    form = ResetPasswordForm()


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
    app.run(debug=True)