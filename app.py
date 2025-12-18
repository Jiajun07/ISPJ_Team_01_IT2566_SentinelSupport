# app.py
from flask import Flask, g, Flask, render_template, request, redirect, url_for
from sqlalchemy.orm import sessionmaker
from database import get_tenant_engine
from tenant_service import get_db_name_for_company
from markupsafe import escape
from forms import Loginform, SignUpForm, ForgetPasswordForm, ResetPasswordForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

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

@app.route("/login", methods=["GET", "POST"])
def login():

    return render_template("login.html")

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

#TODO login, sign up, html, css, connect email application
@app.route('/forgot-password', methods=['GET', 'POST'])
def forget_password():
    
    form = ForgetPasswordForm()

    if form.validate_on_submit():
        email = escape(form.email.data)
        user = User.query.filter_by(email=email).first()

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
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
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
    log_audit_event(f'{session.get("username", "Anonymous")} viewed reset password page')
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash("The password reset link has expired.", "danger")
        return redirect(url_for('forget_password'))
    except Exception as e:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('forget_password'))

    form = ResetPasswordForm()













if __name__ == "__main__":
    app.run(debug=True)