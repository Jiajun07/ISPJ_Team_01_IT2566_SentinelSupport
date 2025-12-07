# app.py
from flask import Flask, g, request
from sqlalchemy.orm import sessionmaker
from database import get_tenant_engine
from tenant_service import get_db_name_for_company

app = Flask(__name__)

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

