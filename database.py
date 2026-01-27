# database.py
from flask_alchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine
import psycopg2
import bcrypt
MASTER_DB_URL = (
    "postgresql://postgres.ijbxuudpvxsjjdugewuj:SentinelSupport%2A2026@"
    "aws-1-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
# database.py
db = SQLAlchemy()

class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=db.func.now())

def create_tenant(company_name: str, admin_email: str, admin_password: str):
    # 1) Create tenant record
    tenant = Tenant(company_name=company_name)
    db.session.add(tenant)
    db.session.flush()  # get id without committing yet
    tenant_id = tenant.id
    schema_name = f"tenant_{tenant_id}"

    # 2) CREATE SCHEMA
    db.session.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name};"))

    # 3) CREATE TABLES IN SCHEMA
    db.session.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {schema_name}.users (
            id            SERIAL PRIMARY KEY,
            email         VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255)        NOT NULL,
            role          VARCHAR(50)         NOT NULL,
            created_at    TIMESTAMP           NOT NULL DEFAULT NOW()
        );
    """))

    db.session.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {schema_name}.documents (
            id              SERIAL PRIMARY KEY,
            owner_user_id   INT          NOT NULL REFERENCES {schema_name}.users(id),
            file_path       TEXT         NOT NULL,
            classification  VARCHAR(50)  NOT NULL,
            version         INT          NOT NULL DEFAULT 1,
            created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
        );
    """))

    # 4) Insert admin user
    password_hash = bcrypt.hashpw(
        admin_password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    db.session.execute(
        text(f"INSERT INTO {schema_name}.users (email, password_hash, role) VALUES (%s, %s, 'admin');"),
        (admin_email, password_hash)
    )

    db.session.commit()
    return tenant_id, schema_name




master_engine = create_engine(MASTER_DB_URL)
MasterSessionLocal = sessionmaker(bind=master_engine)
def get_tenant_users(tenant_id: str):
    with psycopg2.connect(MASTER_DB_URL) as conn:
        with conn.cursor() as cur:
            schema_name = f"tenant_{tenant_id}"
            cur.execute(f"SET search_path TO {schema_name}, public;")
            cur.execute("SELECT * FROM users;")
            return cur.fetchall()
