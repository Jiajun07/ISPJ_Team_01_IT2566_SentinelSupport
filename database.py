# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine
import psycopg2
import bcrypt
MASTER_DB_URL = (
    "postgresql://postgres:Jiajun07@@2025@localhost:5432/sdsm_master"
)

MASTER_DSN = "dbname=sdsm_master user=postgres password=Jiajun07@@2025 host=localhost port=5432"
SUPER_DSN  = "dbname=postgres    user=postgres password=Jiajun07@@2025 host=localhost port=5432"


# database.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import bcrypt

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
    db.session.flush()
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

    db.session.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {schema_name}.audit_logs (
            id           SERIAL PRIMARY KEY,
            user_id      INT REFERENCES {schema_name}.users(id),
            action       VARCHAR(100) NOT NULL,
            target_type  VARCHAR(50),
            target_id    INT,
            details      TEXT,
            created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
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

def get_tenant_engine(db_name: str) -> Engine:
    return create_engine(
        f"postgresql://postgres:Jiajun07@@2025@localhost:5432/{db_name}"
    )