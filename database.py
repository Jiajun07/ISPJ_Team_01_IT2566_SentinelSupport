# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine
import psycopg2
import bcrypt
MASTER_DB_URL = (
    "postgresql://postgres:Jiajun07@@2025@localhost:5432/sdsm_master"
)

MASTER_DSN = (
    "dbname=sdsm_master user=postgres "
    "password=Jiajun07@@2025 host=localhost port=5432"
)

SUPER_DSN = (
    "dbname=postgres user=postgres "
    "password=Jiajun07@@2025 host=localhost port=5432"
)


def create_tenant(company_name: str, admin_email: str, admin_password: str):
    # 1) insert tenant row in sdsm_master and get id
    with psycopg2.connect(MASTER_DSN) as master_conn:
        with master_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (company_name, status)
                VALUES (%s, 'active')
                RETURNING id;
                """,
                (company_name,),
            )
            tenant_id = cur.fetchone()[0]
            db_name = f"tenant_{tenant_id}"

            cur.execute(
                """
                UPDATE tenants
                SET db_name = %s
                WHERE id = %s;
                """,
                (db_name, tenant_id),
            )

    # 2) create the tenant database (needs superuser)
    with psycopg2.connect(SUPER_DSN) as super_conn:
        super_conn.autocommit = True
        with super_conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{db_name}";')

    # 3) create tables inside the new tenant database
    tenant_dsn = (
        f'dbname={db_name} user=postgres '
        f'password=Jiajun07@@2025 host=localhost port=5432'
    )
    with psycopg2.connect(tenant_dsn) as tenant_conn:
        with tenant_conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id            SERIAL PRIMARY KEY,
                    email         VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255)        NOT NULL,
                    role          VARCHAR(50)         NOT NULL,
                    created_at    TIMESTAMP           NOT NULL DEFAULT NOW()
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id              SERIAL PRIMARY KEY,
                    owner_user_id   INT          NOT NULL REFERENCES users(id),
                    file_path       TEXT         NOT NULL,
                    classification  VARCHAR(50)  NOT NULL,
                    version         INT          NOT NULL DEFAULT 1,
                    created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id           SERIAL PRIMARY KEY,
                    user_id      INT REFERENCES users(id),
                    action       VARCHAR(100) NOT NULL,
                    target_type  VARCHAR(50),
                    target_id    INT,
                    details      TEXT,
                    created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
                );
                """
            )

            password_hash = bcrypt.hashpw(
                admin_password.encode("utf-8"),
                bcrypt.gensalt(),
            ).decode("utf-8")

            cur.execute(
                """
                INSERT INTO users (email, password_hash, role)
                VALUES (%s, %s, 'admin');
                """,
                (admin_email, password_hash),
            )

    return tenant_id, db_name




master_engine = create_engine(MASTER_DB_URL)
MasterSessionLocal = sessionmaker(bind=master_engine)

def get_tenant_engine(db_name: str) -> Engine:
    return create_engine(
        f"postgresql://postgres:Jiajun07@@2025@localhost:5432/{db_name}"
    )