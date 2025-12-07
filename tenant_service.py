# tenant_service.py
from database import MasterSessionLocal

def get_db_name_for_company(company_name: str) -> str | None:
    session = MasterSessionLocal()
    row = session.execute(
        "SELECT db_name FROM tenants WHERE company_name = :c AND status = 'active'",
        {"c": company_name},
    ).fetchone()
    session.close()
    return row[0] if row else None
