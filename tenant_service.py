# tenant_service.py
from database import MasterSessionLocal


def get_db_name_for_company(company_name: str) -> str | None:
    session = MasterSessionLocal()
    row = session.execute(
        "SELECT id FROM tenants WHERE company_name = %s AND status = 'active'",
        (company_name,)
    ).fetchone()
    session.close()
    return f"tenant_{row[0]}" if row else None

