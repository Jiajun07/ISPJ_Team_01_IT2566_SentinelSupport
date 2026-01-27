# test_create_tenant.py
from app import app, db
from database import create_tenant

with app.app_context():
    print("Script started")
    try:
        tenant_id, schema_name = create_tenant(
            company_name="Demo SME Pte Ltd",
            admin_email="admin@demosme.com",
            admin_password="StrongPass123!"
        )
        print("Created tenant:", tenant_id, "Schema:", schema_name)
    except Exception as e:
        print("Error:", repr(e))
