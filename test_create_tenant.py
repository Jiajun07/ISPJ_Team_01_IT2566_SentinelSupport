from database import create_tenant

if __name__ == "__main__":
    print("Script started")
    try:
        tenant_id, db_name = create_tenant(
            company_name="Demo SME Pte Ltd",
            admin_email="admin@demosme.com",
            admin_password="StrongPass123!"
        )
        print("Created tenant:", tenant_id, "DB:", db_name)
    except Exception as e:
        print("Error creating tenant:", repr(e))
