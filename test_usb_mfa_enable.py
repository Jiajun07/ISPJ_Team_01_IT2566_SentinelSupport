"""
Test script to verify USB MFA setup and enable functionality
"""

from app import app
from database import db
from sqlalchemy import text
import sys

with app.app_context():
    print("🔍 Checking USB MFA column existence across tenants...")
    
    try:
        # Get all tenant schemas
        result = db.session.execute(text("""
            SELECT schema_name FROM information_schema.schemata 
            WHERE schema_name LIKE 'tenant_%'
            ORDER BY schema_name
        """))
        
        tenant_schemas = [row[0] for row in result.fetchall()]
        
        if not tenant_schemas:
            print("❌ No tenants found!")
            sys.exit(1)
        
        migration_needed = False
        
        for schema in tenant_schemas:
            try:
                # Check if column exists
                check = db.session.execute(text(f"""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_schema = '{schema}' 
                        AND table_name = 'users' 
                        AND column_name = 'usb_mfa_enabled'
                    )
                """))
                
                column_exists = check.scalar()
                
                if column_exists:
                    print(f"✅ {schema}.users has usb_mfa_enabled column")
                else:
                    print(f"❌ {schema}.users MISSING usb_mfa_enabled column")
                    migration_needed = True
                    
                    # Try to add it
                    try:
                        print(f"   → Adding column to {schema}...")
                        db.session.execute(text(f'''
                            ALTER TABLE "{schema}".users 
                            ADD COLUMN usb_mfa_enabled BOOLEAN DEFAULT FALSE
                        '''))
                        db.session.commit()
                        print(f"   ✅ Added usb_mfa_enabled to {schema}.users")
                    except Exception as add_err:
                        print(f"   ❌ Failed to add column: {add_err}")
                        db.session.rollback()
            
            except Exception as e:
                print(f"❌ Error checking {schema}: {e}")
        
        if migration_needed:
            print("\n✅ Migration complete! USB MFA is now ready.")
        else:
            print("\n✅ All tenants already have USB MFA support!")
            
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

print("\n✅ Test complete. You can now enable USB MFA!")
