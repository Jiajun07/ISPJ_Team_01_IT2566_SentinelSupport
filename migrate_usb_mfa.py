"""
Migration script to add USB MFA support to existing tenants
Run this once to add the usb_mfa_enabled column to all existing tenant users tables
"""

from database import db
from sqlalchemy import text
import sys

def migrate_usb_mfa():
    """Add usb_mfa_enabled column to existing users tables"""
    
    try:
        # Get all tenant schemas
        result = db.session.execute(text("""
            SELECT schema_name FROM information_schema.schemata 
            WHERE schema_name LIKE 'tenant_%'
        """))
        
        tenant_schemas = [row[0] for row in result.fetchall()]
        
        print(f"Found {len(tenant_schemas)} tenant schemas")
        
        for schema in tenant_schemas:
            try:
                # Check if column already exists
                check = db.session.execute(text(f"""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_schema = '{schema}' 
                        AND table_name = 'users' 
                        AND column_name = 'usb_mfa_enabled'
                    )
                """))
                
                column_exists = check.scalar()
                
                if not column_exists:
                    # Add column
                    db.session.execute(text(f'''
                        ALTER TABLE "{schema}".users 
                        ADD COLUMN usb_mfa_enabled BOOLEAN DEFAULT FALSE
                    '''))
                    db.session.commit()
                    print(f"✅ Added usb_mfa_enabled to {schema}.users")
                else:
                    print(f"ℹ️  Column already exists in {schema}.users")
            
            except Exception as e:
                print(f"❌ Error migrating {schema}: {e}")
                db.session.rollback()
        
        print("✅ Migration complete!")
        return True
    
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False


if __name__ == '__main__':
    from app import app
    
    with app.app_context():
        success = migrate_usb_mfa()
        sys.exit(0 if success else 1)
