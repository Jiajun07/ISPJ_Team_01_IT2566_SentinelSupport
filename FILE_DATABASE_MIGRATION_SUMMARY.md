# File Database Migration Summary

## Overview
Successfully migrated from JSON file-based storage to PostgreSQL database storage with BLOB support for binary file data.

## Database Models Created (in `database.py`)

### 1. **File** - Master file records
- `id`: Primary key
- `document_id`: UUID for grouping all versions of same document
- `file_name`: Original filename
- `owner_user_id` & `owner_email`: File owner references
- `file_data`: BYTEA column storing actual file binary data (BLOB)
- `file_size`, `file_hash`: Size and SHA256 hash
- `mime_type`: File MIME type
- `sensitivity`: Public, Internal, Confidential, Restricted
- `classification`, `risk_level`: DLP scan results
- `notes`: User notes
- `is_current_version`: Boolean flag for current version
- `is_deleted`: Soft delete flag (for bin functionality)
- `deleted_at`: Deletion timestamp
- `created_at`, `updated_at`: Timestamps

### 2. **FileVersion** - Version history
- `id`: Primary key
- `document_id`: Links to parent File.document_id
- `version_number`: Sequential version (1, 2, 3...)
- `file_name`, `file_data`, `file_size`, `file_hash`: Version content
- `uploaded_by`: User who uploaded this version
- `uploaded_at`: Upload timestamp
- `is_current`: Boolean for current version
- **Unique constraint** on (document_id, version_number)

### 3. **FileSharingLink** - Share links
- `id`: Primary key
- `document_id`: Links to File
- `share_token`: Unique share token (URL parameter)
- `password_hash`: Bcrypt hash if password protected
- `require_key_exchange`: Boolean for security exchange requirement
- `exchange_id`: Reference to KeyExchange table
- `created_by`: Creator email
- `is_active`: Active status
- `expires_at`: Optional expiration
- `last_accessed`, `access_count`: Usage tracking

### 4. **Sharing** - Direct user shares
- `id`: Primary key
- `document_id`: Links to File
- `shared_with_email`, `shared_by_email`: Parties involved
- `access_level`: 'view', 'edit', 'download'
- `is_accepted`, `is_active`: Status flags
- `shared_at`, `expires_at`: Timestamps
- `last_accessed`, `access_count`: Usage tracking
- **Unique constraint** on (document_id, shared_with_email)

### 5. **SharingActivity** - Audit trail
- `id`: Primary key
- `document_id`: Links to File
- `action`: 'shared', 'unshared', 'accessed', 'downloaded', 'link_created'
- `shared_with_email`, `shared_via_link`: Tracking methods
- `shared_by_email`: Actor
- `ip_address`, `user_agent`: Request tracking
- `activity_at`: Timestamp
- `details`: JSON for additional metadata

### 6. **KeyExchange** - Security key verification
- `id`: Primary key
- `exchange_id`: Unique exchange identifier
- `sharer_email`, `recipient_email`: Parties
- `document_id`: Links to File
- `sharer_public_key`, `recipient_public_key`: RSA keys
- `sharer_fingerprint`, `recipient_fingerprint`: Key fingerprints
- `status`: 'pending', 'verified', 'expired', 'rejected'
- `sharer_verified`, `recipient_verified`, `recipient_confirmed`: Verification flags
- `created_at`, `expires_at`, `verified_at`: Timestamps

## Helper Functions Created (in `database.py`)

### File Operations
- `generate_document_id()`: Generate UUID for document tracking
- `store_file_in_db(...)`: Store new file with blob data
- `add_file_version(...)`: Add new version to existing file
- `get_file_from_db(...)`: Retrieve file by document_id or filename
- `get_all_files_for_tenant(...)`: List all files for tenant/user
- `delete_file_from_db(...)`: Soft/hard delete file
- `get_file_versions_from_db(...)`: Get all versions of a file

### Key Features
✅ **BLOB Storage**: Files stored as BYTEA in PostgreSQL (no filesystem dependency)
✅ **Version Control**: document_id groups versions, version_number tracks individual versions
✅ **Soft Delete**: Bin functionality via is_deleted flag
✅ **Multi-tenant**: All tables created in tenant-specific schemas (tenant_1, tenant_2, etc.)
✅ **Audit Trail**: SharingActivity tracks all file operations
✅ **Security**: Key exchange system for encrypted sharing

## Schema Updates in `company_signup` Route

When a new tenant signs up, the following tables are automatically created in their schema:

### Existing Tables (unchanged)
- users
- documents  
- audit_logs

### NEW Tables (added)
- files
- file_versions
- file_sharing_links
- sharing
- sharing_activity
- key_exchanges

All with proper indexes for performance.

## Code Cleanup Completed

### Removed
- ❌ `DUMMY_ACCOUNTS` dictionary
- ❌ All references to tenant '1' and '2' hardcoded accounts
- ❌ Hardcoded owner names ('John Doe', 'Jane Smith')

### Replaced With
- ✅ `session.get('email')` for current user
- ✅ `Tenant.query.get(tenant_id)` for company names
- ✅ Dynamic lookups from database

## Next Steps (Remaining Work)

### TODO #4: Update File Upload Routes ⏳
Routes to update:
- `/upload/temp` - Store files in DB instead of pending folder
- `/upload/confirm/<temp_id>` - Save to DB with metadata
- `/upload/version/temp/<filename>` - Version uploads to DB
- `/upload/version/confirm/<temp_id>/<filename>` - Finalize version in DB

### TODO #5: Update File Retrieval Routes ⏳
Routes to update:
- `/myfiles` - Query from files table
- `/file/<filename>` - Retrieve from DB
- `/uploads/<filename>` - Download blob from DB
- `/download/version/<filename>` - Download version from file_versions

### TODO #6: Update Sharing Routes ⏳
Routes to update:
- `/generate_share_link` - Create FileSharingLink record
- `/validate_share_link` - Query FileSharingLink table
- `/download/shared/<filename>` - Retrieve from DB
- `/initiate_key_exchange` - Create KeyExchange record
- All key exchange verification routes

### TODO #7: Update File Operations ⏳
Routes to update:
- `/rename` - Update file_name in files table
- `/delete` - Set is_deleted=TRUE
- `/bin` - Query deleted files
- `/bin/restore/<bin_key>` - Restore file (set is_deleted=FALSE)
- `/bin/permanent-delete/<bin_key>` - Hard delete from DB

## Migration Benefits

### 1. **Database-Centric**
- No file system dependencies
- Easier backups (just pg_dump)
- Atomic transactions

### 2. **Scalability**
- Works with cloud databases
- No disk I/O bottlenecks
- Easy replication

### 3. **Security**
- Files encrypted at rest in database
- Row-level security policies
- Audit trail built-in

### 4. **Multi-tenant Isolation**
- Each tenant has separate schema
- No cross-tenant access possible
- Clean data separation

## Database Storage Considerations

### BLOB Storage (BYTEA)
- PostgreSQL BYTEA can store up to 1GB per field
- For files > 1GB, consider Large Objects (lo_*)
- Current implementation suitable for documents, images, PDFs

### Performance Tips
- Index on document_id, owner_email for fast queries
- Consider partitioning files table if > millions of records
- Use connection pooling (already configured with Supabase)

## Example Usage

```python
# Store a file
from database import store_file_in_db

with open('document.pdf', 'rb') as f:
    file_data = f.read()

result = store_file_in_db(
    tenant_id=1,
    file_data=file_data,
    filename='document.pdf',
    owner_user_id=42,
    owner_email='user@example.com',
    file_hash='abc123...',
    mime_type='application/pdf',
    sensitivity='Confidential'
)
# Returns: {'success': True, 'file_id': 1, 'document_id': 'uuid...', 'filename': 'document.pdf'}

# Retrieve a file
from database import get_file_from_db

file_record = get_file_from_db(tenant_id=1, filename='document.pdf')
file_data = file_record['file_data']  # Binary blob

# List all files
from database import get_all_files_for_tenant

files = get_all_files_for_tenant(tenant_id=1, owner_email='user@example.com')
```

## Status: Phase 1 Complete ✅

- [x] Database models created
- [x] Helper functions implemented
- [x] Schema auto-creation in company_signup
- [x] DUMMY_ACCOUNTS removed
- [ ] File upload routes updated
- [ ] File retrieval routes updated
- [ ] Sharing routes updated
- [ ] File operations updated

Ready to proceed with route updates!
