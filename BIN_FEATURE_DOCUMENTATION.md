# Bin/Trash Feature Implementation

## Overview
The bin feature has been successfully implemented to provide users with a safety mechanism for file deletion. When users delete files, they are moved to a bin instead of being permanently deleted, allowing for recovery within a 30-day window.

## Features Implemented

### 1. **Soft Delete Mechanism**
- **Previous Behavior**: Files were permanently deleted when users clicked delete
- **Current Behavior**: Files are moved to a bin folder and tracked in `bin_metadata.json`
- **Location**: Files are stored in `/bin` directory with unique timestamped filenames
- **Metadata Tracking**: Each deleted file's metadata is stored including:
  - Original filename
  - Tenant ID
  - Deletion timestamp
  - Version history (if applicable)
  - Original file path

### 2. **Automatic Cleanup**
- **Schedule**: Runs every 1 hour via APScheduler (BackgroundScheduler)
- **Retention Period**: 30 days
- **Action**: Files older than 30 days are permanently deleted from the bin
- **Logging**: Cleanup logs are printed to console (e.g., "✅ Bin cleanup: 2 files permanently deleted")

### 3. **Shared Files Handling**
- When a file is deleted, it is automatically removed from all shared shares
- **Behavior**: Files no longer appear in other users' "Shared with me" page
- **Implementation**: `received_shares.json` is updated to filter out deleted files
- **Share Links**: Any share links pointing to deleted files are also removed

### 4. **Bin Management Page**
- **Route**: `/bin` (GET request)
- **Template**: `templates/users/bin.html`
- **Features**:
  - Display all deleted files for the current tenant
  - Show deletion date and days remaining until permanent deletion
  - Color-coded badge system (red for ≤7 days, blue for >7 days)
  - Search functionality to filter deleted files
  - Responsive grid layout matching existing file list design

### 5. **Restore Functionality**
- **Route**: `/bin/restore/<bin_key>` (POST request)
- **Process**:
  1. File is copied from bin folder back to original location
  2. Version history is restored if applicable
  3. File is removed from bin metadata
  4. User receives success confirmation
- **Confirmation**: Modal popup asks user to confirm restoration

### 6. **Permanent Delete Functionality**
- **Route**: `/bin/permanent-delete/<bin_key>` (POST request)
- **Process**:
  1. File is permanently deleted from bin folder
  2. Metadata entry is removed
  3. User receives success confirmation
- **Confirmation**: Modal popup with warning that action is irreversible

### 7. **Manual Cleanup Endpoint**
- **Route**: `/bin/cleanup` (POST request)
- **Purpose**: Manually trigger cleanup (can be called by admin)
- **Response**: Returns count of files permanently deleted

## Files Modified/Created

### New Files
1. **`bin_metadata.json`** - Stores metadata for all deleted files
2. **`bin/` directory** - Stores actual deleted files
3. **`templates/users/bin.html`** - Bin view template with restore/delete UI

### Modified Files
1. **`app.py`**:
   - Added imports for APScheduler
   - Added BIN_FOLDER and BIN_METADATA_FILE configuration
   - Added functions:
     - `load_bin_metadata()` - Load bin data from JSON
     - `save_bin_metadata()` - Save bin data to JSON
     - `move_file_to_bin()` - Move file to bin with metadata tracking
     - `restore_file_from_bin()` - Restore file from bin
     - `permanently_delete_from_bin()` - Permanently delete from bin
     - `cleanup_bin()` - Auto-delete files older than 30 days
     - `cleanup_bin_wrapper()` - Safe wrapper for scheduler
   - Modified `/delete` endpoint to use soft delete instead of hard delete
   - Added new routes:
     - `GET /bin` - View bin contents
     - `POST /bin/restore/<bin_key>` - Restore file
     - `POST /bin/permanent-delete/<bin_key>` - Permanently delete
     - `POST /bin/cleanup` - Manual cleanup trigger
   - Added background scheduler initialization

2. **`templates/users/myfiles.html`**:
   - Updated sidebar navigation to include Bin link
   - Changed static button to functional link: `onclick="window.location.href='/bin?tenant={{ tenant_id }}'"`

3. **`templates/users/shared_with_me.html`**:
   - Updated sidebar navigation to include Bin link
   - Changed static button to functional link: `onclick="window.location.href='/bin?tenant={{ tenant_id }}'"`

4. **`requirements.txt`**:
   - Added APScheduler package for background task scheduling

## Database/Storage Structure

### bin_metadata.json Format
```json
{
  "tenant_1/filename.pdf_1707123456": {
    "original_filename": "filename.pdf",
    "tenant_id": 1,
    "bin_filename": "1_filename.pdf_1707123456",
    "deleted_at": "2024-02-05T10:30:45.123456",
    "original_path": "/uploads/tenant_1/filename.pdf",
    "versions": []
  }
}
```

## User Workflow

### Deleting a File
1. User clicks delete button on a file
2. Confirmation dialog appears
3. File is moved to bin (soft delete)
4. User receives "File moved to bin" message
5. File disappears from My Files and Shared with Me pages

### Viewing Bin
1. User clicks "Bin" in sidebar
2. All deleted files for current tenant are displayed
3. Each file shows:
   - Original filename
   - Deletion date
   - Days remaining (until automatic deletion)
   - Action buttons

### Restoring a File
1. User views bin and clicks restore button on desired file
2. Restoration confirmation modal appears
3. User confirms
4. File is restored to original location
5. Version history is restored if applicable
6. File disappears from bin

### Permanently Deleting from Bin
1. User clicks permanent delete button
2. Warning modal appears stating action is irreversible
3. User confirms
4. File is permanently deleted
5. File disappears from bin

## Security Considerations

1. **Tenant Isolation**: All operations check that files belong to current tenant
2. **Authorization**: `/bin/restore` and `/bin/permanent-delete` endpoints verify tenant ID
3. **CSRF Protection**: Delete endpoint uses @csrf.exempt (existing pattern)
4. **File Path Safety**: Uses `sanitize_filename()` and absolute paths

## Performance Impact

1. **Bin Cleanup**: Runs hourly in background, minimal impact
2. **Metadata Storage**: JSON file grows linearly with deleted files
3. **Search**: Client-side filtering in bin.html (no server load)

## Future Enhancements

1. **Database Migration**: Move bin_metadata from JSON to PostgreSQL for production
2. **Bulk Operations**: Add select-all and bulk restore/delete
3. **Retention Policies**: Allow per-tenant or per-user retention periods
4. **Audit Logging**: Log who deleted what and when
5. **Advanced Search**: Filter by date range, file type, etc.
6. **Recovery Timeline**: Show graphical timeline of deleted files
7. **Storage Quota**: Track bin storage usage per tenant

## Testing Checklist

- [x] Delete file moves to bin (not hard deleted)
- [x] Bin page displays deleted files
- [x] Restore functionality works
- [x] Permanent delete functionality works
- [x] Automatic cleanup runs hourly
- [x] Files older than 30 days are auto-deleted
- [x] Deleted shared files don't appear in Shared with Me
- [x] Tenant isolation works
- [x] Search functionality works
- [x] Sidebar navigation links work
- [x] Modals display correctly
- [x] Error handling works

## Known Limitations

1. **JSON Storage**: Using JSON for production may have performance issues with large datasets
2. **No Concurrent Delete**: Current implementation doesn't handle concurrent modifications
3. **Manual Cleanup**: `/bin/cleanup` endpoint has no authentication (should be admin-only)

## Troubleshooting

### APScheduler Not Running
- Ensure APScheduler is installed: `pip install APScheduler`
- Check console for scheduler initialization messages
- Restart application

### Bin Metadata Corruption
- Delete `bin_metadata.json` to reset
- Existing files in `/bin` folder will be orphaned but can be manually cleaned

### Files Not Restoring
- Check that `/bin/` directory exists and is writable
- Verify bin_metadata.json is not corrupted
- Check file permissions

## Deployment Notes

1. **Production Database**: Replace JSON storage with PostgreSQL for scalability
2. **Backup Strategy**: Include `/bin` folder and `bin_metadata.json` in backup routines
3. **Monitoring**: Monitor `/bin/cleanup` logs for cleanup success/failures
4. **Storage Management**: Monitor bin folder size to ensure disk space
