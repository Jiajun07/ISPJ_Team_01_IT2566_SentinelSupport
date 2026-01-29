# Tenant Account Switching Guide

## Two Dummy Accounts

You now have 2 separate tenant accounts set up:

1. **Tenant 1 - Acme Corp** (Owner: John Doe)
2. **Tenant 2 - Tech Solutions** (Owner: Jane Smith)

## How to Switch Accounts

### Method 1: Using the Dropdown (Easiest)
- On the `/myfiles` page, use the account switcher dropdown at the top of the sidebar
- Select the account you want to view
- The page will automatically reload with that account's files

### Method 2: Using URL Parameters
You can manually edit the URL to switch accounts:

- **Acme Corp (Tenant 1)**: `http://localhost:5000/myfiles?tenant=1`
- **Tech Solutions (Tenant 2)**: `http://localhost:5000/myfiles?tenant=2`

## File Isolation

- Each tenant has completely separate file storage
- Files uploaded to Tenant 1 won't appear in Tenant 2 and vice versa
- Files are stored in separate folders:
  - `uploads/tenant_1/` for Acme Corp
  - `uploads/tenant_2/` for Tech Solutions

## Testing

1. Go to `http://localhost:5000/myfiles?tenant=1`
2. Upload some files
3. Switch to `http://localhost:5000/myfiles?tenant=2`
4. Upload different files
5. Switch back to tenant 1 - you'll only see the files you uploaded to tenant 1

All file operations (upload, rename, share, delete) are tenant-specific and isolated.

## Default Behavior

If you visit `/myfiles` without the `?tenant=` parameter, it defaults to **Tenant 1 (Acme Corp)**.
