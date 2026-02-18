"""
Test USB MFA functionality
This script tests:
1. USB drive detection
2. USB file reading (single and multiple keys)
3. Key generation and validation
4. Multiple keys on one USB
"""

from usb_mfa import USBMFAManager
import json
import os

print("=" * 60)
print("🧪 USB MFA FUNCTIONALITY TEST")
print("=" * 60)

# Test 1: USB Detection
print("\n1️⃣  Testing USB Drive Detection...")
print("-" * 60)
manager = USBMFAManager()
usb_drives = manager.get_usb_drives()

if usb_drives:
    print(f"✅ Found {len(usb_drives)} USB drive(s):")
    for drive in usb_drives:
        print(f"   - {drive}")
else:
    print("⚠️  No USB drives detected")
    print("   → Make sure your USB is inserted")

# Test 2: Key Generation
print("\n2️⃣  Testing MFA Key Generation...")
print("-" * 60)
test_user_id = 42
test_tenant_id = 4
test_email = "test@example.com"

key_info = manager.generate_mfa_key(test_user_id, test_tenant_id, test_email)
print(f"✅ Key Generated Successfully!")
print(f"\nGenerated Key Structure:")
print(json.dumps(key_info['key_data'], indent=2))

# Test 3: Key Validation
print("\n3️⃣  Testing Key Validation...")
print("-" * 60)
is_valid = manager.validate_mfa_key(
    key_info['key_data'],
    test_user_id,
    test_tenant_id,
    test_email
)
print(f"{'✅' if is_valid else '❌'} Key validation: {is_valid}")

# Test with wrong data
is_valid_wrong = manager.validate_mfa_key(
    key_info['key_data'],
    999,  # Wrong user ID
    test_tenant_id,
    test_email
)
print(f"{'✅' if not is_valid_wrong else '❌'} Wrong user rejection: {not is_valid_wrong}")

# Test 4: File I/O Test with Multiple Keys
print("\n4️⃣  Testing File I/O (Simulating Multiple Keys on USB)...")
print("-" * 60)

# Create test directory to simulate USB
test_usb_dir = "test_usb_multi_key"
os.makedirs(test_usb_dir, exist_ok=True)

try:
    # Generate 3 different keys
    print("Generating 3 different keys to simulate multiple users...")
    for i in range(1, 4):
        key_info = manager.generate_mfa_key(
            user_id=100 + i,
            tenant_id=4,
            email=f"user{i}@example.com"
        )
        
        # Save as mfa_key_1.json, mfa_key_2.json, etc.
        filename = f"{test_usb_dir}/mfa_key_{i}.json"
        with open(filename, 'w') as f:
            json.dump(key_info['key_data'], f, indent=2)
        print(f"   ✅ Wrote {filename}")
    
    # Now test finding all keys
    print("\nScanning simulated USB for all MFA keys...")
    all_keys = manager.find_all_mfa_keys_on_usb(test_usb_dir)
    print(f"✅ Found {len(all_keys)} keys on USB:")
    for i, key in enumerate(all_keys, 1):
        print(f"   Key {i}: user_id={key['user_id']}, email={key['email']}")
    
    # Test validation for each key
    print("\nValidating each key...")
    for i, key in enumerate(all_keys, 1):
        is_valid = manager.validate_mfa_key(
            key,
            key['user_id'],
            key['tenant_id'],
            key['email']
        )
        print(f"   {'✅' if is_valid else '❌'} Key {i}: {is_valid}")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_usb_dir)
    print(f"\n✅ Cleaned up test directory")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import shutil
    if os.path.exists(test_usb_dir):
        shutil.rmtree(test_usb_dir)

print("\n" + "=" * 60)
print("📋 MULTIPLE KEY SUPPORT")
print("=" * 60)
print("""
✨ NEW FEATURE: Multiple MFA Keys per USB!

Now you can store multiple keys on ONE USB thumbdrive:
- Generate key #1 for user A → Download as mfa_key_20260219_143022.json
- Generate key #2 for user B → Download as mfa_key_20260219_143530.json
- Copy both files to USB root: mfa_key_20260219_143022.json, mfa_key_20260219_143530.json
- At login, system checks ALL mfa_key*.json files

Benefits:
✅ Share one USB with multiple users
✅ Backup multiple keys on one drive
✅ Create USB key pairs for team members

Setup Multiple Keys:
1. Generate and download key for User A → mfa_key_DATE_TIME.json
2. Copy to USB root
3. Generate and download key for User B → mfa_key_DATE_TIME.json  
4. Copy to USB root
5. Both users can use the SAME USB for login!
""")

print("\n✅ Test Complete!")

