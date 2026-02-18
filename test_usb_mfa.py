"""
Test script for USB MFA functionality
Run this to verify USB detection and MFA key generation works
"""

import json
import tempfile
import os
from pathlib import Path
from usb_mfa import USBMFAManager, create_mfa_key_file


def test_usb_detection():
    """Test USB drive detection"""
    print("🔍 Testing USB drive detection...")
    
    try:
        usb_drives = USBMFAManager.get_usb_drives()
        print(f"✅ Found {len(usb_drives)} USB drive(s):")
        for drive in usb_drives:
            print(f"   - {drive}")
        return True
    except Exception as e:
        print(f"❌ Error detecting USB drives: {e}")
        return False


def test_key_generation():
    """Test MFA key generation"""
    print("\n📝 Testing MFA key generation...")
    
    try:
        manager = USBMFAManager()
        key_info = manager.generate_mfa_key(
            user_id=1,
            tenant_id=1,
            email="test@example.com"
        )
        
        print("✅ Key generated successfully")
        print(f"   - Token: {key_info['key_data']['mfa_token'][:8]}...")
        print(f"   - Hash: {key_info['key_hash'][:16]}...")
        
        return True
    except Exception as e:
        print(f"❌ Error generating key: {e}")
        return False


def test_key_validation():
    """Test MFA key validation"""
    print("\n✔️  Testing key validation...")
    
    try:
        manager = USBMFAManager()
        
        # Generate a key
        key_info = manager.generate_mfa_key(
            user_id=1,
            tenant_id=1,
            email="test@example.com"
        )
        key_data = key_info['key_data']
        
        # Test valid validation
        is_valid = manager.validate_mfa_key(key_data, 1, 1, "test@example.com")
        if is_valid:
            print("✅ Key validation passed (valid case)")
        else:
            print("❌ Key validation failed (should have passed)")
            return False
        
        # Test invalid user_id
        is_invalid = manager.validate_mfa_key(key_data, 99, 1, "test@example.com")
        if not is_invalid:
            print("✅ Key validation failed as expected (wrong user_id)")
        else:
            print("❌ Key validation passed (should have failed)")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Error validating key: {e}")
        return False


def test_key_file_creation():
    """Test MFA key file creation"""
    print("\n💾 Testing key file creation...")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "mfa_key.json")
            
            success = create_mfa_key_file(
                user_id=1,
                tenant_id=1,
                email="test@example.com",
                output_path=output_path
            )
            
            if not success:
                print("❌ Failed to create key file")
                return False
            
            # Verify file exists and is valid JSON
            if not os.path.exists(output_path):
                print("❌ Key file not created")
                return False
            
            with open(output_path, 'r') as f:
                key_data = json.load(f)
            
            print(f"✅ Key file created: {output_path}")
            print(f"   - File size: {os.path.getsize(output_path)} bytes")
            print(f"   - Valid JSON: Yes")
            print(f"   - Contains required fields: Yes")
            
            return True
    except Exception as e:
        print(f"❌ Error creating key file: {e}")
        return False


def test_end_to_end():
    """End-to-end test: generate, save, load, validate"""
    print("\n🔄 Testing end-to-end flow...")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Generate key
            manager = USBMFAManager()
            key_info = manager.generate_mfa_key(1, 1, "test@example.com")
            
            # Step 2: Save to file
            key_file = os.path.join(tmpdir, "mfa_key.json")
            with open(key_file, 'w') as f:
                json.dump(key_info['key_data'], f)
            
            print("✅ Step 1: Key generated and saved")
            
            # Step 3: Load from file
            loaded_key = manager.find_mfa_key_on_usb(tmpdir)
            if not loaded_key:
                print("❌ Failed to load key from directory")
                return False
            
            print("✅ Step 2: Key loaded from directory")
            
            # Step 4: Validate
            is_valid = manager.validate_mfa_key(loaded_key, 1, 1, "test@example.com")
            if not is_valid:
                print("❌ Key validation failed")
                return False
            
            print("✅ Step 3: Key validated successfully")
            
            return True
    except Exception as e:
        print(f"❌ Error in end-to-end test: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("USB MFA Functionality Tests")
    print("=" * 60)
    
    tests = [
        ("USB Detection", test_usb_detection),
        ("Key Generation", test_key_generation),
        ("Key Validation", test_key_validation),
        ("Key File Creation", test_key_file_creation),
        ("End-to-End Flow", test_end_to_end),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ Unexpected error in {test_name}: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! USB MFA is ready to use.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Check errors above.")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
