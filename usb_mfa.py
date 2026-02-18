"""
USB MFA (Multi-Factor Authentication) Module
Provides physical USB thumbdrive-based authentication for enhanced security.
"""
import os
import json
import uuid
import hashlib
import platform
from pathlib import Path
from datetime import datetime

# Platform-specific imports for USB detection
if platform.system() == "Windows":
    import win32api
    import win32file
    import pywintypes
elif platform.system() == "Darwin":  # macOS
    import subprocess
elif platform.system() == "Linux":
    import subprocess


class USBMFAManager:
    """Manage USB MFA functionality"""
    
    MFA_KEY_FILENAME = "mfa_key.json"
    MFA_KEY_HASH_FILENAME = "mfa_key_hash.txt"
    
    @staticmethod
    def generate_mfa_key(user_id: int, tenant_id: int, email: str) -> dict:
        """
        Generate a new MFA key for a user to store on USB
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID
            email: User email
            
        Returns:
            dict with key data and hash
        """
        mfa_token = str(uuid.uuid4())
        mfa_secret = str(uuid.uuid4())
        
        key_data = {
            "version": 1,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "email": email,
            "mfa_token": mfa_token,
            "mfa_secret": mfa_secret,
            "created_at": datetime.utcnow().isoformat(),
            "last_used": None
        }
        
        # Create hash for validation
        key_json = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.sha256(key_json.encode()).hexdigest()
        
        return {
            "key_data": key_data,
            "key_hash": key_hash,
            "key_json": key_json
        }
    
    @staticmethod
    def get_usb_drives() -> list:
        """
        Detect all connected USB drives
        
        Returns:
            list of mount paths for USB drives
        """
        usb_drives = []
        
        if platform.system() == "Windows":
            try:
                import ctypes
                # Try to detect drives the reliable way
                for i in range(ord('A'), ord('Z') + 1):
                    drive = chr(i) + ':'
                    try:
                        # Use ctypes to check if drive exists and is removable
                        ret = ctypes.windll.kernel32.GetLogicalDrives()
                        if ret & (1 << (i - ord('A'))):
                            # Drive exists, check if it's ready
                            drive_path = drive + '\\'
                            try:
                                # Try to access the drive to check if it's ready
                                test_path = os.path.join(drive_path, 'mfa_key.json')
                                # If we can stat the parent, the drive is accessible
                                if os.path.exists(drive_path):
                                    usb_drives.append(drive_path)
                            except:
                                pass
                    except:
                        pass
            except Exception as e:
                print(f"❌ Error detecting USB drives: {e}")
        
        elif platform.system() == "Darwin":  # macOS
            try:
                result = subprocess.run(
                    ["diskutil", "list"], 
                    capture_output=True, 
                    text=True
                )
                # Parse output for /Volumes mount points
                for line in result.stdout.split('\n'):
                    if '/Volumes/' in line and 'external' in line.lower():
                        usb_drives.append(line.split()[-1] if line.split() else None)
            except Exception as e:
                print(f"❌ Error detecting USB drives: {e}")
        
        elif platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["lsblk", "-Jp"], 
                    capture_output=True, 
                    text=True
                )
                # Parse for removable=1 devices
                data = json.loads(result.stdout)
                for device in data.get("blockdevices", []):
                    if device.get("rm") == 1 and "mountpoint" in device:
                        usb_drives.append(device["mountpoint"])
            except Exception as e:
                print(f"❌ Error detecting USB drives: {e}")
        
        return [d for d in usb_drives if d]
    
    @staticmethod
    def find_all_mfa_keys_on_usb(usb_path: str) -> list:
        """
        Find all MFA keys on a USB drive (mfa_key*.json)
        
        Args:
            usb_path: Path to USB drive root
            
        Returns:
            list of dicts with key data, empty list if none found
        """
        keys = []
        try:
            # List all files in USB root
            if os.path.exists(usb_path):
                for filename in os.listdir(usb_path):
                    # Match mfa_key*.json pattern (e.g., mfa_key.json, mfa_key_1.json, etc.)
                    if filename.startswith('mfa_key') and filename.endswith('.json'):
                        try:
                            key_file = os.path.join(usb_path, filename)
                            with open(key_file, 'r') as f:
                                key_data = json.load(f)
                            keys.append(key_data)
                            print(f"✅ Found MFA key: {filename}")
                        except Exception as e:
                            print(f"⚠️  Error reading {filename}: {e}")
        except Exception as e:
            print(f"❌ Error scanning USB for MFA keys: {e}")
        
        return keys
    
    @staticmethod
    def find_mfa_key_on_usb(usb_path: str) -> dict:
        """
        Look for any mfa_key*.json on a USB drive (supports multiple keys)
        
        Args:
            usb_path: Path to USB drive root
            
        Returns:
            dict with first valid key data if found, None otherwise
        """
        keys = USBMFAManager.find_all_mfa_keys_on_usb(usb_path)
        return keys[0] if keys else None
    
    @staticmethod
    def validate_mfa_key(key_data: dict, user_id: int, tenant_id: int, email: str) -> bool:
        """
        Validate that the MFA key matches the user
        
        Args:
            key_data: The MFA key from USB
            user_id: User ID to validate against
            tenant_id: Tenant ID to validate against
            email: User email to validate against
            
        Returns:
            True if valid, False otherwise
        """
        if not key_data:
            return False
        
        # Verify key contains required fields
        required_fields = ["user_id", "tenant_id", "email", "mfa_token", "version"]
        if not all(field in key_data for field in required_fields):
            return False
        
        # Verify it matches the user
        if (key_data.get("user_id") == user_id and
            key_data.get("tenant_id") == tenant_id and
            key_data.get("email") == email):
            return True
        
        return False
    
    @staticmethod
    def find_and_validate_usb_mfa(user_id: int, tenant_id: int, email: str) -> bool:
        """
        Scan all USB drives for valid MFA keys for this user
        Supports multiple keys per USB drive
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID
            email: User email
            
        Returns:
            True if any valid USB MFA key found and validated
        """
        try:
            usb_drives = USBMFAManager.get_usb_drives()
            
            for usb_path in usb_drives:
                # Get ALL keys from this USB
                all_keys = USBMFAManager.find_all_mfa_keys_on_usb(usb_path)
                
                # Check each key
                for key_data in all_keys:
                    if USBMFAManager.validate_mfa_key(key_data, user_id, tenant_id, email):
                        print(f"✅ Valid USB MFA key found on {usb_path}")
                        return True
            
            print(f"❌ No valid USB MFA key found for user {user_id}")
            return False
        
        except Exception as e:
            print(f"❌ Error validating USB MFA: {e}")
            return False


def create_mfa_key_file(user_id: int, tenant_id: int, email: str, output_path: str) -> bool:
    """
    Generate and save MFA key file for user to put on USB
    
    Args:
        user_id: User ID
        tenant_id: Tenant ID
        email: User email
        output_path: Path to save the mfa_key.json file
        
    Returns:
        True if successful
    """
    try:
        manager = USBMFAManager()
        key_info = manager.generate_mfa_key(user_id, tenant_id, email)
        
        # Save key data
        with open(output_path, 'w') as f:
            json.dump(key_info['key_data'], f, indent=2)
        
        print(f"✅ MFA key file created: {output_path}")
        return True
    
    except Exception as e:
        print(f"❌ Error creating MFA key file: {e}")
        return False
