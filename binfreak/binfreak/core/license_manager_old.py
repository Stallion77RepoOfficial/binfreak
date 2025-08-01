"""
License management system for BinFreak
"""

import os
import json
import hashlib
import platform
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple

from PyQt6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QDialogButtonBox,
    QMessageBox, QVBoxLayout, QLabel, QTextEdit
)
from PyQt6.QtCore import Qt

# License configuration
LICENSE_SERVER_URL = "https://api.binfreak.com/license"  # Placeholder URL
LICENSE_FILE = os.path.expanduser("~/.binfreak_license")


class LicenseManager:
    """Handle license validation and registration"""
    
    def __init__(self):
        self.is_licensed = False
        self.license_data = {}
        self.check_existing_license()
    
    def check_license(self) -> bool:
        """Check if license is valid"""
        return self.is_licensed
    
    def check_existing_license(self):
        """Check if valid license exists"""
        if os.path.exists(LICENSE_FILE):
            try:
                with open(LICENSE_FILE, 'r') as f:
                    self.license_data = json.load(f)
                
                # Check expiration
                expiry = datetime.fromisoformat(self.license_data.get('expiry', ''))
                if expiry > datetime.now():
                    self.is_licensed = True
                    return True
            except:
                pass
        return False
    
    def register_license(self, email: str, password: str) -> Tuple[bool, str]:
        """Register with email and password"""
        try:
            # Generate hardware fingerprint
            fingerprint = self.get_hardware_fingerprint()
            
            # Create offline license for open-source version
            if email and password and len(password) >= 6:
                license_data = {
                    'email': email,
                    'registered': datetime.now().isoformat(),
                    'expiry': (datetime.now() + timedelta(days=9999)).isoformat(),  # Long expiry for open source
                    'fingerprint': fingerprint,
                    'features': ['full_analysis', 'fuzzing', 'visualization'],
                    'type': 'opensource'
                }
                
                with open(LICENSE_FILE, 'w') as f:
                    json.dump(license_data, f, indent=2)
                
                self.license_data = license_data
                self.is_licensed = True
                return True, "Open-source license activated successfully!"
            else:
                return False, "Invalid email or password (minimum 6 characters)"
                
        except Exception as e:
            return False, f"License activation failed: {str(e)}"
    
    def get_hardware_fingerprint(self) -> str:
        """Generate unique hardware fingerprint"""
        info = f"{platform.machine()}-{platform.processor()}-{uuid.getnode()}"
        return hashlib.sha256(info.encode()).hexdigest()[:16]
    
    def get_license_info(self) -> Dict[str, Any]:
        """Get current license information"""
        if self.is_licensed:
            return {
                'status': 'Licensed',
                'email': self.license_data.get('email', 'Unknown'),
                'expiry': self.license_data.get('expiry', 'Unknown'),
                'features': self.license_data.get('features', [])
            }
        return {'status': 'Unlicensed'}


class RegistrationDialog(QDialog):
    """License registration dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("BinFreak License Registration")
        self.setModal(True)
        self.resize(400, 200)
        
        layout = QFormLayout(self)
        
        self.email_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        layout.addRow("Email:", self.email_edit)
        layout.addRow("Password:", self.password_edit)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_credentials(self):
        """Get entered credentials"""
        return self.email_edit.text(), self.password_edit.text()


class LicenseStatusDialog(QDialog):
    """License status display dialog"""
    
    def __init__(self, license_info: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.setWindowTitle("License Status")
        self.setModal(True)
        self.resize(500, 300)
        
        layout = QVBoxLayout(self)
        
        if license_info['status'] == 'Licensed':
            status_text = f"""
License Status: ✓ Active

Email: {license_info['email']}
Expires: {license_info['expiry']}

Licensed Features:
• Full Binary Analysis
• Advanced Visualization  
• Fuzzing Engine
• Enterprise Support
• Priority Updates
            """.strip()
        else:
            status_text = """
License Status: ✗ Unlicensed

You are using BinFreak in limited mode.

To unlock all features:
• Advanced binary analysis
• Interactive visualizations
• Fuzzing capabilities
• Professional support

Please register a license to continue.
            """.strip()
        
        info_label = QTextEdit()
        info_label.setPlainText(status_text)
        info_label.setReadOnly(True)
        layout.addWidget(info_label)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
