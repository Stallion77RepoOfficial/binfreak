"""
Simplified License Manager - Removed unnecessary complexity
"""

from typing import Dict, Any


class SimpleLicenseManager:
    """Simplified license manager for open-source tool"""
    
    def __init__(self):
        # For open-source version, always licensed
        self.is_licensed = True
        self.license_info = {
            'status': 'Open Source',
            'version': 'Community Edition',
            'features': ['analysis', 'visualization', 'basic_tools']
        }
    
    def check_license(self) -> bool:
        """Check if license is valid (always True for open source)"""
        return True
    
    def get_license_info(self) -> Dict[str, Any]:
        """Get license information"""
        return self.license_info
    
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if feature is enabled (all features enabled in open source)"""
        return True