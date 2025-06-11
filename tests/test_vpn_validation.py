import pytest
import json
from pineapple_detector import PineappleDetector

def test_vpn_connection_method_exists():
    """Verify that the validate_vpn_connection method exists."""
    detector = PineappleDetector()
    assert hasattr(detector, 'validate_vpn_connection'), "Method validate_vpn_connection not found"

def test_vpn_connection_returns_expected_structure():
    """Test that the method returns a dictionary with expected keys."""
    detector = PineappleDetector()
    result = detector.validate_vpn_connection()
    
    assert isinstance(result, dict), "Result should be a dictionary"
    expected_keys = {
        'is_connected',
        'security_status',
        'details',
        'warnings'
    }
    assert all(key in result for key in expected_keys), "Missing expected keys in result"

def test_vpn_connection_details_types():
    """Verify types of values in the VPN connection result."""
    detector = PineappleDetector()
    result = detector.validate_vpn_connection()
    
    assert isinstance(result['is_connected'], bool), "is_connected should be a boolean"
    assert isinstance(result['security_status'], str), "security_status should be a string"
    assert isinstance(result['details'], dict), "details should be a dictionary"
    assert isinstance(result['warnings'], list), "warnings should be a list"

def test_vpn_connection_method_is_deterministic():
    """Ensure repeated calls to the method produce consistent overall behavior."""
    detector = PineappleDetector()
    
    results = [detector.validate_vpn_connection() for _ in range(3)]
    
    # Check that is_connected remains consistent across calls
    is_connected_values = [result['is_connected'] for result in results]
    assert len(set(is_connected_values)) <= 1, "VPN connection status should be stable"

def test_vpn_connection_warnings_format():
    """Validate the format of warnings."""
    detector = PineappleDetector()
    result = detector.validate_vpn_connection()
    
    for warning in result['warnings']:
        assert isinstance(warning, str), f"Warning must be a string: {warning}"
        assert len(warning) > 0, "Warning cannot be an empty string"

# Optional: Add more specific tests based on implementation nuances
def test_vpn_connection_details_optional_fields():
    """Check optional details in the result."""
    detector = PineappleDetector()
    result = detector.validate_vpn_connection()
    
    # These are optional, so they might not always be present
    optional_detail_keys = ['public_ip', 'country', 'org', 'vpn_interface']
    for key in optional_detail_keys:
        if key in result['details']:
            assert isinstance(result['details'][key], str), f"{key} should be a string if present"