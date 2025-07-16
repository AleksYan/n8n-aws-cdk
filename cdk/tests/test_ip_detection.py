"""
Unit tests for IP Detection Service

Tests the functionality of IP detection, validation, and normalization
for the n8n CDK deployment security features.
"""

import unittest
import os
from unittest.mock import patch, mock_open
import urllib.error

# Import the module to test
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ip_detection import IPDetectionService


class TestIPDetectionService(unittest.TestCase):
    """Test cases for IPDetectionService class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = IPDetectionService()
    
    def test_validate_ip_address_valid(self):
        """Test validation of valid IP addresses."""
        valid_ips = [
            "192.168.1.1",
            "203.0.113.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.1.1.1"
        ]
        
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(self.service.validate_ip_address(ip))
    
    def test_validate_ip_address_invalid(self):
        """Test validation of invalid IP addresses."""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "invalid-ip",
            "",
            "192.168.1.256",
            "192.168.-1.1"
        ]
        
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(self.service.validate_ip_address(ip))
    
    def test_validate_cidr_block_valid(self):
        """Test validation of valid CIDR blocks."""
        valid_cidrs = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "203.0.113.0/24",
            "192.168.1.1/32",
            "0.0.0.0/0"
        ]
        
        for cidr in valid_cidrs:
            with self.subTest(cidr=cidr):
                self.assertTrue(self.service.validate_cidr_block(cidr))
    
    def test_validate_cidr_block_invalid(self):
        """Test validation of invalid CIDR blocks."""
        invalid_cidrs = [
            "192.168.1.0/33",
            "192.168.1.0/-1",
            "256.256.256.0/24",
            "invalid-cidr/24",
            "192.168.1.0/abc"
        ]
        
        for cidr in invalid_cidrs:
            with self.subTest(cidr=cidr):
                self.assertFalse(self.service.validate_cidr_block(cidr))
    
    def test_normalize_ip_for_security_group(self):
        """Test IP normalization for security group rules."""
        test_cases = [
            ("192.168.1.1", "192.168.1.1/32"),
            ("192.168.1.0/24", "192.168.1.0/24"),
            ("203.0.113.1", "203.0.113.1/32"),
            ("10.0.0.0/8", "10.0.0.0/8")
        ]
        
        for input_ip, expected in test_cases:
            with self.subTest(input_ip=input_ip):
                result = self.service.normalize_ip_for_security_group(input_ip)
                self.assertEqual(result, expected)
    
    def test_normalize_ip_invalid(self):
        """Test normalization with invalid IP addresses."""
        invalid_ips = ["invalid-ip", "256.256.256.256", ""]
        
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    self.service.normalize_ip_for_security_group(ip)
    
    def test_is_private_ip(self):
        """Test private IP detection."""
        private_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "203.0.113.1"  # Documentation range, considered private by Python
        ]
        
        public_ips = [
            "8.8.8.8",
            "1.1.1.1"
        ]
        
        for ip in private_ips:
            with self.subTest(ip=ip):
                self.assertTrue(self.service.is_private_ip(ip))
        
        for ip in public_ips:
            with self.subTest(ip=ip):
                self.assertFalse(self.service.is_private_ip(ip))
    
    def test_get_ip_info_valid_public(self):
        """Test IP info for valid public IP."""
        ip = "8.8.8.8"  # Use a truly public IP
        info = self.service.get_ip_info(ip)
        
        self.assertEqual(info['ip'], ip)
        self.assertTrue(info['valid'])
        self.assertFalse(info['private'])
        self.assertEqual(info['normalized'], "8.8.8.8/32")
        self.assertEqual(len(info['warnings']), 0)
    
    def test_get_ip_info_valid_private(self):
        """Test IP info for valid private IP."""
        ip = "192.168.1.1"
        info = self.service.get_ip_info(ip)
        
        self.assertEqual(info['ip'], ip)
        self.assertTrue(info['valid'])
        self.assertTrue(info['private'])
        self.assertEqual(info['normalized'], "192.168.1.1/32")
        self.assertIn("Private IP detected", info['warnings'][0])
    
    def test_get_ip_info_invalid(self):
        """Test IP info for invalid IP."""
        ip = "invalid-ip"
        info = self.service.get_ip_info(ip)
        
        self.assertEqual(info['ip'], ip)
        self.assertFalse(info['valid'])
        self.assertFalse(info['private'])
        self.assertIsNone(info['normalized'])
        self.assertIn("Invalid IP address", info['warnings'][0])
    
    def test_validate_ip_list(self):
        """Test validation of IP address list."""
        ip_list = [
            "203.0.113.1",      # Valid public IP
            "192.168.1.0/24",   # Valid private CIDR
            "invalid-ip",       # Invalid IP
            "8.8.8.8"          # Valid public IP
        ]
        
        results = self.service.validate_ip_list(ip_list)
        
        self.assertEqual(len(results['valid_ips']), 3)
        self.assertEqual(len(results['invalid_ips']), 1)
        self.assertIn("203.0.113.1", results['valid_ips'])
        self.assertIn("192.168.1.0/24", results['valid_ips'])
        self.assertIn("8.8.8.8", results['valid_ips'])
        self.assertIn("invalid-ip", results['invalid_ips'])
        
        # Check normalized IPs
        self.assertIn("203.0.113.1/32", results['normalized_ips'])
        self.assertIn("192.168.1.0/24", results['normalized_ips'])
        self.assertIn("8.8.8.8/32", results['normalized_ips'])
    
    # Removed test_get_current_public_ip_manual_override as it's no longer relevant
    # Removed test_get_current_public_ip_invalid_manual as it's no longer relevant
    
    @patch('urllib.request.urlopen')
    def test_detect_ip_from_service_success(self, mock_urlopen):
        """Test successful IP detection from service."""
        # Mock the response
        mock_response = mock_open(read_data=b'203.0.113.1\n')
        mock_urlopen.return_value.__enter__.return_value = mock_response.return_value
        
        ip = self.service._detect_ip_from_service('https://api.ipify.org')
        self.assertEqual(ip, '203.0.113.1')
    
    @patch('urllib.request.urlopen')
    def test_detect_ip_from_service_failure(self, mock_urlopen):
        """Test IP detection service failure."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection failed")
        
        with self.assertRaises(Exception):
            self.service._detect_ip_from_service('https://api.ipify.org')
    
    @patch.object(IPDetectionService, '_detect_ip_from_service')
    def test_get_current_public_ip_fallback(self, mock_detect):
        """Test fallback between multiple IP detection services."""
        # First service fails, second succeeds
        mock_detect.side_effect = [
            Exception("First service failed"),
            "203.0.113.1"
        ]
        
        ip = self.service.get_current_public_ip()
        self.assertEqual(ip, "203.0.113.1")
        self.assertEqual(mock_detect.call_count, 2)
    
    @patch.object(IPDetectionService, '_detect_ip_from_service')
    def test_get_current_public_ip_all_fail(self, mock_detect):
        """Test when all IP detection services fail."""
        mock_detect.side_effect = Exception("All services failed")
        
        ip = self.service.get_current_public_ip()
        self.assertIsNone(ip)


class TestIPDetectionServiceEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = IPDetectionService()
    
    def test_empty_ip_list(self):
        """Test validation of empty IP list."""
        results = self.service.validate_ip_list([])
        
        self.assertEqual(len(results['valid_ips']), 0)
        self.assertEqual(len(results['invalid_ips']), 0)
        self.assertEqual(len(results['normalized_ips']), 0)
    
    def test_whitespace_in_ips(self):
        """Test handling of whitespace in IP addresses."""
        ip_list = [
            " 203.0.113.1 ",
            "\t192.168.1.0/24\n",
            "  8.8.8.8  "
        ]
        
        results = self.service.validate_ip_list(ip_list)
        
        self.assertEqual(len(results['valid_ips']), 3)
        self.assertEqual(len(results['invalid_ips']), 0)
    
    def test_cidr_with_host_bits(self):
        """Test CIDR blocks with host bits set."""
        # This should be valid (non-strict mode)
        cidr = "192.168.1.1/24"
        self.assertTrue(self.service.validate_cidr_block(cidr))
    
    def test_ipv6_addresses(self):
        """Test IPv6 address handling."""
        ipv6_addresses = [
            "2001:db8::1",
            "::1",
            "2001:db8::/32"
        ]
        
        for ipv6 in ipv6_addresses:
            with self.subTest(ipv6=ipv6):
                # IPv6 should be valid but may need special handling
                info = self.service.get_ip_info(ipv6)
                # The service should handle IPv6 gracefully
                self.assertIsInstance(info, dict)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)