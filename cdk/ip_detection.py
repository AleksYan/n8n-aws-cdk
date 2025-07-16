"""
IP Detection Service for n8n CDK Deployment

This module provides functionality to validate IP addresses and CIDR blocks
for security group configuration in the secure-by-default approach.
"""

import re
import os
import json
import urllib.request
import urllib.error
from typing import Optional, List
from ipaddress import ip_address, ip_network, AddressValueError


class IPDetectionService:
    """Service for detecting and validating IP addresses for access control."""
    
    # External IP detection services (fallbacks)
    IP_DETECTION_SERVICES = [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://icanhazip.com",
        "https://ipecho.net/plain"
    ]
    
    def __init__(self):
        """Initialize the IP detection service."""
        pass
    
    def get_current_public_ip(self) -> Optional[str]:
        """
        Get the current public IP address (utility function).
        
        This is provided as a utility function for users who want to get their current IP,
        but is not used for automatic IP detection during deployment.
        
        Returns:
            str: The detected public IP address, or None if detection fails
        """
        # Try external IP detection services
        for service_url in self.IP_DETECTION_SERVICES:
            try:
                ip = self._detect_ip_from_service(service_url)
                if ip and self.validate_ip_address(ip):
                    return ip
            except Exception as e:
                continue
        
        return None
    
    def _detect_ip_from_service(self, service_url: str, timeout: int = 10) -> Optional[str]:
        """
        Detect IP address from an external service.
        
        Args:
            service_url: URL of the IP detection service
            timeout: Request timeout in seconds
            
        Returns:
            str: Detected IP address or None if failed
        """
        try:
            with urllib.request.urlopen(service_url, timeout=timeout) as response:
                ip = response.read().decode('utf-8').strip()
                return ip
        except (urllib.error.URLError, urllib.error.HTTPError, Exception) as e:
            raise Exception(f"Service request failed: {e}")
    
    def validate_ip_address(self, ip: str) -> bool:
        """
        Validate if a string is a valid IP address.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            bool: True if valid IP address, False otherwise
        """
        try:
            ip_address(ip)
            return True
        except (AddressValueError, ValueError):
            return False
    
    def validate_cidr_block(self, cidr: str) -> bool:
        """
        Validate if a string is a valid CIDR block.
        
        Args:
            cidr: CIDR block string to validate (e.g., "192.168.1.0/24")
            
        Returns:
            bool: True if valid CIDR block, False otherwise
        """
        try:
            ip_network(cidr, strict=False)
            return True
        except (AddressValueError, ValueError):
            return False
    
    def normalize_ip_for_security_group(self, ip: str) -> str:
        """
        Normalize IP address for security group rules.
        
        Single IP addresses need /32 suffix for security groups.
        
        Args:
            ip: IP address or CIDR block
            
        Returns:
            str: Normalized IP/CIDR for security group rules
        """
        # Check if it's already a CIDR block (contains '/')
        if '/' in ip and self.validate_cidr_block(ip):
            return ip
        elif self.validate_ip_address(ip):
            return f"{ip}/32"
        else:
            raise ValueError(f"Invalid IP address or CIDR block: {ip}")
    
    def is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is in a private range.
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if IP is private, False if public
        """
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_private
        except AddressValueError:
            return False
    
    def get_ip_info(self, ip: str) -> dict:
        """
        Get information about an IP address.
        
        Args:
            ip: IP address to analyze
            
        Returns:
            dict: Information about the IP address
        """
        info = {
            'ip': ip,
            'valid': False,
            'private': False,
            'normalized': None,
            'warnings': []
        }
        
        # Check if it contains '/' - likely a CIDR block
        if '/' in ip and self.validate_cidr_block(ip):
            info['valid'] = True
            info['normalized'] = ip
            # Check if CIDR contains private ranges
            try:
                network = ip_network(ip, strict=False)
                if network.is_private:
                    info['private'] = True
                    info['warnings'].append("Private CIDR block detected")
            except:
                pass
        elif self.validate_ip_address(ip):
            info['valid'] = True
            info['private'] = self.is_private_ip(ip)
            info['normalized'] = self.normalize_ip_for_security_group(ip)
            
            if info['private']:
                info['warnings'].append("Private IP detected - may not work for external access")
        else:
            info['warnings'].append("Invalid IP address or CIDR block format")
        
        return info
    
    def validate_ip_list(self, ip_list: List[str]) -> dict:
        """
        Validate a list of IP addresses and CIDR blocks.
        
        Args:
            ip_list: List of IP addresses/CIDR blocks to validate
            
        Returns:
            dict: Validation results with valid IPs and errors
        """
        results = {
            'valid_ips': [],
            'invalid_ips': [],
            'warnings': [],
            'normalized_ips': []
        }
        
        for ip in ip_list:
            info = self.get_ip_info(ip.strip())
            
            if info['valid']:
                results['valid_ips'].append(ip)
                results['normalized_ips'].append(info['normalized'])
                results['warnings'].extend(info['warnings'])
            else:
                results['invalid_ips'].append(ip)
                results['warnings'].extend(info['warnings'])
        
        return results


def main():
    """Test the IP detection service."""
    service = IPDetectionService()
    
    print("=== IP Detection Service Test ===")
    
    # Test current IP detection
    current_ip = service.get_current_public_ip()
    if current_ip:
        print(f"Current public IP: {current_ip}")
        info = service.get_ip_info(current_ip)
        print(f"IP info: {json.dumps(info, indent=2)}")
    else:
        print("Could not detect current IP")
    
    # Test IP validation
    test_ips = [
        "192.168.1.1",
        "203.0.113.1",
        "192.168.1.0/24",
        "203.0.113.0/24",
        "invalid-ip",
        "256.256.256.256"
    ]
    
    print("\n=== IP Validation Tests ===")
    for test_ip in test_ips:
        info = service.get_ip_info(test_ip)
        print(f"{test_ip}: {info}")
    
    # Test IP list validation
    print("\n=== IP List Validation Test ===")
    results = service.validate_ip_list(test_ips)
    print(f"Validation results: {json.dumps(results, indent=2)}")


if __name__ == "__main__":
    main()