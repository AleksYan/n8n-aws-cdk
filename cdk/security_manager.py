"""
Security Group Manager for n8n CDK Deployment

This module provides functionality to manage AWS security groups for IP-based
access control, including creating, updating, and managing security group rules.
"""

import boto3
from typing import List, Dict, Optional, Tuple
from aws_cdk import (
    aws_ec2 as ec2,
    CfnOutput,
)
from constructs import Construct
from ip_detection import IPDetectionService


class SecurityGroupManager:
    """Manager for AWS security groups with IP-based access control."""
    
    def __init__(self, scope: Construct, vpc: ec2.Vpc):
        """
        Initialize the Security Group Manager.
        
        Args:
            scope: CDK construct scope
            vpc: VPC where security groups will be created
        """
        self.scope = scope
        self.vpc = vpc
        self.ip_service = IPDetectionService()
        self._ec2_client = None
    
    @property
    def ec2_client(self):
        """Lazy initialization of EC2 client for runtime operations."""
        if self._ec2_client is None:
            self._ec2_client = boto3.client('ec2')
        return self._ec2_client
    
    def create_alb_security_group(self, allowed_ips: List[str], construct_id: str = "N8nALBSecurityGroup") -> ec2.SecurityGroup:
        """
        Create ALB security group with IP restrictions.
        
        Args:
            allowed_ips: List of IP addresses/CIDR blocks to allow
            construct_id: CDK construct ID for the security group
            
        Returns:
            ec2.SecurityGroup: Created security group
        """
        # Validate and normalize IP addresses
        validation_results = self.ip_service.validate_ip_list(allowed_ips)
        
        if validation_results['invalid_ips']:
            raise ValueError(f"Invalid IP addresses found: {validation_results['invalid_ips']}")
        
        if validation_results['warnings']:
            for warning in validation_results['warnings']:
                print(f"Warning: {warning}")
        
        # Create ALB security group
        alb_security_group = ec2.SecurityGroup(
            self.scope, construct_id,
            vpc=self.vpc,
            description="Security group for n8n ALB with IP restrictions",
            allow_all_outbound=True
        )
        
        # Add ingress rules for each allowed IP
        normalized_ips = validation_results['normalized_ips']
        for i, ip in enumerate(normalized_ips):
            # HTTP access
            alb_security_group.add_ingress_rule(
                ec2.Peer.ipv4(ip),
                ec2.Port.tcp(80),
                f"HTTP access from {allowed_ips[i]}"
            )
            
            # HTTPS access
            alb_security_group.add_ingress_rule(
                ec2.Peer.ipv4(ip),
                ec2.Port.tcp(443),
                f"HTTPS access from {allowed_ips[i]}"
            )
        
        return alb_security_group
    
    def create_ecs_security_group(self, alb_security_group: ec2.SecurityGroup, construct_id: str = "N8nECSSecurityGroup") -> ec2.SecurityGroup:
        """
        Create ECS security group that only accepts traffic from ALB.
        
        Args:
            alb_security_group: ALB security group to allow traffic from
            construct_id: CDK construct ID for the security group
            
        Returns:
            ec2.SecurityGroup: Created ECS security group
        """
        ecs_security_group = ec2.SecurityGroup(
            self.scope, construct_id,
            vpc=self.vpc,
            description="Security group for n8n ECS tasks - ALB access only",
            allow_all_outbound=True
        )
        
        # Allow traffic from ALB security group on n8n port (5678)
        ecs_security_group.add_ingress_rule(
            ec2.Peer.security_group_id(alb_security_group.security_group_id),
            ec2.Port.tcp(5678),
            "Allow traffic from ALB to n8n"
        )
        
        return ecs_security_group
    
    def create_security_group_outputs(self, alb_sg: ec2.SecurityGroup, ecs_sg: ec2.SecurityGroup, allowed_ips: List[str]) -> None:
        """
        Create CDK outputs for security group information.
        
        Args:
            alb_sg: ALB security group
            ecs_sg: ECS security group
            allowed_ips: List of allowed IP addresses
        """
        # Output ALB security group ID
        CfnOutput(
            self.scope, "ALBSecurityGroupId",
            value=alb_sg.security_group_id,
            description="Security Group ID for ALB (for IP management)"
        )
        
        # Output ECS security group ID
        CfnOutput(
            self.scope, "ECSSecurityGroupId",
            value=ecs_sg.security_group_id,
            description="Security Group ID for ECS tasks"
        )
        
        # Output allowed IPs
        CfnOutput(
            self.scope, "AllowedIPs",
            value=", ".join(allowed_ips),
            description="Currently allowed IP addresses for access"
        )
    
    def update_allowed_ips(self, security_group_id: str, new_ips: List[str], ports: List[int] = [80, 443]) -> Dict[str, any]:
        """
        Update security group rules with new IP list (runtime operation).
        
        This method completely replaces existing IP-based rules with new ones.
        
        Args:
            security_group_id: AWS security group ID
            new_ips: New list of IP addresses/CIDR blocks
            ports: List of ports to allow (default: [80, 443])
            
        Returns:
            dict: Operation results with success status and details
        """
        try:
            # Validate new IPs
            validation_results = self.ip_service.validate_ip_list(new_ips)
            
            if validation_results['invalid_ips']:
                return {
                    'success': False,
                    'error': f"Invalid IP addresses: {validation_results['invalid_ips']}",
                    'warnings': validation_results['warnings']
                }
            
            # Get current security group rules
            current_rules = self._get_current_ip_rules(security_group_id, ports)
            
            # Remove old IP-based rules
            if current_rules:
                self._remove_security_group_rules(security_group_id, current_rules)
            
            # Add new IP-based rules
            normalized_ips = validation_results['normalized_ips']
            new_rules = self._create_ip_rules(normalized_ips, ports)
            self._add_security_group_rules(security_group_id, new_rules)
            
            return {
                'success': True,
                'added_ips': new_ips,
                'normalized_ips': normalized_ips,
                'warnings': validation_results['warnings'],
                'rules_added': len(new_rules),
                'rules_removed': len(current_rules)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'warnings': []
            }
    
    def add_ip_address(self, security_group_id: str, ip: str, ports: List[int] = [80, 443]) -> Dict[str, any]:
        """
        Add a single IP address to security group (runtime operation).
        
        Args:
            security_group_id: AWS security group ID
            ip: IP address or CIDR block to add
            ports: List of ports to allow (default: [80, 443])
            
        Returns:
            dict: Operation results
        """
        try:
            # Validate IP
            ip_info = self.ip_service.get_ip_info(ip)
            
            if not ip_info['valid']:
                return {
                    'success': False,
                    'error': f"Invalid IP address: {ip}",
                    'warnings': ip_info['warnings']
                }
            
            # Check if IP already exists
            current_rules = self._get_current_ip_rules(security_group_id, ports)
            normalized_ip = ip_info['normalized']
            
            for rule in current_rules:
                if rule['CidrIpv4'] == normalized_ip:
                    return {
                        'success': False,
                        'error': f"IP address {ip} already exists in security group",
                        'warnings': ip_info['warnings']
                    }
            
            # Add new rules for the IP
            new_rules = self._create_ip_rules([normalized_ip], ports)
            self._add_security_group_rules(security_group_id, new_rules)
            
            return {
                'success': True,
                'added_ip': ip,
                'normalized_ip': normalized_ip,
                'warnings': ip_info['warnings'],
                'rules_added': len(new_rules)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'warnings': []
            }
    
    def remove_ip_address(self, security_group_id: str, ip: str, ports: List[int] = [80, 443]) -> Dict[str, any]:
        """
        Remove a single IP address from security group (runtime operation).
        
        Args:
            security_group_id: AWS security group ID
            ip: IP address or CIDR block to remove
            ports: List of ports to check (default: [80, 443])
            
        Returns:
            dict: Operation results
        """
        try:
            # Normalize IP for comparison
            ip_info = self.ip_service.get_ip_info(ip)
            
            if not ip_info['valid']:
                return {
                    'success': False,
                    'error': f"Invalid IP address: {ip}",
                    'warnings': ip_info['warnings']
                }
            
            normalized_ip = ip_info['normalized']
            
            # Find rules to remove
            current_rules = self._get_current_ip_rules(security_group_id, ports)
            rules_to_remove = [
                rule for rule in current_rules 
                if rule['CidrIpv4'] == normalized_ip
            ]
            
            if not rules_to_remove:
                return {
                    'success': False,
                    'error': f"IP address {ip} not found in security group",
                    'warnings': ip_info['warnings']
                }
            
            # Remove the rules
            self._remove_security_group_rules(security_group_id, rules_to_remove)
            
            return {
                'success': True,
                'removed_ip': ip,
                'normalized_ip': normalized_ip,
                'warnings': ip_info['warnings'],
                'rules_removed': len(rules_to_remove)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'warnings': []
            }
    
    def list_allowed_ips(self, security_group_id: str, ports: List[int] = [80, 443]) -> Dict[str, any]:
        """
        List all currently allowed IP addresses in security group.
        
        Args:
            security_group_id: AWS security group ID
            ports: List of ports to check (default: [80, 443])
            
        Returns:
            dict: List of allowed IPs and details
        """
        try:
            current_rules = self._get_current_ip_rules(security_group_id, ports)
            
            # Extract unique IP addresses
            allowed_ips = list(set([rule['CidrIpv4'] for rule in current_rules]))
            
            # Group rules by IP for detailed info
            ip_details = {}
            for rule in current_rules:
                ip = rule['CidrIpv4']
                if ip not in ip_details:
                    ip_details[ip] = {
                        'ip': ip,
                        'ports': [],
                        'descriptions': []
                    }
                
                ip_details[ip]['ports'].append(rule['FromPort'])
                if rule.get('Description'):
                    ip_details[ip]['descriptions'].append(rule['Description'])
            
            return {
                'success': True,
                'allowed_ips': allowed_ips,
                'ip_details': ip_details,
                'total_rules': len(current_rules)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'allowed_ips': [],
                'ip_details': {}
            }
    
    def batch_update_ips(self, security_group_id: str, add_ips: List[str] = None, remove_ips: List[str] = None, ports: List[int] = [80, 443]) -> Dict[str, any]:
        """
        Perform batch IP address updates (add and remove in single operation).
        
        Args:
            security_group_id: AWS security group ID
            add_ips: List of IP addresses to add
            remove_ips: List of IP addresses to remove
            ports: List of ports to manage (default: [80, 443])
            
        Returns:
            dict: Batch operation results
        """
        results = {
            'success': True,
            'added': [],
            'removed': [],
            'errors': [],
            'warnings': []
        }
        
        # Remove IPs first
        if remove_ips:
            for ip in remove_ips:
                result = self.remove_ip_address(security_group_id, ip, ports)
                if result['success']:
                    results['removed'].append(ip)
                    results['warnings'].extend(result.get('warnings', []))
                else:
                    results['errors'].append(f"Failed to remove {ip}: {result['error']}")
                    results['success'] = False
        
        # Add IPs second
        if add_ips:
            for ip in add_ips:
                result = self.add_ip_address(security_group_id, ip, ports)
                if result['success']:
                    results['added'].append(ip)
                    results['warnings'].extend(result.get('warnings', []))
                else:
                    results['errors'].append(f"Failed to add {ip}: {result['error']}")
                    results['success'] = False
        
        return results
    
    def _get_current_ip_rules(self, security_group_id: str, ports: List[int]) -> List[Dict]:
        """Get current IP-based ingress rules for specified ports."""
        try:
            response = self.ec2_client.describe_security_groups(
                GroupIds=[security_group_id]
            )
            
            if not response['SecurityGroups']:
                return []
            
            security_group = response['SecurityGroups'][0]
            ip_rules = []
            
            for rule in security_group['IpPermissions']:
                # Check if rule is for one of our target ports
                if rule['FromPort'] in ports and rule['ToPort'] in ports:
                    # Extract IP-based rules (ignore security group references)
                    for ip_range in rule.get('IpRanges', []):
                        ip_rules.append({
                            'IpProtocol': rule['IpProtocol'],
                            'FromPort': rule['FromPort'],
                            'ToPort': rule['ToPort'],
                            'CidrIpv4': ip_range['CidrIp'],
                            'Description': ip_range.get('Description', '')
                        })
            
            return ip_rules
            
        except Exception as e:
            raise Exception(f"Failed to get current security group rules: {e}")
    
    def _create_ip_rules(self, ips: List[str], ports: List[int]) -> List[Dict]:
        """Create security group rule objects for given IPs and ports."""
        rules = []
        
        for ip in ips:
            for port in ports:
                rules.append({
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{
                        'CidrIp': ip,
                        'Description': f'Access from {ip} on port {port}'
                    }]
                })
        
        return rules
    
    def _add_security_group_rules(self, security_group_id: str, rules: List[Dict]) -> None:
        """Add ingress rules to security group."""
        if not rules:
            return
        
        try:
            self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=rules
            )
        except Exception as e:
            raise Exception(f"Failed to add security group rules: {e}")
    
    def _remove_security_group_rules(self, security_group_id: str, rules: List[Dict]) -> None:
        """Remove ingress rules from security group."""
        if not rules:
            return
        
        # Convert rule format for revoke operation
        revoke_rules = []
        for rule in rules:
            revoke_rules.append({
                'IpProtocol': rule['IpProtocol'],
                'FromPort': rule['FromPort'],
                'ToPort': rule['ToPort'],
                'IpRanges': [{
                    'CidrIp': rule['CidrIpv4'],
                    'Description': rule.get('Description', '')
                }]
            })
        
        try:
            self.ec2_client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=revoke_rules
            )
        except Exception as e:
            raise Exception(f"Failed to remove security group rules: {e}")


def main():
    """Test the Security Group Manager (requires AWS credentials)."""
    print("=== Security Group Manager Test ===")
    print("Note: This test requires AWS credentials and will make actual AWS API calls")
    
    # This would typically be used within a CDK context
    # For testing, you would need to provide actual VPC and security group IDs
    
    # Example usage (commented out to avoid accidental execution):
    """
    # Initialize with actual security group ID
    manager = SecurityGroupManager(None, None)
    
    # Test IP listing
    result = manager.list_allowed_ips('sg-xxxxxxxxx')
    print(f"Current IPs: {result}")
    
    # Test adding IP
    result = manager.add_ip_address('sg-xxxxxxxxx', '203.0.113.1')
    print(f"Add IP result: {result}")
    
    # Test removing IP
    result = manager.remove_ip_address('sg-xxxxxxxxx', '203.0.113.1')
    print(f"Remove IP result: {result}")
    """
    
    print("Security Group Manager initialized successfully")
    print("Use within CDK context for actual operations")


if __name__ == "__main__":
    main()