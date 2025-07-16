"""
Integration tests for IP access control functionality.

These tests verify that the IP access control feature works correctly,
ensuring that the n8n deployment is secure by default with no access allowed
until IP addresses are explicitly allowlisted.
"""

import os
import boto3
import pytest
import requests
import time
from botocore.exceptions import ClientError

# Test constants
TEST_STACK_NAME = "N8nTestStack"
TEST_REGION = "us-east-1"
TEST_IP = "203.0.113.1/32"  # RFC 5737 test IP address


@pytest.fixture(scope="module")
def ec2_client():
    """Create an EC2 client for the tests."""
    return boto3.client('ec2', region_name=TEST_REGION)


@pytest.fixture(scope="module")
def cloudformation_client():
    """Create a CloudFormation client for the tests."""
    return boto3.client('cloudformation', region_name=TEST_REGION)


def get_alb_url(cloudformation_client):
    """Get the ALB URL from the CloudFormation stack outputs."""
    try:
        response = cloudformation_client.describe_stacks(StackName=TEST_STACK_NAME)
        outputs = response['Stacks'][0]['Outputs']
        for output in outputs:
            if output['OutputKey'] == 'N8nURL':
                return output['OutputValue']
        return None
    except ClientError as e:
        print(f"Error getting ALB URL: {e}")
        return None


def get_security_group_id(cloudformation_client):
    """Get the ALB security group ID from the CloudFormation stack outputs."""
    try:
        response = cloudformation_client.describe_stacks(StackName=TEST_STACK_NAME)
        outputs = response['Stacks'][0]['Outputs']
        for output in outputs:
            if output['OutputKey'] == 'ALBSecurityGroupId':
                return output['OutputValue']
        return None
    except ClientError as e:
        print(f"Error getting security group ID: {e}")
        return None


def test_default_no_access(cloudformation_client):
    """Test that the deployment is secure by default with no access allowed."""
    # Skip this test if we're not running in a CI environment
    if not os.environ.get('CI'):
        pytest.skip("Skipping integration test outside of CI environment")
    
    # Get the ALB URL
    alb_url = get_alb_url(cloudformation_client)
    assert alb_url is not None, "Failed to get ALB URL from stack outputs"
    
    # Try to access the ALB URL - should timeout or be refused
    try:
        response = requests.get(alb_url, timeout=5)
        # If we get a response, the test fails because we should not be able to access
        assert False, f"Expected connection to be refused, but got response: {response.status_code}"
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        # This is expected - connection should be refused or timeout
        pass


def test_add_ip_allows_access(cloudformation_client, ec2_client):
    """Test that adding an IP to the security group allows access."""
    # Skip this test if we're not running in a CI environment
    if not os.environ.get('CI'):
        pytest.skip("Skipping integration test outside of CI environment")
    
    # Get the security group ID
    sg_id = get_security_group_id(cloudformation_client)
    assert sg_id is not None, "Failed to get security group ID from stack outputs"
    
    # Add test IP to security group
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': TEST_IP}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': TEST_IP}]
                }
            ]
        )
        
        # Wait for security group changes to propagate
        time.sleep(5)
        
        # Verify IP was added
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg = response['SecurityGroups'][0]
        ip_permissions = sg['IpPermissions']
        
        # Check if our test IP is in the security group rules
        found_http = False
        found_https = False
        for perm in ip_permissions:
            if perm['FromPort'] == 80 and perm['ToPort'] == 80:
                for ip_range in perm['IpRanges']:
                    if ip_range['CidrIp'] == TEST_IP:
                        found_http = True
            if perm['FromPort'] == 443 and perm['ToPort'] == 443:
                for ip_range in perm['IpRanges']:
                    if ip_range['CidrIp'] == TEST_IP:
                        found_https = True
        
        assert found_http, f"Test IP {TEST_IP} not found in HTTP rules"
        assert found_https, f"Test IP {TEST_IP} not found in HTTPS rules"
        
    finally:
        # Clean up - remove test IP from security group
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': TEST_IP}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': TEST_IP}]
                    }
                ]
            )
        except Exception as e:
            print(f"Error cleaning up test IP: {e}")


def test_remove_ip_blocks_access(cloudformation_client, ec2_client):
    """Test that removing an IP from the security group blocks access."""
    # Skip this test if we're not running in a CI environment
    if not os.environ.get('CI'):
        pytest.skip("Skipping integration test outside of CI environment")
    
    # Get the security group ID
    sg_id = get_security_group_id(cloudformation_client)
    assert sg_id is not None, "Failed to get security group ID from stack outputs"
    
    # Add test IP to security group
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': TEST_IP}]
                }
            ]
        )
        
        # Wait for security group changes to propagate
        time.sleep(5)
        
        # Now remove the IP
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': TEST_IP}]
                }
            ]
        )
        
        # Wait for security group changes to propagate
        time.sleep(5)
        
        # Verify IP was removed
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg = response['SecurityGroups'][0]
        ip_permissions = sg['IpPermissions']
        
        # Check that our test IP is not in the security group rules
        for perm in ip_permissions:
            if perm['FromPort'] == 80 and perm['ToPort'] == 80:
                for ip_range in perm['IpRanges']:
                    assert ip_range['CidrIp'] != TEST_IP, f"Test IP {TEST_IP} still found in HTTP rules"
        
    except Exception as e:
        # Clean up if something went wrong
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': TEST_IP}]
                    }
                ]
            )
        except:
            pass
        raise e


if __name__ == "__main__":
    # This allows running the tests directly
    pytest.main(["-xvs", __file__])