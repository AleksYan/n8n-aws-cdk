# IP Access Control for n8n Deployment

This document provides instructions for managing IP-based access control for your n8n deployment on AWS. By restricting access to specific IP addresses, you can enhance the security of your n8n instance.

## Overview

The n8n deployment uses AWS Security Groups to restrict access to the Application Load Balancer (ALB) that sits in front of your n8n instance. Only traffic from allowed IP addresses can reach the n8n web portal.

## Initial Deployment

### Secure-by-Default Approach

The n8n deployment follows a secure-by-default approach where **no access is allowed initially**. After deployment, you must explicitly allowlist IP addresses to gain access to the n8n web portal.

### Specifying Allowed IPs During Deployment

When deploying the CDK stack, you can optionally specify allowed IP addresses using the `ALLOWED_IPS` environment variable:

```bash
# Allow access from a single IP address
export ALLOWED_IPS="203.0.113.1"

# Allow access from multiple IP addresses (comma-separated)
export ALLOWED_IPS="203.0.113.1,198.51.100.1"

# Allow access from an IP range using CIDR notation
export ALLOWED_IPS="203.0.113.0/24"

# Deploy with the specified IP restrictions
cd cdk && cdk deploy
```

If no IP addresses are specified, the deployment will create security groups with no inbound access rules, and you'll need to add IPs after deployment using the provided management script.

## Managing IP Access After Deployment

### Finding Your Security Group ID

After deployment, the CDK stack outputs the security group IDs. You can find these in the AWS CloudFormation console or by running:

```bash
aws cloudformation describe-stacks --stack-name N8nStack --query "Stacks[0].Outputs[?OutputKey=='ALBSecurityGroupId'].OutputValue" --output text
```

### Viewing Current Allowed IPs

To view the current IP addresses allowed to access your n8n instance:

```bash
# Replace sg-xxxxxxxxx with your ALB security group ID
aws ec2 describe-security-groups --group-ids sg-xxxxxxxxx --query "SecurityGroups[0].IpPermissions[?FromPort==`80`].IpRanges[].CidrIp" --output table
```

### Adding a New IP Address

To add a new IP address to the allowed list:

```bash
# Replace sg-xxxxxxxxx with your ALB security group ID
# Replace 203.0.113.2/32 with the IP address to add (include /32 for single IPs)

aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --ip-permissions \
  "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=203.0.113.2/32,Description='HTTP access'}]" \
  "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=203.0.113.2/32,Description='HTTPS access'}]"
```

### Removing an IP Address

To remove an IP address from the allowed list:

```bash
# Replace sg-xxxxxxxxx with your ALB security group ID
# Replace 203.0.113.2/32 with the IP address to remove

aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --ip-permissions \
  "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=203.0.113.2/32}]" \
  "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=203.0.113.2/32}]"
```

### Finding Your Current Public IP

If you need to find your current public IP address to add to the security group:

```bash
# Using curl
curl -s https://checkip.amazonaws.com

# Using dig
dig +short myip.opendns.com @resolver1.opendns.com
```

## Best Practices

1. **Least Privilege**: Only allow access from IP addresses that absolutely need it.
2. **Regular Audits**: Periodically review the allowed IP addresses and remove any that are no longer needed.
3. **CIDR Blocks**: For office networks or VPNs, use CIDR blocks instead of individual IPs.
4. **Documentation**: Keep a record of which IP addresses are allowed and why.
5. **Temporary Access**: For temporary access, add the IP and set a reminder to remove it later.

## Troubleshooting

### Cannot Access n8n After IP Change

If you've changed your IP address and can no longer access n8n:

1. Connect to AWS using the AWS Console or CLI from a location that has access
2. Add your new IP address to the security group
3. Verify the security group rules were updated correctly

### Security Group Rule Limits

AWS has a limit of 60 rules per security group. If you need to allow many IPs, consider:

1. Using CIDR blocks to group IPs where possible
2. Creating a new security group and attaching it to the ALB



## Advanced Configuration

### Using a Script for IP Management

For more complex IP management, you can use the provided `manage-ip-access.sh` script:

```bash
#!/bin/bash

# Example script to add your current IP to the security group
SG_ID="sg-xxxxxxxxx"
CURRENT_IP=$(curl -s https://checkip.amazonaws.com)

if [ -z "$CURRENT_IP" ]; then
  echo "Failed to detect IP address"
  exit 1
fi

echo "Adding $CURRENT_IP/32 to security group $SG_ID"

aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --ip-permissions \
  "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=$CURRENT_IP/32,Description='HTTP access'}]" \
  "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=$CURRENT_IP/32,Description='HTTPS access'}]"
```

### Using AWS Systems Manager for IP Management

For enterprise environments, consider using AWS Systems Manager to automate IP management:

1. Create an SSM document that updates the security group
2. Use SSM Run Command to execute the document
3. Set up SSM Maintenance Windows for regular IP audits

## Security Considerations

### Dynamic IP Addresses

If you have a dynamic IP address that changes frequently:

1. Consider using a VPN service with a static IP
2. Set up a scheduled task to update the security group with your current IP
3. Use broader CIDR blocks if appropriate for your security requirements

### VPN and Corporate Networks

When accessing through a VPN or corporate network:

1. Determine the outbound IP address or range used by your VPN/network
2. Add the entire range if necessary, but be as specific as possible
3. Consider setting up a dedicated VPN connection to AWS if you need more secure access