#!/bin/bash

# Exit on error
set -e

# Help function
show_help() {
  echo "n8n IP Access Management Script"
  echo ""
  echo "Usage: $0 [command] [options]"
  echo ""
  echo "Commands:"
  echo "  list                   List currently allowed IP addresses"
  echo "  add [ip] [description] Add an IP address to allowed list"
  echo "  remove [ip]            Remove an IP address from allowed list"
  echo "  current                Show your current public IP address"
  echo "  help                   Show this help message"
  echo ""
  echo "Options:"
  echo "  --sg-id [id]           Security group ID (required for add/remove/list)"
  echo ""
  echo "Examples:"
  echo "  $0 current"
  echo "  $0 list --sg-id sg-1234567890abcdef0"
  echo "  $0 add 203.0.113.1/32 \"Office IP\" --sg-id sg-1234567890abcdef0"
  echo "  $0 remove 203.0.113.1/32 --sg-id sg-1234567890abcdef0"
  echo ""
}

# Get current public IP
get_current_ip() {
  echo "Detecting your current public IP address..."
  
  # Try multiple services in case one fails
  IP=$(curl -s https://checkip.amazonaws.com || curl -s https://api.ipify.org || curl -s https://icanhazip.com)
  
  if [ -z "$IP" ]; then
    echo "Failed to detect your public IP address."
    exit 1
  fi
  
  echo "Your current public IP address is: $IP"
  echo "To add this IP to your security group, run:"
  echo "$0 add $IP/32 \"My IP\" --sg-id YOUR_SECURITY_GROUP_ID"
}

# List allowed IPs
list_ips() {
  if [ -z "$SG_ID" ]; then
    echo "Error: Security group ID is required."
    echo "Usage: $0 list --sg-id sg-1234567890abcdef0"
    exit 1
  fi
  
  echo "Listing allowed IP addresses for security group $SG_ID..."
  
  # Get HTTP (port 80) rules
  echo "HTTP (Port 80) Access:"
  aws ec2 describe-security-groups --group-ids $SG_ID --query "SecurityGroups[0].IpPermissions[?FromPort==\`80\`].IpRanges[].[CidrIp,Description]" --output table
  
  # Get HTTPS (port 443) rules
  echo "HTTPS (Port 443) Access:"
  aws ec2 describe-security-groups --group-ids $SG_ID --query "SecurityGroups[0].IpPermissions[?FromPort==\`443\`].IpRanges[].[CidrIp,Description]" --output table
}

# Add IP address
add_ip() {
  if [ -z "$SG_ID" ] || [ -z "$IP" ]; then
    echo "Error: Security group ID and IP address are required."
    echo "Usage: $0 add 203.0.113.1/32 \"Description\" --sg-id sg-1234567890abcdef0"
    exit 1
  fi
  
  # Ensure IP has CIDR notation
  if [[ ! "$IP" =~ / ]]; then
    IP="$IP/32"
    echo "Adding CIDR notation: $IP"
  fi
  
  echo "Adding IP $IP to security group $SG_ID..."
  
  # Add for HTTP (port 80)
  aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --ip-protocol tcp \
    --from-port 80 \
    --to-port 80 \
    --cidr $IP \
    --description "${DESCRIPTION:-Added by manage-ip-access.sh}"
  
  # Add for HTTPS (port 443)
  aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --ip-protocol tcp \
    --from-port 443 \
    --to-port 443 \
    --cidr $IP \
    --description "${DESCRIPTION:-Added by manage-ip-access.sh}"
  
  echo "Successfully added $IP to security group $SG_ID"
}

# Remove IP address
remove_ip() {
  if [ -z "$SG_ID" ] || [ -z "$IP" ]; then
    echo "Error: Security group ID and IP address are required."
    echo "Usage: $0 remove 203.0.113.1/32 --sg-id sg-1234567890abcdef0"
    exit 1
  fi
  
  # Ensure IP has CIDR notation
  if [[ ! "$IP" =~ / ]]; then
    IP="$IP/32"
    echo "Adding CIDR notation: $IP"
  fi
  
  echo "Removing IP $IP from security group $SG_ID..."
  
  # Remove for HTTP (port 80)
  aws ec2 revoke-security-group-ingress \
    --group-id $SG_ID \
    --ip-protocol tcp \
    --from-port 80 \
    --to-port 80 \
    --cidr $IP
  
  # Remove for HTTPS (port 443)
  aws ec2 revoke-security-group-ingress \
    --group-id $SG_ID \
    --ip-protocol tcp \
    --from-port 443 \
    --to-port 443 \
    --cidr $IP
  
  echo "Successfully removed $IP from security group $SG_ID"
}

# Parse command line arguments
COMMAND=$1
shift

# Parse options
while [[ $# -gt 0 ]]; do
  case $1 in
    --sg-id)
      SG_ID="$2"
      shift 2
      ;;
    *)
      if [ -z "$IP" ]; then
        IP="$1"
        shift
      elif [ -z "$DESCRIPTION" ]; then
        DESCRIPTION="$1"
        shift
      else
        echo "Error: Unknown parameter $1"
        show_help
        exit 1
      fi
      ;;
  esac
done

# Execute command
case $COMMAND in
  list)
    list_ips
    ;;
  add)
    add_ip
    ;;
  remove)
    remove_ip
    ;;
  current)
    get_current_ip
    ;;
  help|--help|-h)
    show_help
    ;;
  *)
    echo "Error: Unknown command $COMMAND"
    show_help
    exit 1
    ;;
esac