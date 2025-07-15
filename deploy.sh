#!/bin/bash

# Exit on error
set -e

# Parse command line arguments
REGION=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --region|-r)
      REGION="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

echo "Deploying n8n AWS CDK..."

# Check if region is specified
if [ -z "$REGION" ]; then
  echo "Error: Region must be specified using --region parameter."
  echo "Usage: $0 --region [region]"
  echo "Example: $0 --region us-east-1"
  exit 1
fi

echo "Using specified region: $REGION"
export CDK_DEPLOY_REGION="$REGION"

# Activate virtual environment
cd cdk
source .venv/bin/activate

# Install dependencies if needed
pip install -r requirements.txt

# Deploy the stack
cdk deploy --require-approval never

echo "Deployment complete!"
echo "You can access n8n at the URL shown in the outputs above."
echo ""
echo "⚠️ IMPORTANT: By default, this deployment is completely closed with no access allowed."
echo "You must explicitly allowlist IP addresses to gain access to the n8n web portal."
echo ""
echo "To add your current IP address:"
echo "1. Get the security group ID from the outputs above (ALBSecurityGroupId)"
echo "2. Run: ./manage-ip-access.sh add \$(curl -s https://checkip.amazonaws.com)/32 \"My IP\" --sg-id <security-group-id>"
echo ""
echo "For more information, see docs/ip-access-control.md"
