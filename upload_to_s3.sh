#!/bin/bash

# Exit on error
set -e

# Parse command line arguments
REGION=""
STACK_NAME="N8nStack"

while [[ $# -gt 0 ]]; do
  case $1 in
    --region|-r)
      REGION="$2"
      shift 2
      ;;
    --stack-name|-s)
      STACK_NAME="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --region, -r REGION       AWS region (required)"
      echo "  --stack-name, -s NAME     CloudFormation stack name (default: N8nStack)"
      echo "  --help, -h                Show this help message"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

echo "Utility script for uploading data files to S3..."
echo "This script creates an S3 bucket and sets up permissions for the n8n task role."

# Check if region is specified
if [ -z "$REGION" ]; then
  echo "Error: Region must be specified using --region parameter."
  echo "Usage: $0 --region [region]"
  echo "Example: $0 --region us-east-1"
  exit 1
fi

echo "Using region: $REGION"
echo "Using stack name: $STACK_NAME"

# Check if data directory exists
if [ ! -d "data" ]; then
    echo "Creating data directory..."
    mkdir -p data
    echo "Please add your data files to the data/ directory before running this script."
    exit 1
fi

# Check if there are any files in the data directory
if [ -z "$(ls -A data/)" ]; then
    echo "No files found in data/ directory."
    echo "Please add your data files to the data/ directory before running this script."
    exit 1
fi

# Create a S3 bucket for data files
BUCKET_NAME="n8n-data-files-$(date +%s)"
aws s3 mb s3://$BUCKET_NAME --region $REGION
echo "Created S3 bucket: $BUCKET_NAME"

# Upload all files from data directory to S3
echo "Uploading data files to S3..."
aws s3 cp data/ s3://$BUCKET_NAME/data/ --recursive --region $REGION

# Get the n8n task role ARN from CloudFormation
TASK_ROLE_ARN=$(aws cloudformation describe-stack-resources --stack-name $STACK_NAME --logical-resource-id N8nTaskRole --query "StackResources[0].PhysicalResourceId" --output text --region $REGION)

# Set bucket policy to allow n8n task role to access the files
cat > /tmp/bucket_policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/$TASK_ROLE_ARN"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::$BUCKET_NAME",
        "arn:aws:s3:::$BUCKET_NAME/*"
      ]
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy file:///tmp/bucket_policy.json --region $REGION

echo "Data files uploaded successfully to S3 bucket: $BUCKET_NAME"
echo "You can now access the files in n8n using the AWS S3 node."
echo "Bucket: $BUCKET_NAME"
