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

echo "Utility script for uploading data files to n8n container..."
echo "This script can be used to transfer files to the n8n ECS container via S3."

# Check if region is specified
if [ -z "$REGION" ]; then
  echo "Error: Region must be specified using --region parameter."
  echo "Usage: $0 --region [region]"
  echo "Example: $0 --region us-east-1"
  exit 1
fi

echo "Using region: $REGION"
echo "Using stack name: $STACK_NAME"

# Get the ECS cluster name
CLUSTER_NAME=$(aws ecs list-clusters --region $REGION | grep "$STACK_NAME-N8nCluster" | cut -d'/' -f2 | cut -d'"' -f1)
echo "Cluster name: $CLUSTER_NAME"

# Get the task ARN
TASK_ARN=$(aws ecs list-tasks --cluster $CLUSTER_NAME --region $REGION | grep "task/" | cut -d'"' -f2)
echo "Task ARN: $TASK_ARN"

echo "To upload your own data files:"
echo "1. Create a temporary S3 bucket"
echo "2. Upload your files to S3"
echo "3. Use ECS execute-command to download files to the container"
echo "4. Clean up the temporary S3 bucket"

echo "Example commands:"
echo "aws s3 mb s3://your-temp-bucket-name --region $REGION"
echo "aws s3 cp your-file.json s3://your-temp-bucket-name/data/ --region $REGION"
echo "aws ecs execute-command --cluster \$CLUSTER_NAME --task \$TASK_ARN --container n8n --command \"aws s3 cp s3://your-temp-bucket-name/data/your-file.json /home/node/.n8n/data/\" --interactive --region $REGION"
