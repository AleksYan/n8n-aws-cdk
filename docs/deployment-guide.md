# n8n AWS Deployment Guide

This guide explains how to deploy the n8n workflow automation tool on AWS using ECS with Fargate.

## Deployment Architecture

The deployment consists of:
- n8n container running on AWS Fargate
- EFS volume for data persistence
- IAM roles for AWS service access (S3, SNS)
- Application Load Balancer for web access
- Security groups for network access control

## Deployment Steps

### 1. Prerequisites

- AWS CLI installed and configured
- Permissions to create ECS, IAM, EFS, and other AWS resources
- Docker installed (for local testing)

### 2. Deploy the Infrastructure

```bash
./deploy.sh
```

This script will:
- Create necessary IAM roles
- Set up EFS for persistence
- Configure security groups
- Deploy the ECS task definition and service

### 3. Access n8n

After deployment completes, you'll receive a URL to access your n8n instance.

### 4. Configure AWS Integrations

In the n8n interface:
1. Add S3 credentials using the AWS node
2. Set up SNS integration for notifications

## Sharing with Others

To share this project with others:
1. Provide them with this repository
2. They should configure their AWS credentials
3. Run the deployment script in their own AWS account

## Cleanup

To remove all resources:

```bash
./cleanup.sh
```
