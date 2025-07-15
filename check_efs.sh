#!/bin/bash

# Get the EFS File System ID from CloudFormation outputs
EFS_ID=$(aws cloudformation describe-stacks --stack-name N8nStack --query "Stacks[0].Outputs[?OutputKey=='N8nFileSystemId'].OutputValue" --output text)

if [ -z "$EFS_ID" ]; then
  echo "Could not find EFS File System ID. Make sure the stack is deployed and has the correct output."
  exit 1
fi

echo "Found EFS File System ID: $EFS_ID"

# Get mount targets for the EFS file system
echo "Checking mount targets..."
aws efs describe-mount-targets --file-system-id $EFS_ID

# Get the security groups for the mount targets
echo -e "\nChecking mount target security groups..."
MOUNT_TARGET_IDS=$(aws efs describe-mount-targets --file-system-id $EFS_ID --query "MountTargets[*].MountTargetId" --output text)

for MT_ID in $MOUNT_TARGET_IDS; do
  echo -e "\nMount Target: $MT_ID"
  aws efs describe-mount-target-security-groups --mount-target-id $MT_ID
done

# Get the task security group
echo -e "\nChecking task security group..."
TASK_SG=$(aws cloudformation describe-stack-resources --stack-name N8nStack --logical-resource-id N8nSecurityGroup --query "StackResources[0].PhysicalResourceId" --output text)

if [ -n "$TASK_SG" ]; then
  echo "Task Security Group: $TASK_SG"
  aws ec2 describe-security-groups --group-ids $TASK_SG
fi

# Get the EFS security group
echo -e "\nChecking EFS security group..."
EFS_SG=$(aws cloudformation describe-stack-resources --stack-name N8nStack --logical-resource-id EfsSecurityGroup --query "StackResources[0].PhysicalResourceId" --output text)

if [ -n "$EFS_SG" ]; then
  echo "EFS Security Group: $EFS_SG"
  aws ec2 describe-security-groups --group-ids $EFS_SG
fi

echo -e "\nChecking for failed ECS tasks..."
CLUSTER_ARN=$(aws cloudformation describe-stack-resources --stack-name N8nStack --logical-resource-id N8nCluster --query "StackResources[0].PhysicalResourceId" --output text)

if [ -n "$CLUSTER_ARN" ]; then
  echo "Cluster ARN: $CLUSTER_ARN"
  
  # Get the most recent stopped tasks
  TASKS=$(aws ecs list-tasks --cluster $CLUSTER_ARN --desired-status STOPPED --query "taskArns" --output text)
  
  if [ -n "$TASKS" ]; then
    for TASK in $TASKS; do
      echo -e "\nTask: $TASK"
      aws ecs describe-tasks --cluster $CLUSTER_ARN --tasks $TASK --query "tasks[0].stoppedReason"
    done
  else
    echo "No stopped tasks found."
  fi
fi
