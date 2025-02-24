#!/bin/bash

set -e

# Check if the architecture argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <architecture>"
  echo "Supported architectures: x86_64, arm64"
  exit 1
fi

ARCHITECTURE=$1
# Set AMI and instance type based on architecture
if [ "$ARCHITECTURE" == "x86_64" ]; then
  # x86_64 instance is `i3en.3xlarge`
  IMAGE_ID="ami-0583d8c7a9c35822c"  # x86_64 AMI ID
  INSTANCE_TYPE="i3en.3xlarge"       # x86_64 instance type
elif [ "$ARCHITECTURE" == "arm64" ]; then
  # arm64 instance is `im4gn.4xlarge`
  IMAGE_ID="ami-07472131ec292b5da"  # arm64 AMI ID
  INSTANCE_TYPE="im4gn.4xlarge"     # arm64 instance type
else
  echo "Unsupported architecture: $ARCHITECTURE"
  echo "Supported architectures: x86_64, arm64"
  exit 1
fi

# Find VPC and security-group via `aws ec2 describe-security-groups`
SECURITY_GROUP=$(aws ec2 describe-security-groups --filters 'Name=group-name,Values=scribe-sg' --query 'SecurityGroups[*].GroupId' --output text)

VPC_ID=$(aws ec2 describe-security-groups --filters 'Name=group-name,Values=scribe-sg' --query 'SecurityGroups[*].VpcId' --output text)

# Find subnet-id via `aws ec2 describe-subnets --filter "Name=vpc-id,Values=$VPC_ID" --query '`
SUBNET_ID=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$VPC_ID Name=tag:Name,Values="pennnet-snarky-vpc-1 Public01" \
  --query 'Subnets[*].SubnetId' \
  --output text)


KEY_NAME="Pratyush-Gethen"

# If you want to use a spot-instance, add the following command
# --instance-market-options 'MarketType=spot'
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --count 1 \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_NAME \
  --security-group-ids $SECURITY_GROUP \
  --subnet-id $SUBNET_ID \
  --network-interfaces "DeviceIndex=0,SubnetId=$SUBNET_ID,AssociatePublicIpAddress=true"\
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":30}}]' \
  --user-data file://server-setup.sh \
  --query "Instances[0].InstanceId" \
  --output text)

aws ec2 wait instance-running --instance-ids $INSTANCE_ID

PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query "Reservations[*].Instances[*].PublicIpAddress" \
  --output text)

echo "Instance ID: $INSTANCE_ID"
echo "Instance Public IP: $PUBLIC_IP"
echo "SSH into instance with ssh -o ForwardAgent=yes ec2-user@$PUBLIC_IP"
