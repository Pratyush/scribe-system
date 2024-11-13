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
  IMAGE_ID="ami-0583d8c7a9c35822c"  # x86_64 AMI ID
  INSTANCE_TYPE="i3en.3xlarge"       # x86_64 instance type
elif [ "$ARCHITECTURE" == "arm64" ]; then
  IMAGE_ID="ami-07472131ec292b5da"  # arm64 AMI ID
  INSTANCE_TYPE="im4gn.4xlarge"     # arm64 instance type
else
  echo "Unsupported architecture: $ARCHITECTURE"
  echo "Supported architectures: x86_64, arm64"
  exit 1
fi

# Find VPC and security-group via `aws ec2 describe-security-groups`
SECURITY_GROUP="sg-0f1980007115350db"
# Find subnet-id via `aws ec2 describe-subnets --filter "Name=vpc-id,Values=<vpc-id>"`
SUBNET_ID="subnet-0fc322a35969a58de"


# arm64 instance is `im4gn.4xlarge`
# x86_64 instance is `i3en.3xlarge`
KEY_NAME="Pratyush-Gethen"

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --count 1 \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_NAME \
  --security-group-ids $SECURITY_GROUP \
  --subnet-id $SUBNET_ID \
  --instance-market-options 'MarketType=spot'  \
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
