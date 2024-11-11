#!/bin/bash



# Find AMI ID for RHEL via 
# ```
#  aws ec2 describe-images \
#         --region us-east-1 \
#         --owners amazon \
#         --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
#         --query "Images[*].[ImageId,Name,CreationDate]" \
#         --output table
# ```
# This ID depends on the region.
# arm64 ID is `ami-07472131ec292b5da`
# x86_64 ID is `ami-0583d8c7a9c35822c`
IMAGE_ID="ami-07472131ec292b5da"

# Find VPC and security-group via `aws ec2 describe-security-groups`
SECURITY_GROUP="sg-0f1980007115350db"
# Find subnet-id via `aws ec2 describe-subnets --filter "Name=vpc-id,Values=<vpc-id>"`
SUBNET_ID="subnet-0fc322a35969a58de"


INSTANCE_TYPE="im4gn.4xlarge"
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
