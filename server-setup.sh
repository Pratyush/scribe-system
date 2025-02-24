#!/bin/bash

# Get a list of all disk devices and their sizes (in bytes) using lsblk
DISKS=$(lsblk -bnd -o NAME,SIZE | awk '{print "/dev/"$1, $2}')

# Initialize variables to track the largest disk
LARGEST_DISK=""
LARGEST_SIZE=0

# Iterate through each disk to find the largest one
while read -r DISK SIZE; do
  if [ "$SIZE" -gt "$LARGEST_SIZE" ]; then
    LARGEST_DISK=$DISK
    LARGEST_SIZE=$SIZE
  fi
done <<< "$DISKS"

sudo mkfs.ext4 -E nodiscard $LARGEST_DISK
sudo mkdir -p /home/ec2-user/external
sudo mount -o noatime $LARGEST_DISK /home/ec2-user/external 
yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
yum install git gcc vim htop -y
dnf install 'dnf-command(config-manager)'
dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
dnf install gh --repo gh-cli -y

sudo chown -R ec2-user:ec2-user /home/ec2-user/external/
sudo -u ec2-user bash <<EOF
# Commands run as ec2-user
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
echo "set -o vi" > /home/ec2-user/.bashrc
source "home/ec2-user/.cargo/env"
source /home/ec2-user/.bashrc
mkdir /home/ec2-user/external/tmp
EOF
