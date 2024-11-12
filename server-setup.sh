#!/bin/bash

DEVICE=$(lsblk -nd --output NAME,TYPE | grep disk | grep nvme2n1 | awk '{print "/dev/" $1}')
sudo mkfs.ext4 -E nodiscard $DEVICE
sudo mkdir -p /home/ec2-user/external
sudo mount -o noatime $DEVICE /home/ec2-user/external 
yum update -y
yum install git gcc vim -y
yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
yum install htop

sudo chown -R ec2-user:ec2-user /home/ec2-user/external/
sudo -u ec2-user bash <<EOF
# Commands run as ec2-user
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
echo "set -o vi" > /home/ec2-user/.bashrc
source "home/ec2-user/.cargo/env"
source /home/ec2-user/.bashrc
mkdir /home/ec2-user/external/tmp
EOF

# rustup default nightly

# git clone git@github.com:Pratyush/streaming-snarks-system.git
# set TMPDIR in streaming-snarks-systems/src/scribe/benches/run_bench.sh
