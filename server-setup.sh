#!/bin/bash

DEVICE=$(lsblk -nd --output NAME,TYPE | grep disk | grep nvme2n1 | awk '{print "/dev/" $1}')
sudo mkfs.ext4 -E nodiscard $DEVICE
sudo mkdir -p /home/ec2-user/external
sudo mount -o noatime $DEVICE /home/ec2-user/external 
sudo chown -R ec2-user:ec2-user /home/ec2-user/external/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
. "$HOME/.cargo/env"
# rustup default nightly
# sudo yum install git gcc vim -y
# sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
# sudo yum install htop
mkdir /home/ec2-user/external/tmp
echo "set -o vi" > /home/ec2-user/.bashrc

# git clone git@github.com:Pratyush/streaming-snarks-system.git
# set TMPDIR in streaming-snarks-systems/src/scribe/benches/run_bench.sh
