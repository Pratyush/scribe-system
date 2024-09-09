sudo mkfs.ext4 -E nodiscard /dev/nvme1n1
mkdir /home/ec2-user/external
sudo mount /dev/nvme1n1 /home/ec2-user/external 
sudo chown -R ec2-user external/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
mkdir ~/external/tmp
sudo yum install git gcc vim
git clone git@github.com:Pratyush/streaming-snarks-system.git
# set TMPDIR in streaming-snarks-systems/src/scribe/benches/run_bench.sh
