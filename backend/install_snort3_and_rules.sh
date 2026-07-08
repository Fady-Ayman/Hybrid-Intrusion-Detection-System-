#!/bin/bash
# =========================================================================
# Snort 3 & ET Open Rules Installation Script for Ubuntu 24.04 (Production)
# =========================================================================

set -e # Exit immediately if a command exits with a non-zero status

echo "[*] Updating system packages..."
sudo apt-get update -y

echo "[*] Installing Snort 3 build dependencies..."
sudo apt-get install -y build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev libpcap-dev \
    libpcre3-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev openssl libssl-dev cpputest \
    libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autoconf libtool bison flex \
    wget curl jq tzdata libcap2-bin

# Create working directory
mkdir -p ~/snort3_src
cd ~/snort3_src

echo "[*] Downloading and installing libDAQ..."
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
sudo make install
sudo ldconfig
cd ..

echo "[*] Downloading and installing gperftools (TCMalloc)..."
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar xzvf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1
./configure
make
sudo make install
sudo ldconfig
cd ..

echo "[*] Downloading and Compiling Snort 3..."
git clone https://github.com/snort3/snort3.git
cd snort3
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make
sudo make install
sudo ldconfig

echo "[*] Applying Network Capabilities for Unprivileged Execution..."
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort

echo "[*] Creating Snort Directories and Users..."
sudo groupadd snort || true
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort || true
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /var/log/snort
sudo mkdir -p /usr/local/lib/snort_dynamicrules

# Apply strict and secure permissions
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules
sudo chmod -R 755 /etc/snort
sudo chmod -R 755 /var/log/snort

echo "[*] Downloading Emerging Threats (ET) Open Rules..."
sudo wget -O /tmp/emerging.rules.tar.gz https://rules.emergingthreats.net/open/snort3/emerging.rules.tar.gz
sudo tar -xvzf /tmp/emerging.rules.tar.gz -C /tmp/

# Move extracted rules safely
sudo mv /tmp/rules/*.rules /etc/snort/rules/ 2>/dev/null || true
sudo rm -rf /tmp/rules /tmp/emerging.rules.tar.gz

echo "[*] Configuring snort.lua..."
sudo cp /usr/local/etc/snort/snort.lua /usr/local/etc/snort/snort.lua.backup

# Safely append JSON configuration using proper Lua syntax
sudo bash -c 'cat << EOF >> /usr/local/etc/snort/snort.lua

-- ==========================================
-- Hybrid IDS Custom Configurations (FastAPI)
-- ==========================================

-- Configure pure JSON output (Disk I/O will be bypassed via Python FIFO)
alert_json = {
    file = true,
    limit = 0 -- Disable log rotation to maintain continuous stream
}

-- Update existing IPS table safely without overwriting defaults
ips = ips or {}
ips.mode = "tap"

-- Include the main Emerging Threats rules file
include "/etc/snort/rules/emerging.rules"
EOF'

echo "[*] Copying configurations..."
# Copy ALL configs and magic files to prevent missing reference errors
sudo cp -r /usr/local/etc/snort/* /etc/snort/

echo "[*] Verification: Running Snort 3 Version and Config Check..."
/usr/local/bin/snort -V
/usr/local/bin/snort -c /etc/snort/snort.lua -T

echo "========================================================================="
echo "Installation Complete!"
echo "Snort 3 Path: /usr/local/bin/snort (Network Capabilities Applied)"
echo "Config file : /etc/snort/snort.lua"
echo "Alert Log   : /var/log/snort/alert_json.txt"
echo "========================================================================="