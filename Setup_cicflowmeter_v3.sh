#!/bin/bash
# ============================================================
# CICFlowMeter V3 (Original) - Auto Setup Script
# Original UNB repository used to generate CIC-IDS-2018 datasets
# ============================================================

set -e   # Exit immediately if any command fails

# Output colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'   # No Color

log()   { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ============================================================
# 0. Installation directory
# ============================================================
INSTALL_DIR="${1:-$HOME/CICFlowMeter_V3}"
log "Installation directory: $INSTALL_DIR"

# ============================================================
# 1. Install dependencies
# ============================================================
log "Installing dependencies..."

sudo apt-get update -qq
sudo apt-get install -y openjdk-8-jdk libpcap-dev maven git > /dev/null 2>&1

log "Dependencies installed successfully ✓"

# Verify Java installation
JAVA_VER=$(java -version 2>&1 | head -1)
log "Java version: $JAVA_VER"

# ============================================================
# 2. Clone the repository
# ============================================================
if [ -d "$INSTALL_DIR" ]; then
    warn "Directory already exists: $INSTALL_DIR"
    warn "Skipping repository clone."
else
    log "Cloning CICFlowMeter repository..."
    git clone https://github.com/ahlashkari/CICFlowMeter.git "$INSTALL_DIR"
    log "Repository cloned successfully ✓"
fi

cd "$INSTALL_DIR"

# ============================================================
# 3. Install native libraries
# ============================================================
log "Installing jNetPcap native libraries..."

if [ ! -f "./jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap.so" ]; then
    error "libjnetpcap.so not found. Please verify that the repository was cloned correctly."
fi

sudo cp ./jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap.so /usr/lib/
sudo cp ./jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap-pcap100.so /usr/lib/ 2>/dev/null || \
    warn "libjnetpcap-pcap100.so not found. Skipping."

sudo ldconfig

log "Native libraries installed successfully ✓"

# ============================================================
# 4. Install jNetPcap JAR into Maven
# ============================================================
log "Installing jNetPcap JAR into Maven..."

mvn install:install-file \
  -Dfile=./jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
  -DgroupId=org.jnetpcap \
  -DartifactId=jnetpcap \
  -Dversion=1.4.1 \
  -Dpackaging=jar \
  -q

log "jNetPcap JAR installed successfully ✓"

# ============================================================
# 5. Build the project
# ============================================================
log "Building the project (this may take a minute)..."

mvn package -DskipTests -q

JAR_FILE="$INSTALL_DIR/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"

if [ ! -f "$JAR_FILE" ]; then
    error "Build failed. Unable to locate the generated JAR file."
fi

log "Build completed successfully ✓"

# ============================================================
# 6. Create a helper run script
# ============================================================
RUN_SCRIPT="$INSTALL_DIR/run_cicflow.sh"

cat > "$RUN_SCRIPT" << EOF
#!/bin/bash
# CICFlowMeter V3 launcher
# Usage: ./run_cicflow.sh <pcap_file_or_folder> <output_dir>

PCAP="\$1"
OUT="\$2"

if [ -z "\$PCAP" ] || [ -z "\$OUT" ]; then
    echo "Usage: \$0 <pcap_file_or_folder> <output_dir>"
    echo "Example: \$0 /data/attack.pcap /data/csv_output"
    exit 1
fi

mkdir -p "\$OUT"

java -cp $JAR_FILE \\
  cic.cs.unb.ca.ifm.Cmd \\
  "\$PCAP" \\
  "\$OUT"
EOF

chmod +x "$RUN_SCRIPT"

# ============================================================
# 7. Summary
# ============================================================
echo ""
echo "============================================================"
echo -e "${GREEN}✓ CICFlowMeter V3 is ready to use!${NC}"
echo "============================================================"
echo ""

echo "Run using a PCAP file:"
echo "  $RUN_SCRIPT /path/to/file.pcap /path/to/output"
echo ""

echo "Or execute directly:"
echo "  java -cp $JAR_FILE \\"
echo "    cic.cs.unb.ca.ifm.Cmd \\"
echo "    /path/to/file.pcap \\"
echo "    /path/to/output"
echo ""
