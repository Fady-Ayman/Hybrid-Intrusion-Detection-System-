# CyberHawk: Hybrid AI-Powered NIDS

CyberHawk is an advanced, hybrid Network Intrusion Detection System designed for real-time threat detection and proactive network monitoring. By integrating the deterministic precision of Snort's signature-based rules with the analytical power of Machine Learning models, the system successfully identifies both known exploits and complex, unmapped anomalous behaviors.

Core Components:

Hybrid Detection Engine: Seamlessly merges Snort signature-based packet analysis with Machine Learning/Deep Learning classifiers to ensure comprehensive threat coverage and reduce false negatives.

Dual-Mode Traffic Analysis: Supports continuous live packet sniffing and offline PCAP file evaluation for flexible threat extraction.

High-Performance Backend: Engineered with Python and Flask to handle low-latency data processing, alert correlation, ML model inference, and robust API serving.

Interactive Frontend: Built with React and Vite to deliver a responsive, real-time security dashboard that provides network administrators with instant alerts and clear data flow visualization.

## 🛠️ Installation & Setup

This section outlines the steps required to configure and run the completely integrated NIDS environment, including the machine learning backend, traffic capture engine, Snort NIDS, and the interactive frontend.

### 1. Backend Server Configuration (ML Engine)
The backend requires an isolated Conda environment to manage dependencies efficiently.

```bash
# Create the Conda environment and install all dependencies directly from the configuration file
conda env create -f environment.yml

# Activate the initialized environment (ensure the name matches the one specified inside environment.yml)
conda activate hawk

# Start the backend inference server
uvicorn inference_server:app --host 0.0.0.0 --port 8000
```

### 2. CICFlowMeter Setup (Traffic Capture)
CICFlowMeter is utilized for real-time traffic feature extraction.

```bash
# Grant execution permissions and run the setup script
chmod +x Setup_cicflowmeter_v3.sh
./Setup_cicflowmeter_v3.sh

# Start live packet capturing
# IMPORTANT: Replace <PROJECT_PATH> with your actual absolute project directory path.
# Replace <NIC_NAME> with your active network interface (e.g., ens33 for VMware or eth0 for WSL).
sudo java -Djava.library.path=<PROJECT_PATH>/CICFlowMeter_V3/jnetpcap/linux/jnetpcap-1.4.r1425 \
     -cp <PROJECT_PATH>/CICFlowMeter_V3/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar \
     cic.cs.unb.ca.ifm.LiveCmd <NIC_NAME>
```

### 3. Snort 3 Installation (Signature-Based NIDS)
Execute the provided shell script to automate the deployment of Snort 3 and its associated rule sets.

```bash
# Grant execution permissions and run the installer
chmod +x install_snort3_and_rules.sh
sudo ./install_snort3_and_rules.sh
```

### 4. Frontend Dashboard Setup
The interactive React/Vite dashboard visualizes network statistics and real-time alerts.

```bash
# Navigate to the frontend directory
cd frontend/

# Install Node.js modules
npm install

# Start the development server
npm run dev
```
