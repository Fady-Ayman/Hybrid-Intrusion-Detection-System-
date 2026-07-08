import os
import subprocess
import logging

logger = logging.getLogger(__name__)

CICFLOWMETER_JAVA = "sudo java" # Using sudo because jnetpcap sometimes requires root even for offline analysis
LIBRARY_PATH = "/mnt/extra_storage/IDS_Project/CICFlowMeter_V3/jnetpcap/linux/jnetpcap-1.4.r1425"
JAR_PATH = "/mnt/extra_storage/IDS_Project/CICFlowMeter_V3/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
MAIN_CLASS = "cic.cs.unb.ca.ifm.Cmd"

def extract_flows_from_pcap(pcap_path: str, output_dir: str) -> str:
    """
    Runs CICFlowMeter offline on a PCAP file and returns the path to the generated CSV.
    """
    try:
        # Command: java -Xms256m -Xmx1g -Djava.library.path=... -cp ... cic.cs.unb.ca.ifm.Cmd <pcap_path> <output_dir>
        cmd = [
            "java",
            "-Xms256m", "-Xmx1g",
            f"-Djava.library.path={LIBRARY_PATH}",
            "-cp", JAR_PATH,
            MAIN_CLASS,
            pcap_path,
            output_dir
        ]
        
        logger.info(f"[PCAPAnalyzer] Running CICFlowMeter offline: {' '.join(cmd)}")
        
        # Route stdout to DEVNULL to save memory, capture only stderr for errors
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=600, cwd=output_dir)
        
        if result.returncode != 0:
            logger.error(f"[PCAPAnalyzer] CICFlowMeter failed: {result.stderr}")
            return None
            
        # The java code generates a file named: <original_filename>.pcap_Flow.csv (or just _Flow.csv)
        base_name = os.path.basename(pcap_path)
        expected_csv = os.path.join(output_dir, f"{base_name}_Flow.csv")
        
        if os.path.exists(expected_csv):
            logger.info(f"[PCAPAnalyzer] CSV generated at {expected_csv}")
            return expected_csv
                
        logger.error(f"[PCAPAnalyzer] Expected CSV not found at {expected_csv}. Extraction likely failed.")
        return None
    except subprocess.TimeoutExpired:
        logger.error("[PCAPAnalyzer] CICFlowMeter offline extraction timed out after 600 seconds.")
        return None
    except Exception as e:
        logger.error(f"[PCAPAnalyzer] Error in extract_flows_from_pcap: {e}")
        return None
