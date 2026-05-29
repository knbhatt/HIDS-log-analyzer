import re
import pandas as pd # type: ignore
from datetime import timedelta
from sklearn.metrics import confusion_matrix # type: ignore
import numpy as np


# --- CONFIGURATION (TM3 MUST EDIT THIS SECTION) ---

# 1. Path to the log file copied from the Victim VM
LOG_PATH = '"E:\Programs\SA\Assignment\auth_log.txt"' 

# 2. Attack Time Markers (Replace with the times recorded by TM1)
# Use a specific format: YYYY Mon DD HH:MM:SS
CURRENT_YEAR = 2025 # Assuming this is the year of your lab
ATTACKER_IP = '192.168.29.173' # Replace with your Kali machine's IP

BRUTE_FORCE_START = f'{CURRENT_YEAR} Nov 22 05:57:00'
BRUTE_FORCE_END = f'{CURRENT_YEAR} Nov 22 06:05:00'

PRIV_ESC_START = f'{CURRENT_YEAR} Nov 22 06:06:00'
PRIV_ESC_END = f'{CURRENT_YEAR} Nov 22 06:08:00'

# --- PHASE 2: PARSING AND STRUCTURING (TM2's Role) ---

def parse_auth_log(file_path):
    """Reads raw log file and extracts structured data using regex."""
    data = []
    
    # Pattern 1: Failed SSH Login (Brute Force) - Captures Timestamp and Source IP
    SSH_FAIL_PATTERN = re.compile(r"(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    # Pattern 2: Sudo Failed Attempt (Privilege Escalation) - Captures Timestamp and User
    SUDO_FAIL_PATTERN = re.compile(r"(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}).*sudo: (\w+)\s+:\s+\d+\s+incorrect password attempts")

    with open(file_path, 'r') as f:
        for line in f:
            match_ssh = SSH_FAIL_PATTERN.search(line)
            match_sudo = SUDO_FAIL_PATTERN.search(line)

            if match_ssh:
                data.append({
                    'timestamp_str': match_ssh.group(1),
                    'source_ip': match_ssh.group(2),
                    'event_type': 'SSH_FAIL',
                })
            elif match_sudo:
                 data.append({
                    'timestamp_str': match_sudo.group(1),
                    'source_ip': 'LOCAL', 
                    'event_type': 'SUDO_FAIL',
                })
                
    df = pd.DataFrame(data)
    
    # Normalization: Convert time strings to datetime objects
    if 'timestamp_str' in df.columns and not df.empty:
        df['timestamp'] = pd.to_datetime(f'{CURRENT_YEAR} ' + df['timestamp_str'], format='%Y %b %d %H:%M:%S') 
        df = df.sort_values(by='timestamp').reset_index(drop=True)
    
    return df

# --- PHASE 3: DETECTION AND EVALUATION (TM2/TM3's Role) ---


def apply_detection_rules(df, ssh_threshold, ssh_window_minutes):
    """Applies rule-based logic to detect intrusion patterns."""
    
    df['detection_flag'] = 'NO_ALERT'
    
    # Rule 1: Brute Force (SSH_FAIL)
    ssh_failures = df[df['event_type'] == 'SSH_FAIL'].copy()
    
    for ip, group in ssh_failures.groupby('source_ip'):
        if len(group) >= ssh_threshold:
            
            for i in range(len(group) - ssh_threshold + 1):
                start_time = group.iloc[i]['timestamp']
                end_time = group.iloc[i + ssh_threshold - 1]['timestamp']
                
                time_diff = (end_time - start_time)
                
                if time_diff <= timedelta(minutes=ssh_window_minutes):
                    # Flag the events in the original DataFrame
                    df.loc[group.index[i]:group.index[i + ssh_threshold - 1], 'detection_flag'] = 'ALERT_BRUTE_FORCE'

    # Rule 2: Privilege Escalation (SUDO_FAIL - Fixed threshold)
    SUDO_THRESH = 3
    SUDO_WINDOW = 2 
    sudo_failures = df[df['event_type'] == 'SUDO_FAIL'].copy()
    
    if len(sudo_failures) >= SUDO_THRESH:
        for i in range(len(sudo_failures) - SUDO_THRESH + 1):
            start_time = sudo_failures.iloc[i]['timestamp']
            end_time = sudo_failures.iloc[i + SUDO_THRESH - 1]['timestamp']
            
            if (end_time - start_time) <= timedelta(minutes=SUDO_WINDOW):
                df.loc[sudo_failures.index[i]:sudo_failures.index[i + SUDO_THRESH - 1], 'detection_flag'] = 'ALERT_PRIV_ESC'
                
    return df

def apply_ground_truth(df):
    """Applies the actual labels based on TM1's recorded times (Ground Truth)."""
    
    df['actual_label'] = 'Normal'
    
    # 1. Brute Force Labeling
    df.loc[
        (df['event_type'] == 'SSH_FAIL') &
        (df['source_ip'] == ATTACKER_IP) &
        (df['timestamp'] >= pd.to_datetime(BRUTE_FORCE_START)) &
        (df['timestamp'] <= pd.to_datetime(BRUTE_FORCE_END)),
        'actual_label'
    ] = 'Attack'

    # 2. Privilege Escalation Labeling
    df.loc[
        (df['event_type'] == 'SUDO_FAIL') &
        (df['timestamp'] >= pd.to_datetime(PRIV_ESC_START)) &
        (df['timestamp'] <= pd.to_datetime(PRIV_ESC_END)),
        'actual_label'
    ] = 'Attack'
    
    return df

def calculate_metrics(y_true, y_pred, label):
    """Calculates and prints the performance metrics (TPR, FPR)."""
    
    # Confusion Matrix: TN, FP, FN, TP
    # Labels are 0=Normal, 1=Attack
    try:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    except ValueError:
        # Handle case where one class (e.g., Attack) is missing entirely
        print(f"\n! Warning: Not enough data points to compute full confusion matrix for {label}. Skipping metrics.")
        return {'TPR': 0, 'FPR': 0, 'TP': 0, 'FP': 0, 'FN': 0, 'TN': len(y_true)}
        
    # Calculation
    TPR = tp / (tp + fn) if (tp + fn) > 0 else 0 
    FPR = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print(f"\n--- Metrics for {label} ---")
    print(f"True Positives (TP): {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"True Positive Rate (TPR/Recall): {TPR:.4f}")
    print(f"False Positive Rate (FPR): {FPR:.4f}")
    
    return {'TPR': TPR, 'FPR': FPR, 'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn}

# --- MAIN ---

if __name__ == "__main__":
    print("Starting Log Pattern Analysis Project...")

    # 1. PARSING (TM2)
    df_logs = parse_auth_log(LOG_PATH)
    if df_logs.empty:
        print("\nERROR: No security events found in the log file. Check LOG_PATH and regex patterns.")
        exit()
        
    print(f"\nSuccessfully parsed {len(df_logs)} security events.")

    # 2. GROUND TRUTH LABELING (TM3)
    df_logs = apply_ground_truth(df_logs)
    attack_events_count = len(df_logs[df_logs['actual_label'] == 'Attack'])
    print(f"Labeled {attack_events_count} events as 'Attack' (Ground Truth).")
    
    y_true = (df_logs['actual_label'] == 'Attack').astype(int)

    # 3. THRESHOLD COMPARISON (TM3)

    # --- Threshold 1: Sensitive Rule (5 failures in 10 minutes) ---
    df_t1 = apply_detection_rules(df_logs.copy(), ssh_threshold=5, ssh_window_minutes=10)
    y_pred_t1 = (df_t1['detection_flag'] != 'NO_ALERT').astype(int)
    results_t1 = calculate_metrics(y_true, y_pred_t1, "Threshold 1 (5 failures/10 min - High Sensitivity)")

    # --- Threshold 2: Strict Rule (10 failures in 10 minutes) ---
    df_t2 = apply_detection_rules(df_logs.copy(), ssh_threshold=10, ssh_window_minutes=10)
    y_pred_t2 = (df_t2['detection_flag'] != 'NO_ALERT').astype(int)
    results_t2 = calculate_metrics(y_true, y_pred_t2, "Threshold 2 (10 failures/10 min - Low False Positives)")
    
    # 4. FINAL REPORT TABLE (TM3)
    
    comparison_df = pd.DataFrame({
        'Metric': ['TPR (Recall)', 'FPR (False Alarm)', 'TP', 'FP'],
        'Threshold 1 (5/10 min)': [results_t1['TPR'], results_t1['FPR'], results_t1['TP'], results_t1['FP']],
        'Threshold 2 (10/10 min)': [results_t2['TPR'], results_t2['FPR'], results_t2['TP'], results_t2['FP']]
    })

    print("\n==========================================================")
    print("FINAL RESULTS FOR THRESHOLD COMPARISON")
    print("==========================================================")
    print("Use this table and the calculated metrics for your report analysis.")
    print(comparison_df.to_markdown(index=False))

    # df_logs.to_csv('final_labeled_data.csv', index=False)