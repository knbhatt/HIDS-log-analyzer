# Python HIDS - Host Intrusion Detection & Log Analyzer

**A Python-based Host Intrusion Detection System (HIDS) that analyzes Linux authentication logs to detect SSH brute-force attacks and privilege escalation attempts using rule-based detection, sliding-window correlation, and quantitative security metrics.**

---

## Overview

Modern security operations rely heavily on log analysis to identify suspicious activity before it escalates into a security incident.

This project implements a lightweight **Host-Based Intrusion Detection System (HIDS)** that automates the analysis of Linux authentication logs and generates alerts for malicious behavior. The system was tested in a controlled cybersecurity lab environment using **Kali Linux** and **Ubuntu Server** virtual machines.

### Key Features

* Detects SSH brute-force attacks from authentication logs
* Detects privilege escalation attempts through failed sudo activity
* Uses regex-based log parsing and event extraction
* Implements sliding-window correlation for attack detection
* Generates security alerts with attack context
* Applies ground-truth labeling for validation
* Evaluates detection performance using TPR and FPR metrics

---

## Project Architecture

```text
Kali Linux (Attacker)
        │
        ▼
SSH Brute Force / Privilege Escalation
        │
        ▼
Ubuntu Server (Victim)
        │
        ▼
/var/log/auth.log
        │
        ▼
Python Log Parser
        │
        ▼
Detection Engine
        │
        ├── SSH Brute Force Detection
        └── Privilege Escalation Detection
        │
        ▼
Alert Generation
        │
        ▼
TPR / FPR Evaluation
```

---

## Attack Scenarios Simulated

### 1. SSH Brute Force Attack

The attacker repeatedly attempts authentication using invalid credentials against the SSH service.

**Detection Logic**

* Failed SSH login attempts
* Source IP correlation
* Sliding time-window analysis
* Configurable alert threshold

**Sample Alert**

```text
[ALERT] SSH Brute Force Detected

Source IP : 192.168.x.x
Attempts  : 10
Window    : 10 Minutes
```

---

### 2. Privilege Escalation Attempt

Repeated failed sudo authentication attempts are analyzed to identify suspicious privilege escalation behavior.

**Detection Logic**

* Failed sudo executions
* Burst activity detection
* Short-duration threshold monitoring

**Sample Alert**

```text
[ALERT] Potential Privilege Escalation Detected

User       : testuser
Event Type : SUDO_FAIL
```

---

## Detection Workflow

### Phase 1 - Log Collection

Security events are collected from:

```text
/var/log/auth.log
```

Events include:

* SSH authentication failures
* Sudo authentication failures
* User activity records

---

### Phase 2 - Log Parsing

Regular Expressions (Regex) are used to extract structured information from raw log entries.

**Extracted Fields**

| Field                 | Description           |
| --------------------- | --------------------- |
| Timestamp             | Event occurrence time |
| Source IP             | Attacker IP address   |
| Event Type            | SSH_FAIL or SUDO_FAIL |
| Authentication Status | Success or Failure    |

---

### Phase 3 - Detection Engine

#### Rule 1: SSH Brute Force Detection

An alert is generated when multiple failed SSH login attempts occur from the same source IP within a predefined time window.

#### Rule 2: Privilege Escalation Detection

An alert is generated when repeated failed sudo authentication attempts occur within a short duration.

---

### Phase 4 - Ground Truth Labeling

Known attack windows are manually labeled to establish a ground-truth dataset.

This enables objective evaluation of detection effectiveness and supports performance analysis.

---

### Phase 5 - Performance Evaluation

Detection results are evaluated using standard cybersecurity metrics.

#### Metrics Used

| Metric | Description                 |
| ------ | --------------------------- |
| TP     | True Positives              |
| FP     | False Positives             |
| TN     | True Negatives              |
| FN     | False Negatives             |
| TPR    | True Positive Rate (Recall) |
| FPR    | False Positive Rate         |

---

## Threshold Comparison

Two detection configurations were evaluated:

| Configuration       | Threshold                     |
| ------------------- | ----------------------------- |
| High Sensitivity    | 5 failures within 10 minutes  |
| Low False Positives | 10 failures within 10 minutes |

The comparison demonstrates the real-world trade-off between:

* Detection coverage
* False alarm reduction
* SOC analyst workload
* Alert fatigue

---

## Technologies Used

| Category             | Tools                                          |
| -------------------- | ---------------------------------------------- |
| Programming Language | Python                                         |
| Data Processing      | Pandas                                         |
| Pattern Matching     | Regex                                          |
| Metrics & Evaluation | Scikit-Learn                                   |
| Operating Systems    | Ubuntu Server, Kali Linux                      |
| Security Logs        | Linux Authentication Logs                      |
| Security Concepts    | HIDS, Detection Engineering, Threat Monitoring |

---

## Repository Structure

```text
hids-log-analyzer/
│
├── hids_detector.py
├── auth_log.txt
├── requirements.txt
├── README.md
│
├── docs/
│   ├── Technical_Report.pdf
│   └── Background_Research.pdf
│
└── screenshots/
    ├── architecture.png
    ├── detection_output.png
    └── metrics_results.png
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/knbhatt/hids-log-analyzer.git
cd hids-log-analyzer
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Detection Engine

```bash
python hids_detector.py
```

---

## Sample Output

```text
Successfully Parsed 142 Security Events

[ALERT] SSH Brute Force Detected
Source IP: 192.168.29.xxx

[ALERT] Potential Privilege Escalation Detected

TPR: 0.91
FPR: 0.07
```

---

## Security Concepts Demonstrated

* Host-Based Intrusion Detection Systems (HIDS)
* Log Analysis
* Detection Engineering
* Threat Monitoring
* Security Event Correlation
* Brute Force Detection
* Privilege Escalation Detection
* Security Metrics Evaluation
* SOC Workflow Fundamentals

---

## Future Enhancements

* Real-time log monitoring
* SIEM integration
* Email alerting
* Slack alerting
* Fail2Ban integration
* MITRE ATT&CK mapping
* Machine Learning-based anomaly detection
* Dashboard-based visualization

---

## Academic Context

Developed as part of the **M.Tech Cyber Security Program at Nirma University**.

The project focuses on practical intrusion detection through log analysis, security event correlation, and quantitative evaluation of detection effectiveness in a controlled lab environment.
