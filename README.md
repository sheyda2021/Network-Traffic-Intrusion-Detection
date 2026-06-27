# Network Traffic Intrusion Detection using LightGBM

Machine Learning pipeline for **multi-class network intrusion detection** using protocol-level network traffic data, domain-specific feature engineering, and LightGBM.

---

## Project Overview

This project was developed for a machine learning competition focused on **network traffic intrusion detection**.

The objective is to classify each captured network packet into one of **16 traffic categories**, including normal traffic and multiple cyberattack types such as:

* DoS
* DDoS
* SYN Flood
* SQL Injection
* XSS
* FTP Attacks
* SSH Brute Force
* Port Scanning
* and others.

The solution combines extensive feature engineering with a LightGBM classifier trained using Stratified K-Fold Cross Validation.

---

## Dataset

| Item              | Value             |
| ----------------- | ----------------- |
| Training Samples  | ~3.3 Million      |
| Test Samples      | ~1.2 Million      |
| Classes           | 16                |
| Evaluation Metric | Weighted F1 Score |

The dataset contains packet-level features extracted from Wireshark across multiple protocol layers.

### Available Protocols

* Ethernet
* IP
* TCP
* UDP
* ICMP
* HTTP
* DNS

A major challenge of the dataset is the high sparsity caused by protocol-specific fields that are naturally missing for many packets.

---

# Machine Learning Pipeline

```
Raw Network Packets
        │
        ▼
 Data Cleaning
        │
        ▼
 Feature Engineering
        │
        ▼
 Categorical Encoding
        │
        ▼
 LightGBM
        │
        ▼
 Stratified 5-Fold Cross Validation
        │
        ▼
 Prediction
        │
        ▼
 submission.csv
```

---

# Feature Engineering

The project includes extensive handcrafted features based on networking and cybersecurity knowledge.

### Protocol Indicators

* TCP availability
* UDP availability
* HTTP availability
* DNS availability
* ICMP availability

### TCP Features

* SYN / ACK / FIN / RST flags
* SYN-only packets
* TCP Window Size
* Log-transformed Window Size
* Low / High Port Indicators

### Packet Features

* Packet Length
* Frame Length
* Length Difference
* Tiny Packet Detection
* Large Packet Detection

### Service Port Features

* HTTP (80)
* HTTPS (443)
* FTP (21)
* SSH (22)
* Telnet (23)
* DNS (53)
* MySQL (3306)
* Proxy (8080)

### HTTP Features

* HTTP Method
* URI Length
* Cookie Presence
* Referer
* Authorization

Security-oriented features:

* SQL Injection pattern detection
* Cross-Site Scripting (XSS) pattern detection

### DNS Features

* Query Length
* Number of Subdomains

### ICMP Features

* Echo Request
* Echo Reply

### IP Features

* TTL
* Protocol Type
* Fragment Offset
* IP Flags

---

# Data Preprocessing

The preprocessing pipeline includes:

* Missing value handling
* Numeric conversion of protocol fields
* Label encoding of categorical variables
* Removal of unused columns
* Data type validation

---

# Model

| Component      | Description                        |
| -------------- | ---------------------------------- |
| Algorithm      | LightGBM                           |
| Validation     | Stratified 5-Fold Cross Validation |
| Early Stopping | Yes                                |
| Random Seed    | 42                                 |

---

# Project Structure

```
Network-Traffic-Intrusion-Detection/

├── train.py
├── README.md
├── requirements.txt
└── sample_output/
```

---

# Requirements

```
Python
pandas
numpy
lightgbm
scikit-learn
```

---

# Future Improvements

Potential directions for future work include:

* Hyperparameter optimization with Optuna
* SHAP-based model explainability
* Feature importance analysis
* Ensemble learning
* CatBoost / XGBoost comparison
* Error analysis
* Probability calibration

---

# Skills Demonstrated

* Machine Learning
* Feature Engineering
* LightGBM
* Large-scale Data Processing
* Cybersecurity Analytics
* Multi-class Classification
* Cross Validation
* Data Preprocessing

---

# Notes

This repository is intended to demonstrate the end-to-end workflow of building a practical machine learning pipeline for a large-scale cybersecurity classification problem, from data preprocessing and feature engineering to model training and prediction.
