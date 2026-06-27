# Network-Traffic-Intrusion-Detection
Machine Learning pipeline for network traffic intrusion detection using LightGBM and domain-specific feature engineering.
Overview

This repository presents a machine learning solution for multi-class network intrusion detection using protocol-level network traffic data.

The project was developed for a machine learning competition where the objective is to classify each captured network packet into one of 16 traffic categories, including normal traffic and various cyber attacks such as DoS, DDoS, SQL Injection, XSS, Port Scanning, FTP attacks, SSH brute force, and SYN Flood.

The solution focuses on extensive domain-specific feature engineering combined with a LightGBM classifier trained using Stratified K-Fold Cross Validation.

Problem Description

Each row in the dataset represents a single captured network packet extracted from Wireshark.

The dataset contains protocol information from multiple network layers including:

Ethernet
IP
TCP
UDP
ICMP
HTTP
DNS

One of the main challenges is that many protocol-specific fields are naturally missing because every packet does not contain every protocol.

The goal is to predict the correct attack category for unseen network packets.

Dataset

Training Samples:

Approximately 3.3 Million packets

Test Samples:

Approximately 1.2 Million packets

Target Classes:

16 traffic categories

Evaluation Metric:

Weighted F1 Score
Machine Learning Pipeline
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
LightGBM Training
        │
        ▼
5-Fold Stratified Cross Validation
        │
        ▼
Prediction
        │
        ▼
Submission File
Feature Engineering

A significant part of the project focuses on extracting informative features from raw network packet fields.

Protocol Indicators
TCP availability
UDP availability
HTTP availability
DNS availability
ICMP availability
TCP Features
SYN Flag
ACK Flag
FIN Flag
RST Flag
SYN-only packets
TCP Window Size
Log-transformed TCP Window Size
Low Source Port
Low Destination Port
High Destination Port
Packet Statistics
Packet Length
Frame Length
Length Difference
Tiny Packet Detection
Large Packet Detection
Port-Based Features

Detection of commonly used service ports:

HTTP (80)
HTTPS (443)
FTP (21)
SSH (22)
Telnet (23)
MySQL (3306)
HTTP Proxy (8080)
DNS (53)
HTTP Features
HTTP Request Method
URI Length
Cookie Presence
Authorization Header
Referer Header

Security-oriented features:

SQL Injection Pattern Detection
Cross-Site Scripting (XSS) Pattern Detection
DNS Features
Query Name Length
Number of Subdomains
ICMP Features
Echo Request
Echo Reply
IP Features
Protocol Identification
TTL
Packet Length
Fragment Offset
IP Flags
Data Preprocessing

The preprocessing pipeline includes:

Missing value handling
Numeric conversion of protocol fields
Label Encoding for categorical features
Removal of unused columns
Feature type validation
Model

Algorithm:

LightGBM

Training Strategy:

Stratified 5-Fold Cross Validation

Validation:

Out-of-Fold Prediction

Early Stopping:

Enabled

Random Seed:

42
Libraries
Python
Pandas
NumPy
LightGBM
Scikit-Learn
Project Structure
Network-Traffic-Intrusion-Detection/

│── train.py

│── requirements.txt

│── README.md

└── sample_output/
Future Improvements

Possible future improvements include:

Hyperparameter Optimization using Optuna
Feature Importance Analysis
SHAP Explainability
Ensemble Models
CatBoost and XGBoost Comparison
Error Analysis
Model Calibration
Skills Demonstrated
Machine Learning
Feature Engineering
Network Traffic Analysis
Cybersecurity Analytics
Multi-class Classification
Cross Validation
LightGBM
Data Preprocessing
Large-scale Dataset Handling
