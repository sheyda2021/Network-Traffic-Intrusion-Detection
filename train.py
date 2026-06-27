"""
Network Traffic Intrusion Detection - Optimized Solution
Target: Beat score 0.6965 (current #1)
Strategy: LightGBM + rich feature engineering
"""

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
import warnings
import os
import gc

warnings.filterwarnings('ignore')

BASE = 'dataset/public'
TRAIN_PATH = os.path.join(BASE, 'train.csv')
TEST_PATH  = os.path.join(BASE, 'test.csv')
OUTPUT_PATH = 'working/submission.csv'

print("="*60)
print("Loading data...")

train = pd.read_csv(TRAIN_PATH)
test  = pd.read_csv(TEST_PATH)

print(f"Train: {train.shape}, Test: {test.shape}")

def feature_engineering(df):
    df = df.copy()

    df['has_tcp']  = df['TCP Source Port'].notna().astype(np.int8)
    df['has_udp']  = df['UDP Source Port'].notna().astype(np.int8)
    df['has_icmp'] = df['ICMP Type'].notna().astype(np.int8)
    df['has_http'] = df['HTTP Request Method'].notna().astype(np.int8)
    df['has_dns']  = df['DNS Query Name'].notna().astype(np.int8)

    for col in ['TCP SYN Flag', 'TCP ACK Flag', 'TCP FIN Flag', 'TCP RST Flag']:
        df[col] = (df[col] == 'Set').astype(np.int8)

    df['syn_only'] = ((df['TCP SYN Flag'] == 1) & (df['TCP ACK Flag'] == 0)).astype(np.int8)

    for col in ['IP Length', 'IP TTL', 'IP Protocol', 'IP Version', 'IP Fragment Offset']:
        df[col] = pd.to_numeric(
            df[col].astype(str).str.extract(r'(\d+\.?\d*)')[0], errors='coerce'
        )

    # Fix HTTP numeric cols stored as object
    for col in ['HTTP Response Code', 'HTTP Content-Length']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    df['tcp_dst_is_80']   = (df['TCP Destination Port'] == 80).astype(np.int8)
    df['tcp_dst_is_443']  = (df['TCP Destination Port'] == 443).astype(np.int8)
    df['tcp_dst_is_21']   = (df['TCP Destination Port'] == 21).astype(np.int8)
    df['tcp_dst_is_22']   = (df['TCP Destination Port'] == 22).astype(np.int8)
    df['tcp_dst_is_23']   = (df['TCP Destination Port'] == 23).astype(np.int8)
    df['tcp_dst_is_3306'] = (df['TCP Destination Port'] == 3306).astype(np.int8)
    df['tcp_dst_is_8080'] = (df['TCP Destination Port'] == 8080).astype(np.int8)
    df['udp_dst_is_53']   = (df['UDP Destination Port'] == 53).astype(np.int8)

    df['tcp_src_port_low']  = (df['TCP Source Port'] < 1024).astype(np.int8)
    df['tcp_dst_port_low']  = (df['TCP Destination Port'] < 1024).astype(np.int8)
    df['tcp_dst_port_high'] = (df['TCP Destination Port'] > 49152).astype(np.int8)

    df['length_diff'] = df['frame length'] - df['Length']
    df['is_tiny_pkt']  = (df['Length'] < 60).astype(np.int8)
    df['is_large_pkt'] = (df['Length'] > 1400).astype(np.int8)

    df['http_method_enc'] = df['HTTP Request Method'].fillna('NONE')

    sql_kw = r"(?i)(select|union|insert|drop|exec|xp_|or\s+1=1|'--)"
    df['uri_has_sql'] = df['HTTP Request URI'].fillna('').str.contains(sql_kw, regex=True).astype(np.int8)

    xss_kw = r"(?i)(<script|javascript:|onerror=|onload=|alert\()"
    df['uri_has_xss'] = df['HTTP Request URI'].fillna('').str.contains(xss_kw, regex=True).astype(np.int8)

    df['uri_length']  = df['HTTP Request URI'].fillna('').str.len()
    df['has_cookie']  = df['HTTP Cookie'].notna().astype(np.int8)
    df['has_referer'] = df['HTTP Referer'].notna().astype(np.int8)
    df['has_auth']    = df['HTTP Authorization'].notna().astype(np.int8)

    df['icmp_is_echo']  = (df['ICMP Type'] == 8).astype(np.int8)
    df['icmp_is_reply'] = (df['ICMP Type'] == 0).astype(np.int8)

    df['is_arp'] = (df['Ethernet Type'] == 'ARP').astype(np.int8)

    ip_flags_map = {'0x0000': 0, '0x4000': 1, '0x2000': 2}
    df['ip_flags_num'] = df['IP Flags'].map(ip_flags_map).fillna(-1).astype(np.int8)

    df['tcp_win_is_zero'] = (df['TCP Window Size'] == 0).astype(np.int8)
    df['tcp_win_log'] = np.log1p(df['TCP Window Size'].fillna(0))

    df['dns_name_length']     = df['DNS Query Name'].fillna('').str.len()
    df['dns_subdomain_count'] = df['DNS Query Name'].fillna('').str.count(r'\.')

    df['eth_type_enc'] = df['Ethernet Type'].fillna('Unknown')

    df['ip_proto_is_tcp']  = (df['IP Protocol'] == 6).astype(np.int8)
    df['ip_proto_is_udp']  = (df['IP Protocol'] == 17).astype(np.int8)
    df['ip_proto_is_icmp'] = (df['IP Protocol'] == 1).astype(np.int8)

    return df

print("Feature engineering...")
train = feature_engineering(train)
test  = feature_engineering(test)

CAT_COLS = [
    'Ethernet Type', 'IP Flags', 'IP DSCP Field',
    'TCP Flags', 'HTTP Request Method', 'HTTP Request Version',
    'HTTP Content Type', 'HTTP Connection',
    'DNS Query Type', 'eth_type_enc', 'http_method_enc',
    'IP Checksum', 'TCP Checksum', 'UDP Checksum', 'ICMP Checksum',
]
CAT_COLS = [c for c in CAT_COLS if c in train.columns]

label_encoders = {}
for col in CAT_COLS:
    le = LabelEncoder()
    combined = pd.concat([
        train[col].fillna('NaN'),
        test[col].fillna('NaN')
    ], axis=0).astype(str)
    le.fit(combined)
    train[col] = le.transform(train[col].fillna('NaN').astype(str))
    test[col]  = le.transform(test[col].fillna('NaN').astype(str))

print("Encoding done.")

DROP_COLS = [
    'measurement_id',
    'HTTP Request URI', 'HTTP Full URI', 'HTTP User-Agent',
    'HTTP Cookie', 'HTTP Host', 'HTTP Referer',
    'HTTP Location', 'HTTP Authorization',
    'DNS Query Name', 'IP Version',
]
DROP_COLS = [c for c in DROP_COLS if c in train.columns]

TARGET = 'attack_type'
FEATURE_COLS = [c for c in train.columns if c not in DROP_COLS + [TARGET]]

# Final safety check - convert any leftover object cols
print("Checking dtypes...")
for col in FEATURE_COLS:
    if train[col].dtype == object:
        print(f"  Converting {col}...")
        train[col] = pd.to_numeric(train[col], errors='coerce')
        test[col]  = pd.to_numeric(test[col], errors='coerce')

X      = train[FEATURE_COLS]
y_raw  = train[TARGET]
X_test = test[FEATURE_COLS]

le_target = LabelEncoder()
y = le_target.fit_transform(y_raw)

print(f"Features: {len(FEATURE_COLS)}")
print(f"Classes: {list(le_target.classes_)}")

lgb_params = {
    'objective': 'multiclass',
    'num_class': len(le_target.classes_),
    'metric': 'multi_logloss',
    'boosting_type': 'gbdt',
    'n_estimators': 1000,
    'learning_rate': 0.05,
    'num_leaves': 127,
    'max_depth': -1,
    'min_child_samples': 20,
    'feature_fraction': 0.8,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'lambda_l1': 0.1,
    'lambda_l2': 0.1,
    'verbose': -1,
    'n_jobs': -1,
    'random_state': 42,
}

N_FOLDS = 5
skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)

oof_preds  = np.zeros((len(X), len(le_target.classes_)))
test_preds = np.zeros((len(X_test), len(le_target.classes_)))

print(f"\nStarting {N_FOLDS}-Fold CV...")

for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
    print(f"\n--- Fold {fold+1}/{N_FOLDS} ---")

    X_tr, X_val = X.iloc[train_idx], X.iloc[val_idx]
    y_tr, y_val = y[train_idx], y[val_idx]

    model = lgb.LGBMClassifier(**lgb_params)
    model.fit(
        X_tr, y_tr,
        eval_set=[(X_val, y_val)],
        callbacks=[
            lgb.early_stopping(stopping_rounds=50, verbose=False),
            lgb.log_evaluation(period=100),
        ]
    )

    val_prob = model.predict_proba(X_val)
    oof_preds[val_idx] = val_prob

    val_pred = np.argmax(val_prob, axis=1)
    fold_f1 = f1_score(y_val, val_pred, average='weighted')
    print(f"Fold {fold+1} Weighted F1: {fold_f1:.4f}")

    test_preds += model.predict_proba(X_test) / N_FOLDS

    del X_tr, X_val, y_tr, y_val, model
    gc.collect()

oof_labels = np.argmax(oof_preds, axis=1)
overall_f1 = f1_score(y, oof_labels, average='weighted')
print(f"\n{'='*60}")
print(f"Overall OOF Weighted F1: {overall_f1:.4f}")
print(f"{'='*60}")

test_labels       = np.argmax(test_preds, axis=1)
test_attack_types = le_target.inverse_transform(test_labels)

submission = pd.DataFrame({
    'measurement_id': test['measurement_id'],
    'attack_type': test_attack_types
})

submission.to_csv(OUTPUT_PATH, index=False)
print(f"\nSubmission saved to: {OUTPUT_PATH}")
print(f"Shape: {submission.shape}")
print(submission['attack_type'].value_counts())