import streamlit as st
import pandas as pd
import numpy as np
import joblib

st.set_page_config(page_title="Taraba State School of Nursing IDS", page_icon="🛡️", layout="wide")

st.title("🛡️ Machine Learning Intrusion Detection System")
st.caption("Case Study: Taraba State School of Nursing Network Environment")

@st.cache_resource
def load_artifacts():
    return joblib.load('ids_taraba_model.pkl')

try:
    artifacts = load_artifacts()
    model = artifacts['model']
    scaler = artifacts['scaler']
    selected_features = artifacts['selected_features']
    st.sidebar.success("Model pipeline loaded successfully.")
except Exception as e:
    st.error("Failed to load model file 'ids_taraba_model.pkl'. Please check directory.")
    st.stop()

# Human-readable labels and descriptions
FEATURE_DISPLAY_NAMES = {
    "dst_host_srv_rerror_rate": ("Dest. Service REJ Error Rate", "Range 0.0 - 1.0"),
    "serror_rate": ("SYN Error Rate", "Range 0.0 - 1.0"),
    "dst_host_serror_rate": ("Dest. Host SYN Error Rate", "Range 0.0 - 1.0"),
    "count": ("2-Sec Connection Count", "Active connection count in last 2 seconds"),
    "dst_host_same_src_port_rate": ("Same Source Port Rate", "Range 0.0 - 1.0"),
    "protocol_type": ("Protocol Type", "0 = TCP, 1 = UDP, 2 = ICMP"),
    "dst_host_srv_serror_rate": ("Dest. Service SYN Error Rate", "Range 0.0 - 1.0"),
    "dst_host_same_srv_rate": ("Same Service Access Rate", "Range 0.0 - 1.0"),
    "srv_serror_rate": ("Service SYN Error Rate", "Range 0.0 - 1.0"),
    "dst_host_srv_count": ("Target Service Active Count", "Active connection count to target service"),
    "logged_in": ("User Authenticated Status", "0 = Unauthenticated, 1 = Logged In"),
    "same_srv_rate": ("Same Service Proportion", "Range 0.0 - 1.0")
}

# Pre-calculated realistic traffic vectors based on NSL-KDD distributions
TRAFFIC_PRESETS = {
    "Normal Traffic (Portal Session)": {
        "dst_host_srv_rerror_rate": 0.00,
        "serror_rate": 0.00,
        "dst_host_serror_rate": 0.00,
        "count": 5.0,
        "dst_host_same_src_port_rate": 0.05,
        "protocol_type": 0.0, # TCP
        "dst_host_srv_serror_rate": 0.00,
        "dst_host_same_srv_rate": 1.00,
        "srv_serror_rate": 0.00,
        "dst_host_srv_count": 255.0,
        "logged_in": 1.0, # Logged in
        "same_srv_rate": 1.00
    },
    "DDoS SYN Flood Attack": {
        "dst_host_srv_rerror_rate": 0.00,
        "serror_rate": 1.00,
        "dst_host_serror_rate": 1.00,
        "count": 511.0, # Massive burst
        "dst_host_same_src_port_rate": 1.00,
        "protocol_type": 0.0,
        "dst_host_srv_serror_rate": 1.00,
        "dst_host_same_srv_rate": 1.00,
        "srv_serror_rate": 1.00,
        "dst_host_srv_count": 511.0,
        "logged_in": 0.0, # Unauthenticated
        "same_srv_rate": 1.00
    },
    "Port Scan Probe": {
        "dst_host_srv_rerror_rate": 1.00,
        "serror_rate": 0.00,
        "dst_host_serror_rate": 0.00,
        "count": 150.0,
        "dst_host_same_src_port_rate": 0.85,
        "protocol_type": 0.0,
        "dst_host_srv_serror_rate": 0.00,
        "dst_host_same_srv_rate": 0.02, # Rapidly hitting different ports
        "srv_serror_rate": 0.00,
        "dst_host_srv_count": 2.0,
        "logged_in": 0.0,
        "same_srv_rate": 0.02
    }
}

st.subheader("1. Quick Load Preset Scenarios")
st.write("Click a preset scenario to auto-populate realistic feature values into the form below:")

# Render preset selection buttons
preset_cols = st.columns(3)

for idx, (preset_name, preset_values) in enumerate(TRAFFIC_PRESETS.items()):
    col = preset_cols[idx % 3]
    if col.button(preset_name, use_container_width=True):
        # Update session state keys dynamically
        for feature_key, feature_val in preset_values.items():
            st.session_state[f"input_{feature_key}"] = float(feature_val)

st.divider()
st.subheader("2. Network Feature Inputs")

# Render input form with dynamic defaults tied to session state
user_inputs = {}
cols = st.columns(3)

for idx, feat in enumerate(selected_features):
    col = cols[idx % 3]
    display_title, help_text = FEATURE_DISPLAY_NAMES.get(
        feat, (feat.replace("_", " ").title(), "")
    )
    
    session_key = f"input_{feat}"
    if session_key not in st.session_state:
        st.session_state[session_key] = 0.0
        
    user_inputs[feat] = col.number_input(
        label=display_title,
        value=float(st.session_state[session_key]),
        help=help_text,
        key=session_key
    )

st.divider()

if st.button("🔍 Inspect Network Flow Payload", type="primary", use_container_width=True):
    # Construct input frame & scale
    df_input = pd.DataFrame([user_inputs])
    df_scaled = scaler.transform(df_input)
    
    prediction = model.predict(df_scaled)[0]
    probabilities = model.predict_proba(df_scaled)[0]
    
    st.subheader("Inspection Result")
    res_col1, res_col2 = st.columns(2)
    
    if prediction == 1:
        res_col1.error("🚨 **VERDICT: INTRUSION DETECTED**")
        res_col2.metric("Threat Confidence", f"{probabilities[1]*100:.1f}%")
        st.warning("⚠️ Action Required: Network flow matches known malicious anomaly signature. Re-routing or blocking IP context recommended.")
    else:
        res_col1.success("✅ **VERDICT: NORMAL TRAFFIC**")
        res_col2.metric("Legitimate Confidence", f"{probabilities[0]*100:.1f}%")
        st.info("ℹ️ Traffic pattern conforms to baseline student/staff network activity.")
