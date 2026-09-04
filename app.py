# Mapping raw dataset keys to user-friendly titles and guidance
FEATURE_DISPLAY_NAMES = {
    "dst_host_srv_rerror_rate": ("Dest. Service REJ Error Rate", "Range 0.0 - 1.0 (Percentage of rejected connection errors)"),
    "serror_rate": ("SYN Error Rate", "Range 0.0 - 1.0 (Percentage of incomplete TCP handshakes)"),
    "dst_host_serror_rate": ("Dest. Host SYN Error Rate", "Range 0.0 - 1.0 (SYN error percentage at destination)"),
    "count": ("2-Sec Connection Count", "Number of traffic connections in the past 2 seconds"),
    "dst_host_same_src_port_rate": ("Same Source Port Rate", "Range 0.0 - 1.0 (Percentage sharing the same source port)"),
    "protocol_type": ("Protocol Type", "0 = TCP, 1 = UDP, 2 = ICMP"),
    "dst_host_srv_serror_rate": ("Dest. Service SYN Error Rate", "Range 0.0 - 1.0 (SYN errors on target service)"),
    "dst_host_same_srv_rate": ("Same Service Access Rate", "Range 0.0 - 1.0 (Percentage targeting same service)"),
    "srv_serror_rate": ("Service SYN Error Rate", "Range 0.0 - 1.0 (Overall service connection error rate)"),
    "dst_host_srv_count": ("Target Service Active Count", "Total active connections to destination service"),
    "logged_in": ("User Authenticated Status", "0 = Unauthenticated / Guest, 1 = Logged In"),
    "same_srv_rate": ("Same Service Proportion", "Range 0.0 - 1.0 (Proportion of connections to same service)")
}

st.subheader("Interactive Network Flow Inspector")
user_inputs = {}
cols = st.columns(3)

for idx, feat in enumerate(selected_features):
    col = cols[idx % 3]
    display_title, help_text = FEATURE_DISPLAY_NAMES.get(
        feat, (feat.replace("_", " ").title(), "Enter numeric flow parameter")
    )
    
    # Render fields with clear labels and informative hover tooltips
    user_inputs[feat] = col.number_input(
        label=display_title,
        value=0.0,
        help=help_text,
        key=feat
    )
