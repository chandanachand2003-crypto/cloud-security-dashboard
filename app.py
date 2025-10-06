
import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
from datetime import datetime, timedelta
import re

# Set page config
st.set_page_config(
    page_title="Advanced Security Event Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .alert-high {
        color: #ff4b4b;
        font-weight: bold;
    }
    .alert-medium {
        color: #ff8c00;
        font-weight: bold;
    }
    .alert-low {
        color: #00cc00;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Main title
st.markdown('<h1 class="main-header">🛡️ Advanced Cloud Security Event Dashboard</h1>', unsafe_allow_html=True)

# Sidebar for filters and controls
st.sidebar.header("🔧 Dashboard Controls")
st.sidebar.markdown("---")

# File upload
uploaded_file = st.file_uploader(
    "📁 Upload IDS Alert Log File", 
    type=["json", "log"],
    help="Upload Suricata/Zeek JSON alert logs for analysis"
)

# Demo data option
if st.sidebar.button("🎯 Load Demo Data"):
    demo_data = [
        {"timestamp":"2025-10-06T12:05:00Z","src_ip":"192.168.1.10","dest_ip":"8.8.8.8","alert":{"signature":"DNS Query"},"severity":"medium"},
        {"timestamp":"2025-10-06T12:06:00Z","src_ip":"10.0.0.12","dest_ip":"10.0.0.5","alert":{"signature":"HTTP Connection"},"severity":"low"},
        {"timestamp":"2025-10-06T12:07:00Z","src_ip":"192.168.1.11","dest_ip":"192.168.1.1","alert":{"signature":"Port Scan"},"severity":"high"},
        {"timestamp":"2025-10-06T12:08:00Z","src_ip":"192.168.1.15","dest_ip":"8.8.4.4","alert":{"signature":"DNS Query"},"severity":"medium"},
        {"timestamp":"2025-10-06T12:09:00Z","src_ip":"10.0.0.20","dest_ip":"172.16.0.2","alert":{"signature":"SSH Brute Force"},"severity":"critical"},
        {"timestamp":"2025-10-06T12:10:00Z","src_ip":"192.168.1.19","dest_ip":"192.168.1.1","alert":{"signature":"Malware Traffic"},"severity":"critical"},
        {"timestamp":"2025-10-06T12:11:00Z","src_ip":"10.0.0.18","dest_ip":"10.0.0.5","alert":{"signature":"HTTP Connection"},"severity":"low"},
        {"timestamp":"2025-10-06T12:12:00Z","src_ip":"192.168.1.23","dest_ip":"8.8.8.8","alert":{"signature":"DNS Query"},"severity":"medium"},
        {"timestamp":"2025-10-06T12:13:00Z","src_ip":"192.168.1.29","dest_ip":"192.168.1.1","alert":{"signature":"SSH Brute Force"},"severity":"critical"},
        {"timestamp":"2025-10-06T12:14:00Z","src_ip":"10.0.0.21","dest_ip":"192.168.1.1","alert":{"signature":"Port Scan"},"severity":"high"},
        {"timestamp":"2025-10-06T12:15:00Z","src_ip":"192.168.1.14","dest_ip":"8.8.4.4","alert":{"signature":"Malware Traffic"},"severity":"critical"},
        {"timestamp":"2025-10-06T12:16:00Z","src_ip":"10.0.0.27","dest_ip":"10.0.0.5","alert":{"signature":"HTTP Connection"},"severity":"low"},
        {"timestamp":"2025-10-06T12:17:00Z","src_ip":"192.168.1.34","dest_ip":"172.16.0.2","alert":{"signature":"SQL Injection"},"severity":"critical"},
        {"timestamp":"2025-10-06T12:18:00Z","src_ip":"10.0.0.32","dest_ip":"8.8.8.8","alert":{"signature":"DDoS Attack"},"severity":"critical"},
        {"timestamp":"2025-10-06T12:19:00Z","src_ip":"192.168.1.38","dest_ip":"192.168.1.1","alert":{"signature":"Port Scan"},"severity":"high"}
    ]
    st.session_state['demo_data'] = demo_data
    st.sidebar.success("Demo data loaded!")

# Process uploaded file or demo data
data = []
if uploaded_file:
    try:
        for line in uploaded_file:
            try:
                data.append(json.loads(line.decode("utf-8")))
            except Exception:
                continue
    except Exception as e:
        st.error(f"Error reading file: {e}")

elif 'demo_data' in st.session_state:
    data = st.session_state['demo_data']

if data:
    df = pd.DataFrame(data)

    # Add severity if not present
    if 'severity' not in df.columns:
        def assign_severity(signature):
            if isinstance(signature, dict):
                sig = signature.get('signature', '').lower()
            else:
                sig = str(signature).lower()

            if any(word in sig for word in ['malware', 'brute force', 'sql injection', 'ddos']):
                return 'critical'
            elif any(word in sig for word in ['port scan', 'intrusion']):
                return 'high'
            elif any(word in sig for word in ['dns', 'http']):
                return 'medium'
            else:
                return 'low'

        df['severity'] = df['alert'].apply(assign_severity)

    # Extract alert signatures
    if 'alert' in df.columns:
        df['signature'] = df['alert'].apply(lambda x: x.get('signature') if isinstance(x, dict) else str(x))

    # Convert timestamp to datetime if present
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Sidebar filters
    st.sidebar.markdown("### 🔍 Filters")

    # Severity filter
    severities = df['severity'].unique() if 'severity' in df.columns else []
    selected_severities = st.sidebar.multiselect(
        "Filter by Severity", 
        severities, 
        default=severities
    )

    # Alert type filter
    alert_types = df['signature'].unique() if 'signature' in df.columns else []
    selected_alerts = st.sidebar.multiselect(
        "Filter by Alert Type", 
        alert_types, 
        default=alert_types
    )

    # Apply filters
    filtered_df = df.copy()
    if selected_severities:
        filtered_df = filtered_df[filtered_df['severity'].isin(selected_severities)]
    if selected_alerts:
        filtered_df = filtered_df[filtered_df['signature'].isin(selected_alerts)]

    # Main dashboard layout
    col1, col2, col3, col4 = st.columns(4)

    # Key metrics
    with col1:
        st.metric("📊 Total Alerts", len(filtered_df))

    with col2:
        critical_count = len(filtered_df[filtered_df['severity'] == 'critical']) if 'severity' in filtered_df.columns else 0
        st.metric("🚨 Critical Alerts", critical_count)

    with col3:
        unique_ips = filtered_df['src_ip'].nunique() if 'src_ip' in filtered_df.columns else 0
        st.metric("🌐 Unique Source IPs", unique_ips)

    with col4:
        unique_signatures = filtered_df['signature'].nunique() if 'signature' in filtered_df.columns else 0
        st.metric("🎯 Alert Types", unique_signatures)

    st.markdown("---")

    # Charts section
    if len(filtered_df) > 0:
        tab1, tab2, tab3, tab4 = st.tabs(["📈 Alert Analysis", "🗺️ IP Analysis", "⏱️ Timeline", "📋 Raw Data"])

        with tab1:
            col1, col2 = st.columns(2)

            with col1:
                # Alert types pie chart
                if 'signature' in filtered_df.columns:
                    alert_counts = filtered_df['signature'].value_counts()
                    fig_pie = px.pie(
                        values=alert_counts.values, 
                        names=alert_counts.index,
                        title="🎯 Alert Types Distribution",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)

            with col2:
                # Severity distribution
                if 'severity' in filtered_df.columns:
                    severity_counts = filtered_df['severity'].value_counts()
                    colors = {'critical': '#ff4b4b', 'high': '#ff8c00', 'medium': '#ffd700', 'low': '#00cc00'}
                    fig_bar = px.bar(
                        x=severity_counts.index, 
                        y=severity_counts.values,
                        title="⚠️ Severity Distribution",
                        labels={'x': 'Severity Level', 'y': 'Number of Alerts'},
                        color=severity_counts.index,
                        color_discrete_map=colors
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)

        with tab2:
            col1, col2 = st.columns(2)

            with col1:
                # Top source IPs
                if 'src_ip' in filtered_df.columns:
                    top_src_ips = filtered_df['src_ip'].value_counts().head(10)
                    fig_src = px.bar(
                        x=top_src_ips.values,
                        y=top_src_ips.index,
                        orientation='h',
                        title="🔴 Top Source IPs",
                        labels={'x': 'Number of Alerts', 'y': 'Source IP'}
                    )
                    st.plotly_chart(fig_src, use_container_width=True)

            with col2:
                # Top destination IPs
                if 'dest_ip' in filtered_df.columns:
                    top_dest_ips = filtered_df['dest_ip'].value_counts().head(10)
                    fig_dest = px.bar(
                        x=top_dest_ips.values,
                        y=top_dest_ips.index,
                        orientation='h',
                        title="🟢 Top Destination IPs",
                        labels={'x': 'Number of Alerts', 'y': 'Destination IP'}
                    )
                    st.plotly_chart(fig_dest, use_container_width=True)

        with tab3:
            # Timeline analysis
            if 'timestamp' in filtered_df.columns:
                # Alerts over time
                df_time = filtered_df.copy()
                df_time['hour'] = df_time['timestamp'].dt.hour
                hourly_counts = df_time.groupby('hour').size().reindex(range(24), fill_value=0)

                fig_timeline = px.line(
                    x=hourly_counts.index,
                    y=hourly_counts.values,
                    title="📅 Alerts Timeline (by Hour)",
                    labels={'x': 'Hour of Day', 'y': 'Number of Alerts'},
                    markers=True
                )
                st.plotly_chart(fig_timeline, use_container_width=True)

                # Heatmap by severity and hour
                if 'severity' in df_time.columns:
                    heatmap_data = df_time.groupby(['hour', 'severity']).size().unstack(fill_value=0)
                    fig_heatmap = px.imshow(
                        heatmap_data.T,
                        title="🔥 Alert Severity Heatmap by Hour",
                        labels={'x': 'Hour of Day', 'y': 'Severity Level', 'color': 'Alert Count'},
                        color_continuous_scale='Reds'
                    )
                    st.plotly_chart(fig_heatmap, use_container_width=True)

        with tab4:
            # Enhanced data table with search and filters
            st.subheader("📋 Alert Details")

            # Search functionality
            search_term = st.text_input("🔍 Search alerts:", placeholder="Enter IP, signature, or any term...")

            display_df = filtered_df.copy()
            if search_term:
                mask = display_df.astype(str).apply(lambda x: x.str.contains(search_term, case=False, na=False)).any(axis=1)
                display_df = display_df[mask]

            # Color-code severity
            def highlight_severity(val):
                if val == 'critical':
                    return 'background-color: #ffebee; color: #c62828'
                elif val == 'high':
                    return 'background-color: #fff3e0; color: #ef6c00'
                elif val == 'medium':
                    return 'background-color: #fffde7; color: #f57f17'
                else:
                    return 'background-color: #e8f5e8; color: #2e7d32'

            if len(display_df) > 0:
                styled_df = display_df.style.applymap(highlight_severity, subset=['severity'] if 'severity' in display_df.columns else [])
                st.dataframe(styled_df, use_container_width=True, height=400)

                # Export functionality
                csv = display_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Filtered Data as CSV",
                    data=csv,
                    file_name=f'security_alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                    mime='text/csv'
                )
            else:
                st.info("No alerts match your search criteria.")

    # Additional insights
    st.markdown("---")
    st.subheader("🧠 Security Insights")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🎯 Top Attack Patterns")
        if 'signature' in filtered_df.columns:
            top_patterns = filtered_df['signature'].value_counts().head(5)
            for pattern, count in top_patterns.items():
                st.write(f"• **{pattern}**: {count} occurrences")

    with col2:
        st.markdown("### ⚠️ Security Recommendations")
        if 'severity' in filtered_df.columns:
            critical_alerts = len(filtered_df[filtered_df['severity'] == 'critical'])
            if critical_alerts > 0:
                st.warning(f"🚨 {critical_alerts} critical alerts require immediate attention!")

            high_alerts = len(filtered_df[filtered_df['severity'] == 'high'])
            if high_alerts > 0:
                st.info(f"⚠️ {high_alerts} high-priority alerts need investigation.")

            st.success("✅ Implement network segmentation to reduce attack surface.")
            st.success("✅ Enable multi-factor authentication on all systems.")

else:
    # Welcome screen
    st.info("👆 Upload an IDS alert log file or click 'Load Demo Data' to get started!")

    col1, col2, col3 = st.columns(3)
    with col2:
        st.markdown("""
        ### 🚀 Features:
        - **Real-time alert analysis**
        - **Interactive visualizations** 
        - **IP address tracking**
        - **Timeline analysis**
        - **Severity classification**
        - **Export capabilities**
        - **Search and filtering**
        """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ Advanced Cloud Security Event Dashboard | Built with Streamlit & Plotly</p>
    <p>Upload Suricata/Zeek JSON logs for comprehensive security analysis</p>
</div>
""", unsafe_allow_html=True)
