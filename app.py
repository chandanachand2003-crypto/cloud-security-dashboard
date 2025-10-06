import streamlit as st
import pandas as pd
import json
from collections import Counter

st.title("Cloud Security Event Dashboard")

st.write(
    "Upload Suricata/Zeek IDS JSON alert logs to parse and visualize threat data interactively."
)

uploaded = st.file_uploader("Upload IDS alert JSON file (.json or .log)", type=["json", "log"])

if uploaded:
    try:
        data = []
        for line in uploaded:
            try:
                data.append(json.loads(line.decode("utf-8")))
            except Exception:
                continue
        if not data:
            st.error("No valid JSON found in the uploaded file.")
        else:
            df = pd.DataFrame(data)
            st.subheader("Raw Alerts")
            st.write(df)

            if "alert" in df.columns:
                signatures = df["alert"].apply(lambda x: x.get("signature") if isinstance(x, dict) else None)
                st.write("\n**Top Alert Types:**")
                st.json(Counter(signatures).most_common(5))

            if "src_ip" in df.columns:
                st.write("\n**Top Source IPs:**")
                st.json(Counter(df["src_ip"]).most_common(5))

            st.write(f"\n**Total Alerts:** {len(df)}")

    except Exception as e:
        st.error(f"Error parsing file: {e}")
else:
    st.info("Please upload an IDS alert log file to get started.")

st.markdown("---")
st.markdown("Sample test logs can be found by searching 'Suricata EVE JSON sample' online.")
