import streamlit as st
import joblib
import numpy as np
import plotly.graph_objects as go
from datetime import datetime, timezone
from utils.feature_engineering import extract_features
from utils.history import save_detection_history  # ✅ Import history saver

# Load the trained model once
@st.cache_resource
def load_model():
    return joblib.load("models/random_forest_model2.pkl")

model = load_model()

def render_dashboard():
    st.title("Detection Dashboard")
    st.markdown("Enter a URL below to check if it's legitimate or a phishing attempt.")

    url = st.text_input("🔗 Enter URL", placeholder="https://example.com")

    if st.button("Scan URL", key="check_btn"):
        if not url.strip():
            st.error("Please enter a valid URL.")
            return

        try:
            # Feature extraction
            feats = extract_features(url)
            # if dict, convert to 2D array
            if isinstance(feats, dict):
                X = np.array(list(feats.values())).reshape(1, -1)
            else:
                X = np.array(feats).reshape(1, -1)

            # Prediction & confidence
            pred = model.predict(X)[0]
            probs = model.predict_proba(X)[0]
            conf = probs[pred]

            # ✅ Save detection history
            if "user" in st.session_state:
                print("Saving history for:", st.session_state.user, url) #Debug
                save_detection_history(
                    username=st.session_state.user,
                    url=url,
                    prediction_label="Phishing" if pred == 1 else "Legitimate",
                    confidence=round(conf * 100, 2),
                )

            # Show result
            if pred == 1:
                st.error("🚨 The URL is likely a phishing site.")
            else:
                st.success("✅ The URL is likely legitimate.")

            # Gauge for confidence
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=conf * 100,
                number={"suffix": "%"},
                title={"text": "Confidence Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#64ffda"},
                    "steps": [
                        {"range": [0, 50], "color": "#1b263b"},
                        {"range": [50, 100], "color": "#0d1b2a"},
                    ]
                }
            ))
            st.plotly_chart(gauge, use_container_width=True)

            #Improved Bar Chart: Phishing vs Legitimate
            bar_fig = go.Figure(data=[
                go.Bar(
                    name="Phishing",
                    x=["Phishing"],
                    y=[probs[1]],
                    marker_color="#ff4d4d",
                    text=f"{probs[1]*100:.2f}%",
                    textposition="outside"
                ),
                go.Bar(
                    name="Legitimate",
                    x=["Legitimate"],
                    y=[probs[0]],
                    marker_color="#00ff4c",
                    text=f"{probs[0]*100:.2f}%",
                    textposition="outside"
                )
            ])

            bar_fig.update_layout(
                title="🔍 Prediction Confidence by Class",
                xaxis_title="Class",
                yaxis_title="Probability",
                yaxis=dict(range=[0, 1]),
                barmode="group",
                plot_bgcolor="#0d1b2a",
                paper_bgcolor="#0d1b2a",
                font=dict(color="#d8f3dc", size=14),
                margin=dict(t=50, b=40, l=40, r=40),
                height=400
            )

            st.plotly_chart(bar_fig, use_container_width=True)

        except Exception as e:
            st.error(f"❌ Error processing URL: {e}")
