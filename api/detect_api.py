from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from utils.feature_engineering import extract_features
from utils.history import save_detection_history
import joblib
import pandas as pd
import numpy as np
import traceback

# Initialize FastAPI app
app = FastAPI()

# Enable CORS so the extension can access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request model
class ScanRequest(BaseModel):
    url: str
    username: str

# Load ML model
model = joblib.load("models/random_forest_model2.pkl")

# Prediction helper
def predict_url(url: str):
    try:
        print(f"🕵️‍♂️ Scanning URL: {url}")

        # Extract features (returns DataFrame)
        features = extract_features(url)
        print(f"🧬 extract_features returned type: {type(features)}")

        if features is None:
            print("❌ Feature extraction returned None.")
            return {"error": "Feature extraction failed."}

        if not isinstance(features, pd.DataFrame):
            print(f"❌ Feature extraction returned type {type(features)}, expected DataFrame.")
            return {"error": "Invalid feature format — expected DataFrame"}

        df = features
        print(f"📊 DataFrame shape: {df.shape}, Columns: {df.columns.tolist()}")

        # Sanity checks
        if df.isnull().any().any():
            print("❌ DataFrame contains NaN values.")
            return {"error": "Invalid features (NaN detected)."}

        if df.empty:
            print("❌ DataFrame is empty.")
            return {"error": "Feature DataFrame is empty."}

        # Prediction
        prediction = model.predict(df)[0]
        confidence = round(model.predict_proba(df)[0][prediction] * 100, 2)

        print(f"🎯 Prediction: {prediction}, Confidence: {confidence}%")
        return {"label": int(prediction), "confidence": confidence}

    except Exception as e:
        print("🔥 Exception during prediction:")
        print(traceback.format_exc())
        return {"error": f"Prediction failed: {str(e)}"}


@app.post("/scan_and_save")
async def scan_and_save(scan: ScanRequest):
    print("📥 Incoming scan request:")
    print(f"🔗 URL: {scan.url}")
    print(f"👤 Username: {scan.username}")

    if not scan.url or not scan.username:
        return {"error": "Missing url or username"}

    result = predict_url(scan.url)
    print(f"✅ Final Result: {result}")

    if "error" in result:
        return result

    try:
        save_detection_history(
            username=scan.username,
            url=scan.url,
            prediction_label="Phishing" if result["label"] == 1 else "Legitimate",
            confidence=result["confidence"]
        )
    except Exception as e:
        print(f"⚠️ Failed to save history: {e}")

    return result
