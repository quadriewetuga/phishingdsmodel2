import joblib
import numpy as np
import pandas as pd
from scripts.feature_engineering import extract_features  # adjust if path differs

# Load your model (adjust the path if needed)
model = joblib.load("models/random_forest_model2.pkl")

def predict_url(url: str) -> tuple[int, float]:
    # Extract features from the URL
    features_df = extract_features([url])  # make sure it returns a DataFrame
    features_array = features_df.values  # convert to NumPy array if needed

    # Get prediction and confidence
    prediction = model.predict(features_array)[0]
    prediction_proba = model.predict_proba(features_array)[0]  # array like [0.1, 0.9]
    confidence = max(prediction_proba)  # highest probability score (confidence)

    return int(prediction), float(confidence)
