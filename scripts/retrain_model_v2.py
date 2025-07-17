import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# === Step 1: Load your dataset from data subfolder ===
df = pd.read_csv("data/processed_dataset.csv")  # use relative path

# === Step 2: Prepare your data ===
X = df.drop(["url", "domain", "status"], axis=1)
y = df["status"].map({"phishing": 1, "legitimate": 0})

# === Step 3: Split the data ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# === Step 4: Train the model ===
model_v2 = RandomForestClassifier(n_estimators=100, random_state=42)
model_v2.fit(X_train, y_train)

# === Step 5: Evaluate it ===
y_pred = model_v2.predict(X_test)
print("🔍 Model Evaluation:")
print(classification_report(y_test, y_pred))

# === Step 6: Save to models/ folder as random_forest_model2.pkl ===
joblib.dump(model_v2, "models/random_forest_model2.pkl")
print("✅ Model saved as models/random_forest_model2.pkl")
print("Training Features:", list(X.columns))
