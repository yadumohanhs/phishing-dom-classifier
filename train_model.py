import os
import joblib
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from lightgbm import LGBMClassifier

# 1. Define the EXACT 14 features our extractor.py produces
FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "IsHTTPS",
    "HasTitle",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "NoOfiFrame",
    "NoOfExternalRef",
]

def load_and_prepare_data():
    print("[1/4] Fetching PhiUSIIL Phishing Dataset from UCI Repository (ID: 967)...")
    # If you already downloaded the CSV manually, you can replace these 3 lines with:
    # df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")
    dataset = fetch_ucirepo(id=967)
    X_raw = dataset.data.features
    y_raw = dataset.data.targets["label"]

    # Filter strictly to our 14 real-time features
    X = X_raw[FEATURE_COLUMNS].copy()

    # ==========================================================
    # CRITICAL LABEL FLIP:
    # In PhiUSIIL, 1 = Legitimate and 0 = Phishing.
    # In standard cybersecurity ML, 1 = Malicious/Phishing (Positive Alert)
    # and 0 = Benign (Negative). We invert it here so 1 means PHISHING!
    # ==========================================================
    y = y_raw.apply(lambda label: 1 if label == 0 else 0)

    print(f"      Loaded {len(X):,} rows | Phishing (1): {y.sum():,} | Benign (0): {(y == 0).sum():,}")
    return X, y


def train_and_evaluate():
    X, y = load_and_prepare_data()

    # 2. Split into 80% Training and 20% Testing (Stratified to keep class ratios identical)
    print("[2/4] Splitting data into train (80%) and test (20%) sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Initialize and train the LightGBM Classifier
    print("[3/4] Training LightGBM model...")
    model = LGBMClassifier(
        n_estimators=200,        # Number of boosting trees
        learning_rate=0.05,      # Step size shrinkage to prevent overfitting
        num_leaves=31,           # Maximum tree leaves for base learners
        random_state=42,
        n_jobs=-1                # Use all CPU cores for fast training
    )
    model.fit(X_train, y_train)

    # 4. Evaluate on the unseen 20% Test Set
    print("[4/4] Evaluating model performance on unseen test data...\n")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]  # Probability of class 1 (Phishing)

    print("=== CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Phishing (1)"], digits=4))

    print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}\n")

    cm = confusion_matrix(y_test, y_pred)
    print("=== CONFUSION MATRIX ===")
    print(f"True Negatives (Safe marked Safe):       {cm[0][0]:,}")
    print(f"False Positives (Safe marked Phishing):  {cm[0][1]:,}  <-- Keep this low!")
    print(f"False Negatives (Phish marked Safe):     {cm[1][0]:,}  <-- Missed attacks!")
    print(f"True Positives (Phish marked Phishing):  {cm[1][1]:,}\n")

    # 5. Inspect Feature Importance (Which features mattered most?)
    importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print("=== TOP 5 MOST IMPORTANT FEATURES ===")
    print(importances.head(5))

    # 6. Export the trained model into backend/model.pkl
    os.makedirs("backend", exist_ok=True)
    model_path = os.path.join("backend", "model.pkl")
    joblib.dump(model, model_path)
    print(f"\n[SUCCESS] Model saved to {model_path}")


if __name__ == "__main__":
    train_and_evaluate()
