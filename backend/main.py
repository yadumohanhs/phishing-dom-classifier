import os
import joblib
import pandas as pd
import tldextract
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.extractor import extract_features

# 1. Initialize the FastAPI Application
app = FastAPI(
    title="PhishGuard Real-Time DOM Analyzer API",
    description="Hybrid ML + DOM Heuristic Engine for Zero-Day Phishing Detection",
    version="1.0.0"
)

# 2. Configure CORS (Crucial so the Browser Extension can talk to localhost!)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Allows requests from any website/extension content script
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# 3. Load the trained LightGBM model into RAM once at startup
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run train_model.py first.")

model = joblib.load(MODEL_PATH)


# 4. Define the strict Data Contract (Request & Response Schemas)
class AnalyzeRequest(BaseModel):
    url: str = Field(..., example="http://sbi-kyc-update.top/login.php")
    html: str = Field(..., example="<html><head><title>Login</title></head><body><form action='http://1.2.3.4/post'><input type='password'></form></body></html>")


class AnalyzeResponse(BaseModel):
    url: str
    verdict: str                  # "SAFE", "SUSPICIOUS", or "PHISHING"
    risk_score: float             # 0.0 to 100.0 (Percentage)
    ml_probability: float         # Raw LightGBM score (0.0 to 1.0)
    reasons: list[str]            # Human-readable explanations for the user
    features: dict                # The 14 extracted features


# 5. Live DOM Heuristic Helper (Catches zero-day form hijacking)
def check_dom_heuristics(url: str, html_content: str, features: dict) -> tuple[float, list[str]]:
    """
    Inspects live DOM elements that datasets often miss (like cross-domain form actions)
    and generates human-readable alert reasons.
    """
    reasons = []
    heuristic_boost = 0.0

    ext = tldextract.extract(url)
    soup = BeautifulSoup(html_content, "html.parser")

    # Rule 1: Password field on an unencrypted HTTP page
    if features["HasPasswordField"] == 1 and features["IsHTTPS"] == 0:
        reasons.append("Insecure password input field over unencrypted HTTP")
        heuristic_boost += 0.25

    # Rule 2: Form submits credentials to a completely different external domain or raw IP
    for form in soup.find_all("form"):
        action = form.get("action", "").strip()
        if action.startswith(("http://", "https://")):
            action_ext = tldextract.extract(action)
            if action_ext.domain and action_ext.domain != ext.domain:
                reasons.append(f"Form submits data to an external domain ({action_ext.domain}.{action_ext.suffix})")
                heuristic_boost += 0.35
                break

    # Rule 3: Raw IP address in URL
    if features["IsDomainIP"] == 1:
        reasons.append("Website is hosted on a raw IP address instead of a standard domain")
        heuristic_boost += 0.25

    # Rule 4: High external link ratio (Cloned webpage signature)
    if features["NoOfExternalRef"] > 10:
        reasons.append(f"High number of external links ({features['NoOfExternalRef']}) pointing away from this domain")

    # Rule 5: Abnormally long URL or excessive subdomains
    if features["URLLength"] > 75:
        reasons.append(f"Unusually long URL ({features['URLLength']} characters)")
    if features["NoOfSubDomain"] >= 3:
        reasons.append(f"Suspiciously deep subdomain nesting ({features['NoOfSubDomain']} subdomains)")

    return heuristic_boost, reasons


# 6. The Main Inference Endpoint
@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_webpage(payload: AnalyzeRequest):
    try:
        # Step A: Extract the 14 aligned features
        features = extract_features(payload.url, payload.html)

        # Step B: Convert to 1-row DataFrame and run LightGBM inference
        df_input = pd.DataFrame([features])
        ml_prob = float(model.predict_proba(df_input)[0][1])

        # Step C: Run live DOM heuristic checks for explainability and defense-in-depth
        boost, reasons = check_dom_heuristics(payload.url, payload.html, features)

        # Combine ML probability with heuristic boost (capped at 1.0)
        final_prob = min(1.0, ml_prob + boost)
        risk_percentage = round(final_prob * 100, 2)

        # Step D: Determine 3-Tier Verdict
        if final_prob >= 0.75:
            verdict = "PHISHING"
            if not reasons:
                reasons.append("Structural URL and DOM patterns match known phishing signatures")
        elif final_prob >= 0.40:
            verdict = "SUSPICIOUS"
            if not reasons:
                reasons.append("Page exhibits anomalous URL/DOM ratios")
        else:
            verdict = "SAFE"
            reasons = ["No malicious DOM or lexical indicators detected"]

        return AnalyzeResponse(
            url=payload.url,
            verdict=verdict,
            risk_score=risk_percentage,
            ml_probability=round(ml_prob, 4),
            reasons=reasons,
            features=features
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")


@app.get("/health")
async def health_check():
    return {"status": "online", "model_loaded": True}
