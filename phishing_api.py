from flask import Flask, request, jsonify
import joblib
import re
import pandas as pd
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
import logging
# ------------------ Logging Setup ------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ------------------ Flask App Init ------------------
app = Flask(__name__)

# ------------------ Load Model and Vectorizer ------------------
try:
    logging.info("🔄 Loading model and vectorizer...")
    model = joblib.load("phishing_model.joblib")
    vectorizer = joblib.load("tfidf_vectorizer.joblib")
    sender_columns = joblib.load("sender_columns.joblib")  
    logging.info("✅ Model and vectorizer loaded successfully.")
except Exception as e:
    logging.error("❌ Error loading model/vectorizer: %s", str(e))
    raise e
# ------------------ Helper Functions ------------------
def preprocess_text(text):
    if isinstance(text, str):
        text = text.lower()
        return ''.join([c for c in text if c.isalnum() or c == ' '])
    return ''

def extract_url_features(urls):
    if not urls:
        return [0, 0, 0, 0, 0]
    features = []
    for url in urls:
        try:
            parsed = urlparse("http://" + str(url))
            domain = parsed.netloc.lower()
        except:
            domain = ''
        features.append([
            len(str(url)),
            sum(c.isdigit() for c in str(url)),
            sum(str(url).count(c) for c in ['-', '@', '?', '&', '=', '_', '%', '/']),
            1 if re.search(r'\d+\.\d+\.\d+\.\d+', str(url)) else 0,
            len(domain.split('.')[-1]) if '.' in domain else 0
        ])
    return list(pd.DataFrame(features).mean().values)

def extract_sender_domain(sender):
    try:
        match = re.search(r'<(.+?)>', sender)
        email = match.group(1) if match else sender
        domain = email.split('@')[-1]
        return domain.lower()
    except:
        return ''
# ------------------ Prediction Route ------------------
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        logging.info("📨 Received request for prediction.")

        # Get fields
        subject = data.get("subject", "")
        body = data.get("body", "")
        sender = data.get("sender", "")
        urls = data.get("urls", [])

        # === TF-IDF Text Processing ===
        full_text = f"{subject} {body}"
        cleaned_text = preprocess_text(full_text)
        X_text = vectorizer.transform([cleaned_text])

        # === URL Features ===
        url_feats = extract_url_features(urls)
        X_url = csr_matrix([url_feats])

        # === Sender Domain Dummies ===
        domain = extract_sender_domain(sender)
        sender_vec = [1 if domain == col else 0 for col in sender_columns]
        X_sender = csr_matrix([sender_vec])

        # === Combine Features ===
        X_combined = hstack([X_text, X_url, X_sender])
        logging.info(f"🔎 Combined input shape: {X_combined.shape}")

        # === Predict ===
        prediction = model.predict(X_combined)[0]
        confidence = model.predict_proba(X_combined)[0][1]
        threshold = 0.6  # 👈 you can experiment with 0.6, 0.7, 0.8, etc.
        result = "PHISHING" if confidence >= threshold else "SAFE"

        logging.info(f"✅ Prediction: {result} (Confidence: {confidence:.3f})")
        return jsonify({"result": result, "confidence": round(confidence, 3)})
    except Exception as e:
        logging.error(f"❌ Prediction Error: {str(e)}")
        return jsonify({"error": "Prediction failed"}), 500
# ------------------ Run App ------------------
if __name__ == '__main__':
    logging.info("🚀 Starting phishing detection API server...")
    app.run(port=5000)