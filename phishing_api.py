from flask import Flask, request, jsonify
import joblib
import re
import pandas as pd
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
import logging
import json

app = Flask(__name__)

# Load model and vectorizer
model = joblib.load("phishing_model.joblib")
vectorizer = joblib.load("tfidf_vectorizer.joblib")
sender_columns = joblib.load("sender_columns.joblib")

# Helpers
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

def score_attachments(attachments):
    suspicious_exts = {".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".ps1", ".wsf", ".jar", ".com", ".docm", ".xlsm"}
    score = 0
    for att in attachments:
        if att.get("extension", "").lower() in suspicious_exts:
            score += 1
    return score
def log_prediction(data, prediction):
    try:
        log_data = {
            "sender": data.get("sender", ""),
            "receiver": data.get("receiver", ""),
            "subject": data.get("subject", ""),
            "body": data.get("body", "")[:100],
            "label": 1 if prediction == "PHISHING" else 0,
            "urls": 1 if data.get("urls") else 0,
        }

        with open("all_predictions_log.json", "a", encoding="utf-8") as f:
            f.write(json.dumps(log_data) + "\n")

        logging.info("📥 Email logged successfully.")
    except Exception as e:
        logging.warning("⚠️ Failed to log prediction: %s", str(e))

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        subject = data.get("subject", "")
        body = data.get("body", "")
        sender = data.get("sender", "")
        urls = data.get("urls", [])
        attachments = data.get("attachments", [])

        cleaned_text = preprocess_text(f"{subject} {body}")
        X_text = vectorizer.transform([cleaned_text])

        url_feats = extract_url_features(urls)
        X_url = csr_matrix([url_feats])

        domain = extract_sender_domain(sender)
        X_sender = csr_matrix([[1 if domain == col else 0 for col in sender_columns]])

        X_combined = hstack([X_text, X_url, X_sender])

        prediction = model.predict(X_combined)[0]
        confidence = model.predict_proba(X_combined)[0][1]

        result = "PHISHING" if confidence >= 0.6 else "SAFE"
        # Save every prediction (safe or phishing)
        log_prediction(data, result)
        url_score = sum([1 for url in urls if "@" in url or len(url) > 150])
        attachment_score = score_attachments(attachments)

        return jsonify({
            "result": result,
            "confidence": round(confidence, 3),
            "url_score": url_score,
            "attachment_score": attachment_score
        })

    except Exception as e:
        logging.error("Prediction failed: %s", str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000)
