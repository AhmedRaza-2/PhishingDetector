import requests
import json

# 🔍 Sample test email payload
sample_payload = {
    "sender": "attacker@phishy.com",
    "receiver": "victim@example.com",
    "subject": "Your account needs immediate verification!",
    "body": "Click this link http://bit.ly/verify-account now to avoid suspension.",
    "urls": [
        "http://bit.ly/verify-account"
    ],
    "attachments": [
        {
            "file_name": "invoice.js",
            "extension": ".js",
            "is_suspicious": True
        }
    ],
    "suspicious_score": 6,
    "contains_high_risk_urls": True
}

# 🌐 Send POST request to the local Flask API
try:
    response = requests.post(
        "http://127.0.0.1:5000/predict",
        json=sample_payload,
        headers={"Content-Type": "application/json"}
    )

    print("Status Code:", response.status_code)
    print("Response JSON:", response.json())

except Exception as e:
    print("❌ Error contacting API:", str(e))
