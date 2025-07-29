import requests

API_URL = "https://phishing-detector-self.vercel.app"

def test_phishing_detector(text):
    payload = {
        "text": text
    }

    try:
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()  # Raises HTTPError if 4xx/5xx
        result = response.json()
        print("== Phishing Detection Result ==")
        print(f"Text      : {text}")
        print(f"Prediction: {result.get('label')}")
        print(f"Confidence: {result.get('confidence', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print("Error contacting API:", e)
    except ValueError:
        print("Invalid JSON response:", response.text)

# Example test cases
sample_inputs = [
    "Please verify your account at http://phishingsite.com to avoid suspension.",
    "Your order has been shipped and will arrive tomorrow.",
    "URGENT! Update your bank credentials now or risk losing access.",
    "Hey, how are you doing today?"
]

for sample in sample_inputs:
    print("\n---")
    test_phishing_detector(sample)
