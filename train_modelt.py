import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from scipy.sparse import hstack, csr_matrix
import joblib

# ------------------ Load Dataset ------------------
df = pd.read_json("phishing_data.json", lines=True)
df['label'] = df['label'].astype(int)

# ------------------ Preprocessing ------------------
def preprocess_text(text):
    if isinstance(text, str):
        text = text.lower()
        text = ''.join([c for c in text if c.isalnum() or c == ' '])
        return text
    return ''

df['full_text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
df['cleaned_text'] = df['full_text'].apply(preprocess_text)

# ------------------ TF-IDF Vectorization ------------------
tfidf = TfidfVectorizer(max_features=1000)
X_text = tfidf.fit_transform(df['cleaned_text'])

# ------------------ URL Features ------------------
def extract_url_features(url):
    try:
        parsed = urlparse("http://" + str(url))
        domain = parsed.netloc.lower()
    except:
        domain = ''

    return [
        len(str(url)),  # URL length
        sum(c.isdigit() for c in str(url)),  # Digit count
        sum(str(url).count(c) for c in ['-', '@', '?', '&', '=', '_', '%', '/']),
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', str(url)) else 0,
        len(domain.split('.')[-1]) if '.' in domain else 0
    ]

df['url_features'] = df['urls'].apply(extract_url_features)
X_url = pd.DataFrame(df['url_features'].tolist())

# ------------------ Sender Domain Feature ------------------
def extract_domain(sender):
    try:
        email = re.search(r'<(.+?)>', sender)
        domain = email.group(1).split('@')[-1] if email else ''
        return domain.lower()
    except:
        return ''

df['sender_domain'] = df['sender'].apply(extract_domain)
sender_dummies = pd.get_dummies(df['sender_domain']).astype(int)

# ------------------ Combine All Features ------------------
X_combined = hstack([X_text, csr_matrix(X_url.values), csr_matrix(sender_dummies.values)])
y = df['label']

# ------------------ Train/Test ------------------
X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.2, random_state=42)

# ------------------ Train Model ------------------
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

# ------------------ Evaluation ------------------
print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\n📊 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\n📄 Classification Report:\n", classification_report(y_test, y_pred))

# ------------------ Save Model ------------------
joblib.dump(model, 'phishing_model.joblib')
joblib.dump(tfidf, 'tfidf_vectorizer.joblib')
joblib.dump(sender_dummies.columns.tolist(), 'sender_columns.joblib')
print("\n📦 Model and vectorizer saved successfully.")
