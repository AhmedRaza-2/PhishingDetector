import json
import os
import random
from hashlib import sha256

# File paths
main_file = "phishing_data.json"
predictions_file = "all_predictions_log.json"

def load_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line.strip()) for line in f if line.strip()]

def save_jsonl(path, data):
    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")

def get_hash(email):
    """Create unique hash based on sender, subject, body"""
    content = f"{email.get('sender', '')}|{email.get('subject', '')}|{email.get('body', '')}"
    return sha256(content.encode('utf-8')).hexdigest()

# Load datasets
main_data = load_jsonl(main_file)
all_predictions = load_jsonl(predictions_file)

# Get existing hashes to avoid duplicates
existing_hashes = {get_hash(email) for email in main_data}

# Remove duplicates
filtered_preds = [email for email in all_predictions if get_hash(email) not in existing_hashes]

# Split by label
phishing_emails = [email for email in filtered_preds if email.get("label") == 1]
safe_emails = [email for email in filtered_preds if email.get("label") == 0]

# Determine how many safe to add (equal to phishing count)
num_to_add = len(phishing_emails)
safe_to_add = safe_emails[:num_to_add]
balanced_data = phishing_emails + safe_to_add
random.shuffle(balanced_data)

# Update main dataset
updated_main = main_data + balanced_data
save_jsonl(main_file, updated_main)

# Remove added entries from allpredictions.json
used_hashes = {get_hash(email) for email in balanced_data}
remaining_preds = [email for email in all_predictions if get_hash(email) not in used_hashes]
save_jsonl(predictions_file, remaining_preds)

print(f"[✅] Added {len(phishing_emails)} phishing + {len(safe_to_add)} safe emails to main dataset.")
