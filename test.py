import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud

# Load your cleaned dataset
df = pd.read_json("phishing_data.json", lines=True)

# Set Seaborn style
sns.set(style="whitegrid")

# 1. Label Distribution
plt.figure(figsize=(6, 4))
sns.countplot(x='label', data=df, palette='Set2')
plt.title("Phishing (1) vs Safe (0) Email Count")
plt.xlabel("Label")
plt.ylabel("Count")
plt.tight_layout()
plt.show()

# 2. URL Presence Distribution
plt.figure(figsize=(6, 4))
sns.countplot(x='urls', data=df, palette='Set1')
plt.title("Emails with URLs (1) vs No URLs (0)")
plt.xlabel("URLs Present")
plt.ylabel("Count")
plt.tight_layout()
plt.show()

# 3. Label vs URL Presence
plt.figure(figsize=(6, 4))
sns.countplot(x='urls', hue='label', data=df, palette='pastel')
plt.title("Label Distribution by URL Presence")
plt.xlabel("URLs Present")
plt.ylabel("Count")
plt.legend(title='Label', labels=['Safe', 'Phishing'])
plt.tight_layout()
plt.show()

# 4. Word Cloud for Phishing Emails
phishing_text = " ".join(df[df['label'] == 1]['body'].dropna().astype(str))
wordcloud = WordCloud(width=800, height=400, background_color='white').generate(phishing_text)
plt.figure(figsize=(10, 5))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.title("Word Cloud of Phishing Email Bodies")
plt.tight_layout()
plt.show()

# 5. Word Cloud for Safe Emails
safe_text = " ".join(df[df['label'] == 0]['body'].dropna().astype(str))
wordcloud_safe = WordCloud(width=800, height=400, background_color='white').generate(safe_text)
plt.figure(figsize=(10, 5))
plt.imshow(wordcloud_safe, interpolation='bilinear')
plt.axis("off")
plt.title("Word Cloud of Safe Email Bodies")
plt.tight_layout()
plt.show()
