from flask import Flask, render_template, request
import joblib
import numpy as np
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Load trained model
model = joblib.load("phishing_random_forest.pkl")

def extract_features(url):
    features = []

    # IP address
    features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    # URL length
    features.append(len(url))

    # Special characters
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('%'))
    features.append(url.count('='))

    # HTTPS
    features.append(0 if url.startswith("https") else 1)

    # Suspicious keywords
    keywords = ["login", "verify", "secure", "update", "bank", "free"]
    features.append(1 if any(word in url.lower() for word in keywords) else 0)

    # Pad to 49 features
    while len(features) < 49:
        features.append(0)

    return features


@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None

    if request.method == 'POST':
        url = request.form['url']

        features = extract_features(url)
        features = np.array(features).reshape(1, -1)

        result = model.predict(features)[0]
        prob = model.predict_proba(features)[0]
        confidence = round(max(prob) * 100, 2)

        if url.startswith("https://") and confidence < 80:
            prediction = f"Legitimate Website (Confidence: {confidence}%)"
        elif result == 1:
            prediction = f"Phishing Website (Confidence: {confidence}%)"
        else:
            prediction = f"Legitimate Website (Confidence: {confidence}%)"

    return render_template('index.html', prediction=prediction)


if __name__ == '__main__':
    app.run(debug=True)
