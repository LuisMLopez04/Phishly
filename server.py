import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import requests
import os
import uuid
from dotenv import load_dotenv
from pathlib import Path
 
load_dotenv(dotenv_path=Path(__file__).parent / ".env")
 
app = Flask(__name__)
CORS(app)
 
# ─── Load DistilBERT model on startup ────────────────────────
MODEL_DIR = Path("model")
print("Loading DistilBERT model...")
tokenizer = DistilBertTokenizerFast.from_pretrained(str(MODEL_DIR))
model     = DistilBertForSequenceClassification.from_pretrained(str(MODEL_DIR))
model.eval()
print("Model loaded.")
 
MAX_LEN = 256
 
 
# ─── Logging ─────────────────────────────────────────────────
 
@app.before_request
def log_request():
    print("➡️ REQUEST ID:", uuid.uuid4(), request.path)
 
 
# ─── Email verification ───────────────────────────────────────
 
@app.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json()
    email_address = data.get("email")
    api_key = os.getenv("ABSTRACT_EMAIL_API_KEY")
 
    url = "https://emailreputation.abstractapi.com/v1/"
    headers = {"Authorization": f"Bearer {api_key}"}
    params  = {"email": email_address}
 
    try:
        response = requests.get(url, headers=headers, params=params)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 
# ─── Phone verification ───────────────────────────────────────
 
@app.route("/verify-phone", methods=["POST"])
def verify_phone():
    data  = request.get_json()
    phone = data.get("number")
    api_key = os.getenv("NUMVERIFY_API_KEY")
 
    url    = "http://apilayer.net/api/validate"
    params = {"access_key": api_key, "number": phone}
 
    try:
        response = requests.get(url, params=params)
        print("STATUS:", response.status_code)
        print("RESPONSE:", response.text)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ─── VirusTotal Safe Browsing ─────────────────────────────────

@app.route("/check-url-vt", methods=["POST"])
def check_url_vt():
    data = request.get_json()
    links = data.get("links", [])
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return jsonify({"error": "Missing VT API key", "fallback": True})

    results = []
    headers = {"x-apikey": api_key}
    
    for link in links:
        # VirusTotal v3 requires a base64 encoded URL without padding
        url_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        try:
            resp = requests.get(endpoint, headers=headers)
            
            if resp.status_code == 200:
                vt_data = resp.json()
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                if malicious > 0 or suspicious > 0:
                    results.append({
                        "url": link,
                        "malicious": malicious,
                        "suspicious": suspicious
                    })
            elif resp.status_code in [401, 403, 429]:
                print(f"VT API Error or Rate Limit: {resp.status_code}")
                return jsonify({"error": "API limit or unauthorized", "fallback": True})
            elif resp.status_code == 404:
                continue
                
        except Exception as e:
            print(f"VT Error for {link}: {e}")
            return jsonify({"error": str(e), "fallback": True})
            
    return jsonify({"matches": results, "fallback": False})


# ─── Google Safe Browsing ─────────────────────────────────────

@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json()
    links = data.get("links", [])  
    api_key = os.getenv("GSB_API_KEY")

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": { "clientId": "phishly", "clientVersion": "1.0.0" },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": l} for l in links]  
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        result = response.json()
        return jsonify({"unsafe": bool(result.get("matches")), "matches": result.get("matches", [])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 
# ─── Phishing prediction ──────────────────────────────────────


 
@app.route("/predict", methods=["POST"])
def predict():
    body_data = request.get_json()
    subject   = body_data.get("subject", "") or ""
    body      = body_data.get("body", "")    or ""
 
    text = (subject + " [SEP] " + body).strip()
 
    # Return 0 if there's not enough content to analyze
    if len(text.split()) < 3 or len(text) < 10:
        return jsonify({
            "probability": 0.0,
            "themes": [],
            "status": "insufficient_data"
        })
 
    # Tokenize and predict
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=MAX_LEN,
    )
 
    with torch.no_grad():
        outputs = model(**inputs)
        proba = torch.softmax(outputs.logits, dim=1)[0, 1].item()
 
    print(f"🔍 RAW PROBABILITY: {proba:.4f} | subject: {subject[:60]}")
 
    return jsonify({
        "probability": round(proba, 3),
        "themes": []   # themes removed — DistilBERT doesn't use SHAP
    })
 
 
if __name__ == "__main__":
    app.run(port=5001, debug=False)