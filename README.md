# Phishly

A phishing detection and education tool that analyzes emails for phishing signals using a combination of AI, API verification, and pattern matching. Available as a Chrome extension that integrates directly with Gmail and Outlook.

---

## How It Works

Phishly analyzes four signal categories and combines them using a weighted evidence scoring engine:

| Signal | Method |
|---|---|
| **Sender** | Abstract Email API (email) / NumVerify (phone) |
| **Links** | Google Safe Browsing API |
| **Content** | Fine-tuned DistilBERT model |
| **User Context** | Checkboxes (unexpected sender, asks to login, etc.) |

Results are scored on a Clean → Critical scale using compounding evidence math — multiple moderate signals escalate the result correctly rather than just taking the worst single signal.

---

## Project Structure

```
Phishly/
├── manifest.json           # Chrome extension config
├── background.js           # Extension service worker
├── content_script.js       # Gmail/Outlook button injection
├── popup.html/css/js       # Extension popup (main UI)
├── resultpage.html/css/js  # Standalone results page
├── config.js               # API keys (not committed — see setup)
├── server.py               # Flask backend (email API, phone API, AI model)
├── phishing_distilbert.py  # DistilBERT training script
├── phishing_lgbm_shap.py   # Data loading utilities
├── phishly-demo-inbox.html # Demo inbox page
├── demo.js                 # Demo inbox script
├── requirements.txt        # Python dependencies
├── archive/                # Training datasets (not committed)
├── model/                  # Trained DistilBERT model (not committed)
└── icons/                  # Extension icons
```

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/phishly.git
cd phishly
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Create your `.env` file

Create a file named `.env` in the root of the project with your API keys:

```
ABSTRACT_EMAIL_API_KEY=your_abstract_api_key_here
NUMVERIFY_API_KEY=your_numverify_key_here
GOOGLE_SAFE_BROWSING_KEY=your_gsb_key_here
```

API keys can be obtained from:
- Abstract Email API: https://www.abstractapi.com/email-verification-api
- NumVerify: https://numverify.com
- Google Safe Browsing: https://developers.google.com/safe-browsing

### 4. Create your `.env` file

Create a file named `.env` in the root of the project:

NUMVERIFY_API_KEY=KEY
ABSTRACT_EMAIL_API_KEY=KEY
GSB_API_KEY=KEY
VIRUSTOTAL_API_KEY=KEY

> ⚠️ Never commit `.env` or `config.js` — both are in `.gitignore`

### 5. Add training datasets

Create an `archive/` folder and add the following CSV files. Each must have `subject`, `body`, and `label` columns (0 = clean, 1 = phishing):

- `Enron.csv`
- `CEAS_08.csv`
- `SpamAssasin.csv`
- `Ling.csv`
- `Nazario.csv`
- `Nigerian_Fraud.csv`

Then prepare the TREC 2007 clean email data:

```bash
python prepare_trec.py --input path/to/trec07p/email_text.csv
```

### 6. Train the AI model

```bash
python phishing_distilbert.py train
```

This will take 30–60 minutes on CPU. The trained model will be saved to `model/`.

### 7. Start the Flask server

```bash
python server.py
```

The server runs on `http://127.0.0.1:5001` and must be running for analysis to work.

### 8. Load the Chrome extension

1. Go to `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `Phishly` folder

---

## Using the Extension

**From Gmail or Outlook:**
1. Open any email
2. Click the **⚑ Flag with Phishly** button that appears in the email header
3. Click the Phishly icon in your Chrome toolbar
4. The popup opens with all fields pre-filled from the email
5. Check any context boxes that apply, then click **Analyze**

**Standalone (without Gmail):**
1. Open `popup.html` directly in Chrome via the extension toolbar
2. Paste email details manually
3. Click **Analyze**

---

## Scoring System

The overall risk is calculated using a blended score of compounding evidence and weighted averages across all provided signals. Missing signals are excluded from the calculation — the score always reflects only what was actually analyzed.

**Hard overrides:**
- Virus Total or Google Safe Browsing hit → always Critical
- Disposable email on a new domain → minimum High
- API-verified clean sender → capped at High maximum

**Risk levels:**
| Score | Level |
|---|---|
| < 0.15 | Clean |
| 0.15 – 0.35 | Low |
| 0.35 – 0.60 | Moderate |
| 0.60 – 0.80 | High |
| > 0.80 | Critical |

---

## AI Model

Phishly uses a fine-tuned **DistilBERT** model trained on a curated dataset of real phishing emails (Nazario, Nigerian Fraud) and legitimate emails (Enron clean, CEAS clean, SpamAssassin clean, TREC 2007). The model understands context and word order — it correctly distinguishes "your statement is ready" (legitimate) from "your account will be suspended" (phishing).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Extension | Chrome Manifest V3 |
| Frontend | HTML, CSS, Vanilla JS |
| Backend | Python, Flask |
| AI Model | DistilBERT (HuggingFace Transformers) |
| Email Verification | Abstract Email API |
| Phone Verification | NumVerify |
| Link Scanning | VirusTotal, Google Safe Browsing v4 |
