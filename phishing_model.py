import argparse  # For command-line argument parsing
from pathlib import Path  # For file path handling
from typing import Dict, List, Tuple  # For type hints
import re  # For regex matching

# Machine learning and data science libraries
import joblib  # For saving/loading models
import numpy as np  # For numerical operations
import pandas as pd  # For data manipulation
from sklearn.compose import ColumnTransformer  # For feature engineering
from sklearn.linear_model import LogisticRegression  # For classification
from sklearn.metrics import classification_report, roc_auc_score  # For evaluation
from sklearn.model_selection import train_test_split  # For splitting data
from sklearn.pipeline import Pipeline  # For chaining preprocessing and model
from sklearn.feature_extraction.text import TfidfVectorizer  # For text features


ARCHIVE_DIR = Path("archive")  # Directory containing CSV files for training
MODEL_FILE = Path("phishing_model.joblib")  # Default path to save/load model

# Theme lexicon to group features into digestible reasons
THEME_LEXICON: Dict[str, List[str]] = {
    "Urgency / time pressure : Uses artificial deadlines to make you act now and think later": [
        "urgent",
        "urgently",
        "immediately",
        "asap",
        "now",
        "today",
        "tonight",
        "final",
        "last chance",
        "act now",
        "expire",
        "expires",
        "expiring",
        "deadline",
        "limited time",
        "limited offer",
        "time sensitive",
        "within",
        "hours",
        "days",
        "24",
        "48",
        "72",
        "action required",
        "act fast",
        "hurry",
        "rush",
        "soon",
        "time running out",
        "ending soon",
    ],
    "Fear / threat : Uses fear to create a sense of panic": [
        "locked",
        "lock",
        "suspended",
        "suspend",
        "disabled",
        "disable",
        "terminated",
        "terminate",
        "unauthorized",
        "unauthorized access",
        "fraud",
        "fraudulent",
        "breach",
        "breached",
        "compromised",
        "compromise",
        "risk",
        "risky",
        "alert",
        "warning",
        "violation",
        "legal",
        "legal action",
        "police",
        "law enforcement",
        "lawsuit",
        "sue",
        "liability",
        "threat",
        "threatened",
        "attack",
        "attacked",
        "hack",
        "hacked",
        "stolen",
        "theft",
        "dangerous",
        "danger",
    ],
    "Account Security: Impersonates real security alerts in order to steal your login credentials": [
        "account",
        "password",
        "passwd",
        "pin",
        "login",
        "log in",
        "log into",
        "sign in",
        "signin",
        "sign into",
        "authentication",
        "authenticate",
        "2fa",
        "two factor",
        "two-factor",
        "mfa",
        "security",
        "secure",
        "update account",
        "confirm identity",
        "reset password",
        "credentials",
        "credential",
        "username",
        "email address",
        "social security",
        "ssn",
        "identity verification",
        "verify identity",
        "user account",
    ],
    "Money / payment: Lures you with fake prizes to steal your financial information": [
        "payment",
        "pay",
        "paid",
        "invoice",
        "billing",
        "bill",
        "bank",
        "banking",
        "wire",
        "wire transfer",
        "transfer",
        "money transfer",
        "refund",
        "charge",
        "charged",
        "billing",
        "credit",
        "credit card",
        "debit",
        "debit card",
        "card",
        "atm",
        "balance",
        "account balance",
        "tax",
        "taxes",
        "irs",
        "prize",
        "prize money",
        "won",
        "winner",
        "gift",
        "bonus",
        "reward",
        "lottery",
        "bitcoin",
        "cryptocurrency",
        "crypto",
        "ethereum",
        "deposit",
        "withdraw",
        "withdrawal",
        "transaction",
    ],
    "Authority / impersonation : Pretends to be a reputable organization to build trust": [
        "microsoft",
        "apple",
        "google",
        "paypal",
        "amazon",
        "irs",
        "fedex",
        "dhl",
        "ups",
        "ebay",
        "facebook",
        "twitter",
        "instagram",
        "netflix",
        "spotify",
        "adobe",
        "adobe account",
        "bank",
        "wells fargo",
        "chase",
        "citibank",
        "support",
        "customer support",
        "helpdesk",
        "help desk",
        "administrator",
        "admin",
        "team",
        "service",
        "service team",
        "official",
        "officially",
        "government",
        "federal",
        "authorized",
        "verified",
        "representative",
        "agent",
    ],
    "Links / click-through : Encourages you to click a link or file that can steal your data or install malware": [
        "http",
        "https",
        "www",
        "com",
        "org",
        "net",
        "click",
        "click here",
        "link",
        "hyperlink",
        "open",
        "download",
        "visit",
        "go to",
        "access",
        "access here",
        "button",
        "start",
        "begin",
        "proceed",
        "continue",
        "submit",
        "confirm",
        "url",
        "address",
        "web",
        "website",
    ],
}


def load_data(archive_dir: Path = ARCHIVE_DIR) -> pd.DataFrame:
    """
    Loads and concatenates all CSV files in the archive directory.
    Only uses 'subject', 'body', and 'label' columns for training.
    Returns a single DataFrame containing all emails.
    """
    dfs: List[pd.DataFrame] = []
    if archive_dir.exists():
        for csv_path in sorted(archive_dir.glob("*.csv")):
            df = pd.read_csv(csv_path)
            expected_cols = {"subject", "body", "label"}
            missing = expected_cols.difference(df.columns)
            if missing:
                continue  # Skip files missing required columns
            df = df.dropna(subset=["label", "body", "subject"])
            df["label"] = df["label"].astype(int)
            dfs.append(df[list(expected_cols)])
    if not dfs:
        raise FileNotFoundError(f"No usable CSV files found in {archive_dir}/")
    return pd.concat(dfs, ignore_index=True)


def build_pipeline() -> Pipeline:
    """
    Constructs the machine learning pipeline for phishing detection.
    Steps:
      1. Text preprocessing: TF-IDF vectorization of the combined subject/body.
      2. Numeric feature: Passes the 'urls' column (number of URLs) directly.
      3. Classification: Logistic Regression for binary classification.
    Returns:
      An sklearn Pipeline object ready for training or prediction.
    """
    # TF-IDF vectorizer for text features
    text_vectorizer = TfidfVectorizer(
        max_features=100000,
        ngram_range=(1, 3),
        stop_words="english",
        lowercase=True,
    )

    # ColumnTransformer combines text and numeric features
    preprocessor = ColumnTransformer(
        transformers=[
            ("text", text_vectorizer, "text"),  # Text feature
            ("urls", "passthrough", ["urls"]),  # Numeric feature
        ]
    )

    # Logistic Regression classifier
    clf = LogisticRegression(
        max_iter=1000,
        n_jobs=-1,
        class_weight="balanced",
    )

    # Pipeline chains preprocessing and classifier
    model = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("clf", clf),
        ]
    )

    return model


def train_model(model_path: Path = MODEL_FILE) -> None:
    """
    Trains the phishing detection model using all CSVs in archive/.
    Steps:
      1. Loads and concatenates all emails.
      2. Combines subject and body into a single text feature.
      3. Sets 'urls' column to 0 (not used, but kept for pipeline compatibility).
      4. Splits data into training and test sets.
      5. Fits the pipeline.
      6. Evaluates performance and prints metrics.
      7. Saves the trained model to disk.
    """
    df = load_data()

    # Combine subject and body into a single text feature
    df["text"] = (df["subject"].fillna("") + " " + df["body"].fillna("")).str.strip()
    # Set urls to 0 (not used)
    df["urls"] = 0

    # Features and labels
    X = df[["text", "urls"]]
    y = df["label"]

    # Split into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build and fit the pipeline
    model = build_pipeline()
    model.fit(X_train, y_train)

    # Evaluate on test set
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= 0.5).astype(int)

    print("=== Evaluation on hold-out set ===")
    print(classification_report(y_test, y_pred, digits=3))
    try:
        auc = roc_auc_score(y_test, y_proba)
        print(f"ROC AUC: {auc:.3f}")
    except Exception:
        pass

    # Save the trained model
    joblib.dump(model, model_path)
    print(f"\nModel saved to {model_path.resolve()}")


def _theme_from_feature(feature_name: str) -> List[str]:
    """
    Map a TF-IDF feature (word/bigram) into 0+ user-facing themes.
    Matches by substring, since TF-IDF features are already normalized to lowercase.
    """
    # Normalize and split feature into tokens for more robust matching
    normalized = feature_name.lower()
    tokens = set(re.split(r"[^a-z0-9]+", normalized))
    tokens.discard("")

    themes: List[str] = []
    for theme, needles in THEME_LEXICON.items():
        for needle in needles:
            n = needle.lower()
            # Match either substring (for phrases) or token match (for single words)
            if (" " in n and n in normalized) or (n in tokens) or (n in normalized):
                themes.append(theme)
                break
    return themes


def _summarize_themes(
    contribs: List[Tuple[str, float]],
    top_examples_per_theme: int = 3,
) -> List[Tuple[str, List[str]]]:
    """
    Aggregate features into themes and return example features per theme.
    Returns list of: (theme, example_features)
    """
    bucket_net: Dict[str, float] = {}
    examples: Dict[str, List[Tuple[str, float]]] = {}

    for feat, val in contribs:
        for theme in _theme_from_feature(str(feat)):
            bucket_net[theme] = bucket_net.get(theme, 0.0) + float(val)
            examples.setdefault(theme, []).append((str(feat), float(val)))

    summarized: List[Tuple[str, float, List[str]]] = []
    for theme, net in bucket_net.items():
        ex = sorted(
            examples.get(theme, []),
            # prefer examples that push toward phishing (positive), then by magnitude
            key=lambda x: (x[1] <= 0, -abs(x[1])),
        )[:top_examples_per_theme]
        # Extract just the feature names (without values)
        feature_names = [f for f, _ in ex]
        summarized.append((theme, float(net), feature_names))

    # Sort by net positive contribution (descending)
    summarized.sort(key=lambda x: -x[1])
    return summarized


def explain_prediction(
    model: Pipeline, text: str, urls_count: int = 0, top_n: int = 200
) -> Tuple[float, List[Tuple[str, float]]]:
    """
    Explains a single prediction by calculating feature contributions.
    Steps:
      1. Builds a DataFrame for the input email (text, urls).
      2. Gets the phishing probability from the model.
      3. Accesses the internal pipeline to get feature contributions.
      4. Calculates the contribution of each feature (coef * value).
      5. Returns top contributing words (positive = phishing, negative = legitimate).
    Returns:
      - phishing_probability
      - list of (term, contribution) sorted by absolute contribution
    """
    # Build a DataFrame for prediction
    row = pd.DataFrame(
        {
            "text": [text],
            "urls": [urls_count],
        }
    )

    # Get predicted probability
    proba = model.predict_proba(row)[0, 1]

    # Access pipeline internals for explanation
    preproc: ColumnTransformer = model.named_steps["preprocess"]
    clf: LogisticRegression = model.named_steps["clf"]

    # Get text vectorizer and vocabulary
    text_vec: TfidfVectorizer = preproc.named_transformers_["text"]

    # Transform input to feature space
    X_trans = preproc.transform(row)

    # For linear models, contribution = coef * value
    if hasattr(X_trans, "toarray"):
        X_dense = X_trans.toarray()[0]
    else:
        X_dense = np.asarray(X_trans)[0]

    coefs = clf.coef_[0]
    # Check shape
    if X_dense.shape[0] != coefs.shape[0]:
        return proba, []

    contributions = X_dense * coefs

    # Map feature index to name
    feature_names_text = np.array(text_vec.get_feature_names_out())
    n_text_features = feature_names_text.shape[0]

    # Text feature contributions
    text_contribs = contributions[:n_text_features]

    # Get top contributing words (both positive and negative)
    top_idx = np.argsort(-np.abs(text_contribs))[:top_n]

    explanations: List[Tuple[str, float]] = []
    for idx in top_idx:
        if text_contribs[idx] != 0:
            explanations.append((feature_names_text[idx], float(text_contribs[idx])))

    # Sort by absolute contribution magnitude
    explanations = sorted(explanations, key=lambda x: -abs(x[1]))[:top_n]

    return proba, explanations


def explain_email(
    model_path: Path,
    subject: str,
    body: str,
    urls_count: int = 0,
    min_theme_share: float = 0.1,
    max_themes: int = 6,
) -> None:
    """
    Loads the trained model and prints the phishing probability and themed reasons.
    Steps:
      1. Loads the model from disk.
      2. Combines subject and body into a single text string.
      3. Calls explain_prediction to get probability and feature contributions.
      4. Groups features into themes with example words.
      5. Prints the overall probability and themed reasons without showing weights.
    """
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model file not found at {model_path.resolve()}. "
            f"Train it first with: python phishing_model.py train"
        )

    model: Pipeline = joblib.load(model_path)

    text = (subject or "").strip() + " " + (body or "").strip()
    text = text.strip()

    proba, contribs = explain_prediction(
        model=model, text=text, urls_count=urls_count, top_n=200
    )

    print(f"Phishing probability: {proba:.1%}")
    print("\nMain Phishing Contributions:")
    
    themes = _summarize_themes(contribs, top_examples_per_theme=3)
    themes_pos = [(t, s, ex) for (t, s, ex) in themes if s > 0]
    
    if not themes_pos:
        print("  (No phishing-related themes found.)")
        return

    total_pos = sum(s for _, s, _ in themes_pos)
    if total_pos <= 0:
        print("  (No positive theme contribution found.)")
        return

    shown = 0
    for theme, score, examples in themes_pos:
        share = score / total_pos
        if share < min_theme_share:
            continue
        print(f"  - {theme}")
        for feat in examples:
            print(f"      • '{feat}'")
        shown += 1
        if shown >= max_themes:
            break

    if shown == 0:
        print(
            f"  (No theme met the 'likely contributor' threshold of {min_theme_share:.0%}.)"
        )


def parse_args() -> argparse.Namespace:
    """
    Parses command-line arguments for training and explaining.
    Provides:
      - train: trains the model and saves it
      - explain: predicts and explains a single email
    """
    parser = argparse.ArgumentParser(
        description="Train and use a phishing detection model based on archive CSVs."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Training command
    train_p = subparsers.add_parser("train", help="Train the model on archive CSVs")
    train_p.add_argument(
        "--model",
        type=str,
        default=str(MODEL_FILE),
        help="Path to save trained model (default: phishing_model.joblib)",
    )

    # Explanation command
    explain_p = subparsers.add_parser(
        "explain", help="Get probability and reasons for a single email"
    )
    explain_p.add_argument("--subject", type=str, required=True, help="Email subject")
    explain_p.add_argument("--body", type=str, required=True, help="Email body text")
    explain_p.add_argument(
        "--urls",
        type=int,
        default=0,
        help="Number of URLs detected in the email (default: 0)",
    )
    explain_p.add_argument(
        "--model",
        type=str,
        default=str(MODEL_FILE),
        help="Path to trained model file (default: phishing_model.joblib)",
    )
    explain_p.add_argument(
        "--min-theme-share",
        type=float,
        default=0.1,
        help="Only show themes that account for at least this share of total positive theme contribution (default 0.1).",
    )
    explain_p.add_argument(
        "--max-themes",
        type=int,
        default=6,
        help="Maximum number of themes to display (default 6).",
    )

    return parser.parse_args()


if __name__ == "__main__":
    # Entry point: runs main script logic
    args = parse_args()

    if args.command == "train":
        train_model(model_path=Path(args.model))
    elif args.command == "explain":
        explain_email(
            model_path=Path(args.model),
            subject=args.subject,
            body=args.body,
            urls_count=args.urls,
            min_theme_share=args.min_theme_share,
            max_themes=args.max_themes,
        )
    else:
        raise ValueError(f"Unknown command: {args.command}")

