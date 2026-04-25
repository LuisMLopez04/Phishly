import argparse
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
import re
import scipy.sparse as sp
from lightgbm import LGBMClassifier
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV


MODEL_FILE = Path("phishing_lgbm_shap.joblib")
ARCHIVE_DIR = Path("archive")

# Simple user-facing “themes” to group SHAP token contributions into digestible reasons.
# These are intentionally lightweight heuristics; you can expand/tune them over time.
THEME_LEXICON: Dict[str, List[str]] = {
    "Urgency / time pressure": [
        "urgent",
        "immediately",
        "asap",
        "now",
        "today",
        "final",
        "last chance",
        "expire",
        "expires",
        "deadline",
        "limited time",
        "within",
        "hours",
        "24",
        "action required",
    ],
    "Fear / threat": [
        "locked",
        "suspended",
        "disabled",
        "terminated",
        "unauthorized",
        "fraud",
        "breach",
        "compromised",
        "risk",
        "alert",
        "warning",
        "verify",
        "violation",
        "legal",
        "police",
        "lawsuit",
    ],
    "Account / security": [
        "account",
        "password",
        "login",
        "log in",
        "sign in",
        "signin",
        "verify",
        "verification",
        "authenticate",
        "2fa",
        "security",
        "update",
        "confirm",
        "reset",
        "credentials",
    ],
    "Money / payment": [
        "payment",
        "invoice",
        "bank",
        "wire",
        "transfer",
        "refund",
        "charge",
        "billing",
        "credit",
        "debit",
        "card",
        "balance",
        "tax",
        "prize",
        "won",
        "gift",
        "bitcoin",
        "crypto",
    ],
    "Authority / impersonation": [
        "microsoft",
        "apple",
        "google",
        "paypal",
        "amazon",
        "irs",
        "fedex",
        "dhl",
        "ups",
        "support",
        "helpdesk",
        "administrator",
        "admin",
        "team",
        "service",
        "official",
    ],
    "Links / click-through": [
        "http",
        "https",
        "www",
        "click",
        "link",
        "verify here",
        "open",
        "download",
    ],
}


def _load_single_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    expected_cols = {"subject", "body", "label"}
    missing = expected_cols.difference(df.columns)
    if missing:
        raise ValueError(f"{path.name} is missing required columns: {missing}")

    df = df.dropna(subset=["label", "body", "subject"])
    df["label"] = df["label"].astype(int)

    # ── NEW: drop generic spam from datasets where label=1 means spam, not phishing
    SPAM_ONLY_DATASETS = {"Enron.csv", "CEAS_08.csv", "SpamAssasin.csv"}
    if path.name in SPAM_ONLY_DATASETS:
        df = df[df["label"] == 0]  # keep only the clean emails from these datasets
        # These datasets' clean emails are still useful — they're diverse mailing list,
        # corporate, and forum emails that help the model recognize non-phishing content

    return df[list(expected_cols)]

def _build_consumer_clean_emails():
    samples = [
        # --- Account statements ---
        ("Your October statement is ready", "Hi John, your statement for October is now available. Log in to your account at any time to view it."),
        ("Your monthly statement is ready", "Your statement for this month is now available in your account. No action is required."),
        ("November statement available", "Hi Sarah, your November account statement is ready to view. Total balance: $1,204.50."),
        ("Your statement is available online", "Your latest statement is now available. You can view it any time by logging into your account."),
        ("Monthly account statement", "Your monthly statement is now available. Log in to view your full account details and transaction history."),
        ("Your September statement", "Your account statement for September is ready. You can download it as a PDF from your account page."),
        ("Statement ready for download", "Your account statement is ready. Log in to download your statement for the period ending October 31."),
        ("Quarterly statement available", "Your quarterly account statement covering July through September is now available to view online."),
        ("Your bank statement is ready", "Your statement for account ending in 4521 is now available. Log in to view or download it."),
        ("Annual account summary", "Your annual account summary for 2024 is now ready. It includes all transactions from January through December."),
 
        # --- Account notifications (non-suspicious) ---
        ("Your account summary", "Here is a summary of your account activity for the past 30 days. No unusual activity was detected."),
        ("Your account activity for November", "Here is your account summary for November. Total transactions: 4. No unusual activity was detected."),
        ("Account settings updated", "Your account settings were successfully updated. If you did not make this change, please contact us."),
        ("Your account is ready", "Your new account has been created and is ready to use. You can log in at any time."),
        ("Account notification", "This is a notification from your account. Your direct deposit of $1,240.00 has been received."),
        ("Welcome to your account", "Your account has been set up successfully. You can now log in and start using all features."),
        ("Your account has been created", "Welcome! Your account is now active. Take a moment to review your settings and preferences."),
        ("Account update confirmation", "We have updated your account information as requested. Your changes are now saved."),
        ("Your direct deposit was received", "A direct deposit of $2,150.00 was received and added to your account today."),
        ("Deposit confirmed", "Your deposit of $500.00 has been confirmed and will be available in your account within one business day."),
 
        # --- Password / security (legitimate) ---
        ("Password changed successfully", "Your password was successfully updated. If you did not make this change, please contact us immediately."),
        ("Your password has been updated", "This email confirms your password was changed. If this was not you, contact our support team right away."),
        ("Two-factor authentication enabled", "You have successfully enabled two-factor authentication on your account. Your account is now more secure."),
        ("Security settings updated", "Your security settings have been updated as requested. These changes are now active on your account."),
        ("Login from new device", "We noticed a login to your account from a new device. If this was you, no action is needed."),
        ("Your PIN has been updated", "Your account PIN was successfully changed. If you did not request this change, please contact us."),
 
        # --- Orders and shipping ---
        ("Your order has shipped", "Good news — your order #4821 has shipped and is on its way. Expected delivery: Thursday."),
        ("Your package was delivered", "Your package was delivered today at 3:42 PM and left at the front door."),
        ("Your delivery is scheduled", "Your delivery is confirmed for Saturday between 9 AM and 1 PM. Someone will need to be home to sign."),
        ("Order confirmation #8823", "Thank you for your order. We have received your order and will send a shipping confirmation shortly."),
        ("Your order is being prepared", "Great news — your order #7741 is being prepared and will ship within 1-2 business days."),
        ("Shipping confirmation", "Your order has been shipped via UPS. Your tracking number is 1Z999AA10123456784."),
        ("Out for delivery today", "Your package is out for delivery today. Estimated arrival: between 2 PM and 6 PM."),
        ("Delivery attempted", "We attempted to deliver your package today but no one was available. We will try again tomorrow."),
        ("Return confirmation", "We have received your return and are processing your refund. This may take 3-5 business days."),
        ("Refund processed", "Your refund of $45.99 has been processed and will appear in your account within 5 business days."),
 
        # --- Bills and payments ---
        ("Your bill is ready to view", "Your latest bill is now available online. The amount due this month is shown in your account."),
        ("Your bill for December", "Your December bill is now available. Total amount due: $89.99. Payment is due by December 28."),
        ("Payment received", "We have received your payment of $120.00. Thank you — your account is up to date."),
        ("Subscription payment received", "We received your payment. Thank you — your access continues uninterrupted."),
        ("Invoice #2041 from Acme Co", "Please find your invoice attached. Payment is due within 30 days. Thank you for your business."),
        ("Your invoice is ready", "Your invoice for services rendered in October is now available. Total due: $350.00."),
        ("Payment confirmation", "Your payment of $250.00 was successfully processed on November 15. Thank you."),
        ("Automatic payment scheduled", "Your automatic payment of $45.00 is scheduled for November 30. No action is needed."),
        ("Your credit card statement", "Your credit card statement for October is now available. Minimum payment due: $35.00."),
        ("Balance update", "Your account balance has been updated. Current balance: $3,412.87. Last transaction: $200.00 deposit."),
 
        # --- Appointments and reminders ---
        ("Appointment reminder", "This is a reminder that you have an appointment scheduled for tomorrow at 2:00 PM."),
        ("Your appointment is confirmed", "Your appointment on November 18 at 10:00 AM has been confirmed. Please arrive 10 minutes early."),
        ("Reminder: dentist appointment tomorrow", "Just a reminder that your dental appointment is tomorrow at 3:30 PM. Please call if you need to reschedule."),
        ("Meeting reminder", "This is a reminder about your meeting with the project team tomorrow at 9:00 AM in Conference Room B."),
        ("Your reservation is confirmed", "Your reservation at The Grand Hotel for November 22-24 is confirmed. Check-in begins at 3:00 PM."),
        ("Booking confirmation", "Your booking is confirmed. Check-in opens 24 hours before departure. Have a great trip!"),
 
        # --- Subscriptions and renewals ---
        ("Your subscription renews soon", "Just a heads up — your annual subscription renews in 7 days. No action needed if you'd like to continue."),
        ("Subscription renewal confirmation", "Your subscription has been renewed for another year. Your next renewal date is November 1, 2025."),
        ("Your membership has been renewed", "Thank you — your membership has been renewed through December 31, 2025."),
        ("Subscription cancelled", "Your subscription has been cancelled as requested. You will continue to have access until the end of your billing period."),
        ("Free trial ending soon", "Your free trial ends in 3 days. No action is needed if you do not wish to continue."),
 
        # --- General notifications ---
        ("Welcome to your new account", "Thanks for signing up. Your account is ready to use. Feel free to explore at your own pace."),
        ("Receipt for your purchase", "Thank you for your purchase. Your receipt is attached for your records."),
        ("Meeting notes from today", "Hi team, attached are the notes from today's meeting. Let me know if anything needs correction."),
        ("Quarterly report available", "The Q3 report is now available in the shared folder. Please review before Friday's meeting."),
        ("Thanks for contacting support", "We received your message and will get back to you within one business day. Thank you for your patience."),
        ("Hi, following up on our call", "It was great speaking with you earlier. As discussed, I'll send over the proposal by end of week."),
        ("Your feedback has been received", "Thank you for your feedback. We take all suggestions seriously and will review your comments."),
        ("Survey: how did we do?", "We hope your experience was great. If you have a moment, we would appreciate your feedback."),
        ("Your photo upload is complete", "Your photos have been uploaded successfully. You can now view and share them from your account."),
        ("New comment on your post", "Someone left a comment on your post. Log in to reply or manage your notifications."),
        ("Your report is ready", "The report you requested has been generated and is ready to download from your account."),
        ("Team update", "Hi everyone, just a quick update on the project. We are on track to meet the deadline next Friday."),
        ("Re: project update", "Thanks for the update. The timeline looks good to me — let's sync next week to confirm next steps."),
        ("Documents shared with you", "A document has been shared with you. You can view it by logging into your account."),
        ("Your download is ready", "The file you requested is ready to download. The link will be available for the next 48 hours."),
 
        # --- Healthcare ---
        ("Appointment confirmed: Dr. Smith", "Your appointment with Dr. Smith on November 20 at 11:00 AM has been confirmed."),
        ("Your lab results are ready", "Your recent lab results are now available in your patient portal. Log in to review them with your provider."),
        ("Prescription refill reminder", "Your prescription for lisinopril is due for a refill. Contact your pharmacy or doctor to renew it."),
        ("Health insurance card available", "Your new insurance card is available to view and download in your member portal."),
 
        # --- Travel ---
        ("Your flight is confirmed", "Your flight from Atlanta to New York on November 25 is confirmed. Boarding begins at 6:45 AM."),
        ("Hotel booking confirmed", "Your hotel reservation at Marriott Downtown for 2 nights starting December 1 is confirmed."),
        ("Car rental confirmation", "Your car rental reservation for December 1-5 has been confirmed. Pick up is at the airport terminal."),
        ("Your trip itinerary", "Here is your complete trip itinerary for your upcoming travel. All bookings are confirmed."),
 
        # --- Work / professional ---
        ("Your timesheet has been approved", "Your timesheet for the week of November 11 has been approved by your manager."),
        ("Payroll processed", "Your payroll for the period ending November 15 has been processed. Your direct deposit will arrive Friday."),
        ("Benefits enrollment reminder", "Open enrollment for benefits ends November 30. Log in to your HR portal to review your options."),
        ("New company policy update", "Please review the updated company travel policy attached to this email. Changes take effect December 1."),
        ("Your expense report was approved", "Your expense report submitted on November 10 has been approved. Reimbursement will be processed this week."),
    ]
    rows = [{"subject": s, "body": b, "label": 0} for s, b in samples]
    import pandas as pd
    return pd.DataFrame(rows)

def load_data() -> pd.DataFrame:
    dfs: List[pd.DataFrame] = []
    if ARCHIVE_DIR.exists():
        for csv_path in sorted(ARCHIVE_DIR.glob("*.csv")):
            try:
                dfs.append(_load_single_csv(csv_path))
            except ValueError:
                continue
    if not dfs:
        raise FileNotFoundError(f"No usable CSV files found in {ARCHIVE_DIR}/")

    # Add consumer clean emails
    dfs.append(_build_consumer_clean_emails())

    df_all = pd.concat(dfs, ignore_index=True)

    print("=== Dataset composition after filtering ===")
    print(f"Total rows: {len(df_all)}")
    print(f"Clean (0): {(df_all['label']==0).sum()}")
    print(f"Phishing (1): {(df_all['label']==1).sum()}")

    # Balance the dataset — cap clean emails to 3x the phishing count
    phish_count = (df_all["label"] == 1).sum()
    clean_cap = phish_count * 3  # 75% clean / 25% phish target

    clean_df = df_all[df_all["label"] == 0].sample(
        n=min(clean_cap, (df_all["label"] == 0).sum()),
        random_state=42
    )
    phish_df = df_all[df_all["label"] == 1]

    df_all = pd.concat([clean_df, phish_df], ignore_index=True).sample(
        frac=1, random_state=42  # shuffle
    ).reset_index(drop=True)
    return df_all


def build_pipeline(max_features: int = 100_000) -> Pipeline:
    # Only use subject/body text
    text_vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),
        stop_words="english",
        lowercase=True,
        min_df=2,
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("text", text_vectorizer, "text"),
        ],
        sparse_threshold=0.3,
    )

    clf = LGBMClassifier(
        n_estimators=800,
        learning_rate=0.05,
        num_leaves=63,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        class_weight="balanced",
        n_jobs=-1,
    )

    return Pipeline([("preprocess", preprocessor), ("clf", clf)])


def _get_feature_names(preprocess: ColumnTransformer) -> np.ndarray:
    text_vec: TfidfVectorizer = preprocess.named_transformers_["text"]
    text_names = [f"text:{t}" for t in text_vec.get_feature_names_out()]
    return np.asarray(text_names, dtype=object)


def train_model(
    model_path: Path = MODEL_FILE,
    max_samples: int | None = None,
    shap_background_size: int = 256,
) -> None:
    # Load all archive CSVs.
    df = load_data()
    df["text"] = (df["subject"].fillna("") + " " + df["body"].fillna("")).str.strip()

    if max_samples is not None:
        df = df.sample(n=min(max_samples, len(df)), random_state=42)

    X = df[["text"]]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train the base (uncalibrated) model on the training split.
    base_pipeline = build_pipeline()
    base_pipeline.fit(X_train, y_train)

    # Calibrate probabilities (isotonic) on the same training split using CV.
    calibrator = CalibratedClassifierCV(
        estimator=base_pipeline,
        method="isotonic",
        cv=3,
    )
    calibrator.fit(X_train, y_train)

    # Use calibrated probabilities for evaluation.
    y_proba = calibrator.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= 0.65).astype(int)

    print("=== Evaluation on hold-out set ===")
    print(classification_report(y_test, y_pred, digits=3))
    try:
        print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.3f}")
    except Exception:
        pass

    # Build a small background set for SHAP (transformed features)
    preprocess: ColumnTransformer = base_pipeline.named_steps["preprocess"]
    feature_names = _get_feature_names(preprocess)

    bg_df = X_train.sample(
        n=min(shap_background_size, len(X_train)), random_state=42
    ).copy()
    X_bg = preprocess.transform(bg_df)
    if sp.issparse(X_bg):
        X_bg = X_bg.toarray()

    payload: Dict[str, object] = {
        "pipeline": base_pipeline,
        "calibrated": calibrator,
        "feature_names": feature_names,
        "shap_background": X_bg,
    }
    joblib.dump(payload, model_path)
    print(f"\nModel saved to {model_path.resolve()}")


def _predict_proba_and_shap(
    payload: Dict[str, object],
    subject: str,
    body: str,
    top_n: int | None,
) -> Tuple[float, List[Tuple[str, float]]]:
    import shap

    pipeline: Pipeline = payload["pipeline"]  # type: ignore[assignment]
    feature_names: np.ndarray = payload["feature_names"]  # type: ignore[assignment]
    X_bg = payload["shap_background"]  # type: ignore[assignment]

    preprocess: ColumnTransformer = pipeline.named_steps["preprocess"]
    clf: LGBMClassifier = pipeline.named_steps["clf"]

    text = (subject or "").strip() + " " + (body or "").strip()
    row = pd.DataFrame({"text": [text.strip()]})

    # Use calibrated probabilities if available; fall back to the base pipeline.
    calibrated = payload.get("calibrated")
    if calibrated is not None:
        proba = float(calibrated.predict_proba(row)[0, 1])  # type: ignore[call-arg]
    else:
        proba = float(pipeline.predict_proba(row)[0, 1])

    X_row = preprocess.transform(row)
    if sp.issparse(X_row):
        X_row_dense = X_row.toarray()
    else:
        X_row_dense = np.asarray(X_row)

    X_df = pd.DataFrame(X_row_dense, columns=feature_names)

    # TreeExplainer on the underlying booster
    explainer = shap.TreeExplainer(clf, data=X_bg)
    shap_values = explainer.shap_values(X_df)



    # For binary, shap_values can be list [class0, class1] or a single array depending on shap version
    if isinstance(shap_values, list):
        sv = shap_values[1][0]
    else:
        sv = shap_values[0]

    contribs = list(zip(feature_names.tolist(), sv.tolist()))
    contribs.sort(key=lambda x: -abs(x[1]))
    if top_n is None:
        return proba, contribs
    return proba, contribs[:top_n]


def _theme_from_feature(feature_name: str) -> List[str]:
    """
    Map a TF-IDF feature (word/bigram) into 0+ user-facing themes.
    We match by substring, because TF-IDF features are already normalized to lowercase.
    """
    if feature_name == "urls":
        return ["Links / click-through"]

    # Normalize and split feature into tokens for more robust matching.
    # TF-IDF features are lowercase words or bigrams like "account locked".
    normalized = feature_name.lower()
    tokens = set(re.split(r"[^a-z0-9]+", normalized))
    tokens.discard("")

    themes: List[str] = []
    for theme, needles in THEME_LEXICON.items():
        for needle in needles:
            n = needle.lower()
            # Match either substring (for phrases) or token match (for single words / numbers)
            if (" " in n and n in normalized) or (n in tokens) or (n in normalized):
                themes.append(theme)
                break
    return themes


def _summarize_themes(
    contribs: List[Tuple[str, float]],
    top_examples_per_theme: int = 3,
) -> List[Tuple[str, float, List[Tuple[str, float]]]]:
    """
    Aggregate SHAP contributions into themes.
    Returns sorted list of: (theme, net_contrib, example_features)
    """
    bucket_net: Dict[str, float] = {}
    examples: Dict[str, List[Tuple[str, float]]] = {}

    for feat, val in contribs:
        for theme in _theme_from_feature(str(feat)):
            bucket_net[theme] = bucket_net.get(theme, 0.0) + float(val)
            examples.setdefault(theme, []).append((str(feat), float(val)))

    summarized: List[Tuple[str, float, List[Tuple[str, float]]]] = []
    for theme, net in bucket_net.items():
        ex = sorted(
            examples.get(theme, []),
            # prefer examples that push toward phishing (positive), then by magnitude
            key=lambda x: (x[1] <= 0, -abs(x[1])),
        )[:top_examples_per_theme]
        summarized.append((theme, float(net), ex))

    # Sort by net positive contribution (descending)
    summarized.sort(key=lambda x: -x[1])
    return summarized


def explain_email(
    model_path: Path,
    subject: str,
    body: str,
    top_n: int = 15,
    min_theme_share: float = 0.1,
    max_themes: int = 6,
    theme_top_n: int = 200,
) -> None:
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model file not found at {model_path.resolve()}. "
            "Train first: python phishing_lgbm_shap.py train"
        )

    payload: Dict[str, object] = joblib.load(model_path)
    # Use a larger slice of top features for theme aggregation so we don't
    # end up only seeing URL-related tokens.
    proba, contribs_for_themes = _predict_proba_and_shap(
        payload=payload,
        subject=subject,
        body=body,
        top_n=theme_top_n,
    )

    print(f"Phishing probability: {proba:.3f}")
    print("\nMain reasons (grouped into themes):")
    themes = _summarize_themes(contribs_for_themes, top_examples_per_theme=3)
    themes_pos = [(t, s, ex) for (t, s, ex) in themes if s > 0]
    if not themes_pos:
        print("  (No positive themes found among the top contributing features.)")
        return

    total_pos = sum(s for _, s, _ in themes_pos)
    if total_pos <= 0:
        print("  (No positive theme contribution found.)")
        return

    shown = 0
    for theme, score, ex in themes_pos:
        share = score / total_pos
        if share < min_theme_share:
            continue
        print(f"  - {theme} (likely contributor: {share:.0%} of phishing push)")
        for feat, val in ex:
            if val <= 0:
                continue
            print(f"      • '{feat}' pushes toward phishing ({val:+.4f})")
        shown += 1
        if shown >= max_themes:
            break

    if shown == 0:
        print(
            f"  (No theme met the 'likely contributor' threshold of {min_theme_share:.0%}.)"
        )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LightGBM + SHAP phishing classifier")
    sub = p.add_subparsers(dest="command", required=True)

    train_p = sub.add_parser("train", help="Train LightGBM model and save it")
    train_p.add_argument("--model", type=str, default=str(MODEL_FILE))
    train_p.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Cap number of rows used for training (e.g. 200000)",
    )
    train_p.add_argument(
        "--shap-background",
        type=int,
        default=256,
        help="Background sample size for SHAP (default 256)",
    )

    exp_p = sub.add_parser("explain", help="Predict + explain a single email")
    exp_p.add_argument("--subject", type=str, required=True)
    exp_p.add_argument("--body", type=str, required=True)
    exp_p.add_argument("--model", type=str, default=str(MODEL_FILE))
    exp_p.add_argument("--top-n", type=int, default=15)
    exp_p.add_argument(
        "--theme-top-n",
        type=int,
        default=200,
        help="How many top-|SHAP| features to use when aggregating into themes (default 200).",
    )
    exp_p.add_argument(
        "--min-theme-share",
        type=float,
        default=0.1,
        help="Only show themes that account for at least this share of total positive theme contribution (default 0.1).",
    )
    exp_p.add_argument(
        "--max-themes",
        type=int,
        default=6,
        help="Maximum number of themes to display (default 6).",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "train":
        train_model(
            model_path=Path(args.model),
            max_samples=args.max_samples,
            shap_background_size=args.shap_background,
        )
    elif args.command == "explain":
        explain_email(
            model_path=Path(args.model),
            subject=args.subject,
            body=args.body,
            top_n=args.top_n,
            min_theme_share=args.min_theme_share,
            max_themes=args.max_themes,
            theme_top_n=args.theme_top_n,
        )


if __name__ == "__main__":
    main()