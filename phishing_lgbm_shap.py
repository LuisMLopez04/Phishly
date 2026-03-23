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
    # We only rely on these columns; silently ignore extras.
    expected_cols = {"subject", "body", "label"}
    missing = expected_cols.difference(df.columns)
    if missing:
        # Some archive files might not have all fields; skip those that lack core fields.
        raise ValueError(f"{path.name} is missing required columns: {missing}")

    df = df.dropna(subset=["label", "body", "subject"])
    df["label"] = df["label"].astype(int)
    return df[list(expected_cols)]


def load_data() -> pd.DataFrame:
    """
    Load all CSVs in archive/.
    All files must share the key columns used by the model.
    """
    dfs: List[pd.DataFrame] = []
    if ARCHIVE_DIR.exists():
        for csv_path in sorted(ARCHIVE_DIR.glob("*.csv")):
            try:
                dfs.append(_load_single_csv(csv_path))
            except ValueError:
                continue
    if not dfs:
        raise FileNotFoundError(f"No usable CSV files found in {ARCHIVE_DIR}/")
    df_all = pd.concat(dfs, ignore_index=True)
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
    y_pred = (y_proba >= 0.5).astype(int)

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

    # TreeExplainer on the underlying booster
    explainer = shap.TreeExplainer(clf, data=X_bg)
    shap_values = explainer.shap_values(X_row_dense)

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