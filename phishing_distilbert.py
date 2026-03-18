"""
DistilBERT-based phishing classifier. Train on Data.csv and run inference with
optional token-level explanations (attention to [CLS]).
"""
import argparse
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import classification_report, roc_auc_score
from torch.utils.data import Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    EvalPrediction,
)


DATA_FILE = Path("Data.csv")
MODEL_DIR = Path("distilbert_phishing")
DEFAULT_MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 512


def load_data(
    csv_path: Path = DATA_FILE,
    max_samples: Optional[int] = None,
) -> pd.DataFrame:
    """Load dataset; optionally limit rows for faster training."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Could not find data file at {csv_path.resolve()}")

    df = pd.read_csv(csv_path)
    expected = {"sender", "receiver", "date", "subject", "body", "label", "urls"}
    missing = expected.difference(df.columns)
    if missing:
        raise ValueError(f"Missing expected columns: {missing}")

    df = df.dropna(subset=["label", "body", "subject"])
    df["label"] = df["label"].astype(int)

    if max_samples is not None:
        df = df.sample(n=min(max_samples, len(df)), random_state=42)
    return df


class PhishingDataset(Dataset):
    """PyTorch Dataset: (subject + body) -> tokenized input for DistilBERT."""

    def __init__(
        self,
        texts: List[str],
        labels: List[int],
        tokenizer,
        max_length: int = MAX_LENGTH,
    ):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int):
        text = self.texts[idx]
        if not isinstance(text, str):
            text = str(text) if text else ""
        enc = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


def compute_metrics(p: EvalPrediction) -> dict:
    logits = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
    preds = np.argmax(logits, axis=1)
    # logits -> softmax for AUC
    exp_logits = np.exp(logits - logits.max(axis=1, keepdims=True))
    probs = (exp_logits / exp_logits.sum(axis=1, keepdims=True))[:, 1]
    acc = (preds == p.label_ids).mean()
    try:
        auc = roc_auc_score(p.label_ids, probs)
    except Exception:
        auc = 0.0
    return {"accuracy": float(acc), "roc_auc": float(auc)}


def train_model(
    csv_path: Path = DATA_FILE,
    model_dir: Path = MODEL_DIR,
    model_name: str = DEFAULT_MODEL_NAME,
    max_samples: Optional[int] = None,
    train_batch_size: int = 16,
    eval_batch_size: int = 32,
    num_epochs: int = 2,
    learning_rate: float = 2e-5,
    val_ratio: float = 0.1,
) -> None:
    df = load_data(csv_path, max_samples=max_samples)
    df["text"] = (df["subject"].fillna("") + " " + df["body"].fillna("")).str.strip()
    texts = df["text"].tolist()
    labels = df["label"].tolist()

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    # Stratified split
    n = len(texts)
    indices = np.arange(n)
    np.random.seed(42)
    np.random.shuffle(indices)
    n_val = int(n * val_ratio)
    val_idx = set(indices[:n_val])
    train_texts = [texts[i] for i in indices[n_val:]]
    train_labels = [labels[i] for i in indices[n_val:]]
    val_texts = [texts[i] for i in indices[:n_val]]
    val_labels = [labels[i] for i in indices[:n_val]]

    train_ds = PhishingDataset(train_texts, train_labels, tokenizer)
    val_ds = PhishingDataset(val_texts, val_labels, tokenizer)

    num_training_steps = (len(train_ds) // train_batch_size) * num_epochs
    warmup_steps = max(1, int(0.1 * num_training_steps))

    training_args = TrainingArguments(
        output_dir=str(model_dir / "runs"),
        num_train_epochs=num_epochs,
        per_device_train_batch_size=train_batch_size,
        per_device_eval_batch_size=eval_batch_size,
        learning_rate=learning_rate,
        warmup_steps=warmup_steps,
        weight_decay=0.01,
        logging_steps=100,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="roc_auc",
        greater_is_better=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    trainer.save_model(str(model_dir))
    tokenizer.save_pretrained(str(model_dir))

    # Final eval and classification report
    out = trainer.predict(val_ds)
    preds = np.argmax(out.predictions, axis=1)
    probs = out.predictions[:, 1]
    print("\n=== Evaluation on validation set ===")
    print(classification_report(val_labels, preds, digits=3))
    print(f"ROC AUC: {roc_auc_score(val_labels, probs):.3f}")
    print(f"\nModel and tokenizer saved to {model_dir.resolve()}")


def predict_and_explain(
    model_dir: Path,
    subject: str,
    body: str,
    top_k_tokens: int = 15,
) -> Tuple[float, List[Tuple[str, float]]]:
    """
    Return (phishing_probability, list of (token, attention_weight) for explanation).
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
    # Use eager attention so output_attentions=True returns weights (SDPA doesn't)
    try:
        model = AutoModelForSequenceClassification.from_pretrained(
            str(model_dir), attn_implementation="eager"
        )
    except TypeError:
        model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
    model.to(device)
    model.eval()

    text = (subject or "").strip() + " " + (body or "").strip()
    text = text.strip() or " "
    enc = tokenizer(
        text,
        truncation=True,
        max_length=MAX_LENGTH,
        padding="max_length",
        return_tensors="pt",
    )
    input_ids = enc["input_ids"].to(device)
    attention_mask = enc["attention_mask"].to(device)

    with torch.no_grad():
        out = model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_attentions=True,
        )
    logits = out.logits
    probs = torch.softmax(logits, dim=-1)
    phishing_prob = probs[0, 1].item()

    token_weights: List[Tuple[str, float]] = []
    if out.attentions and len(out.attentions) > 0:
        # Explanation: last layer attention to [CLS] (index 0)
        last_attn = out.attentions[-1][0]  # (heads, seq, seq)
        attn_to_cls = last_attn[:, 0, :].mean(dim=0).cpu().numpy()  # (seq,)
        tokens = tokenizer.convert_ids_to_tokens(input_ids[0].cpu().tolist())
        for tok, w in zip(tokens, attn_to_cls):
            if tok in ("[CLS]", "[SEP]", "[PAD]") or not tok.strip():
                continue
            token_weights.append((tok, float(w)))
        token_weights.sort(key=lambda x: -x[1])
        token_weights = token_weights[:top_k_tokens]

    return phishing_prob, token_weights


def explain_email(
    model_dir: Path = MODEL_DIR,
    subject: str = "",
    body: str = "",
    top_k: int = 15,
) -> None:
    if not model_dir.exists():
        raise FileNotFoundError(
            f"Model dir not found at {model_dir.resolve()}. "
            "Train first: python phishing_distilbert.py train"
        )
    prob, token_weights = predict_and_explain(model_dir, subject, body, top_k_tokens=top_k)
    print(f"Phishing probability: {prob:.3f}")
    print("\nReasons (tokens the model attended to most when deciding):")
    if not token_weights:
        print("  (Token-level explanation not available.)")
    for tok, w in token_weights:
        print(f"  '{tok}': attention weight {w:.4f}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DistilBERT phishing classifier")
    sub = p.add_subparsers(dest="command", required=True)

    train_p = sub.add_parser("train", help="Train DistilBERT on Data.csv")
    train_p.add_argument("--data", type=str, default=str(DATA_FILE))
    train_p.add_argument("--model-dir", type=str, default=str(MODEL_DIR))
    train_p.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME)
    train_p.add_argument("--max-samples", type=int, default=None, help="Cap training size (e.g. 100000)")
    train_p.add_argument("--batch-size", type=int, default=16)
    train_p.add_argument("--epochs", type=int, default=2)
    train_p.add_argument("--lr", type=float, default=2e-5)
    train_p.add_argument("--val-ratio", type=float, default=0.1)

    explain_p = sub.add_parser("explain", help="Get probability and token-level explanation")
    explain_p.add_argument("--subject", type=str, required=True)
    explain_p.add_argument("--body", type=str, required=True)
    explain_p.add_argument("--model-dir", type=str, default=str(MODEL_DIR))
    explain_p.add_argument("--top-k", type=int, default=15)

    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "train":
        train_model(
            csv_path=Path(args.data),
            model_dir=Path(args.model_dir),
            model_name=args.model_name,
            max_samples=args.max_samples,
            train_batch_size=args.batch_size,
            num_epochs=args.epochs,
            learning_rate=args.lr,
            val_ratio=args.val_ratio,
        )
    elif args.command == "explain":
        explain_email(
            model_dir=Path(args.model_dir),
            subject=args.subject,
            body=args.body,
            top_k=args.top_k,
        )
    else:
        raise ValueError(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
