"""
phishing_distilbert.py
Trains a DistilBERT-based phishing classifier and saves it to ./model/

Usage:
    python3 phishing_distilbert.py train
    python3 phishing_distilbert.py explain --subject "..." --body "..."
"""

import argparse
import os
import re
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict

import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    get_linear_schedule_with_warmup,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from torch.optim import AdamW


ARCHIVE_DIR  = Path("archive")
MODEL_DIR    = Path("model")
MODEL_DIR.mkdir(exist_ok=True)

SPAM_ONLY_DATASETS = {"Enron.csv", "CEAS_08.csv", "SpamAssasin.csv"}

MAX_LEN      = 256   # token limit per email (DistilBERT max is 512)
BATCH_SIZE   = 16
EPOCHS       = 3
LEARNING_RATE = 2e-5
DEVICE       = torch.device("cpu")  # CPU only — works fine with 32GB RAM


# ─── DATASET ────────────────────────────────────────────────

class EmailDataset(Dataset):
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_len: int):
        self.encodings = tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=max_len,
            return_tensors="pt",
        )
        self.labels = torch.tensor(labels, dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            "input_ids":      self.encodings["input_ids"][idx],
            "attention_mask": self.encodings["attention_mask"][idx],
            "labels":         self.labels[idx],
        }


# ─── DATA LOADING ───────────────────────────────────────────

def _load_single_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    expected = {"subject", "body", "label"}
    if expected.difference(df.columns):
        raise ValueError(f"{path.name} missing columns")
    df = df.dropna(subset=["label", "body", "subject"])
    df["label"] = df["label"].astype(int)
    if path.name in SPAM_ONLY_DATASETS:
        df = df[df["label"] == 0]
    return df[["subject", "body", "label"]]


def _build_consumer_clean_emails() -> pd.DataFrame:
    samples = [
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
        ("Your account summary", "Here is a summary of your account activity for the past 30 days. No unusual activity was detected."),
        ("Your account activity for November", "Here is your account summary for November. Total transactions: 4. No unusual activity was detected."),
        ("Account settings updated", "Your account settings were successfully updated. If you did not make this change please contact us."),
        ("Your account is ready", "Your new account has been created and is ready to use. You can log in at any time."),
        ("Account notification", "This is a notification from your account. Your direct deposit of $1,240.00 has been received."),
        ("Welcome to your account", "Your account has been set up successfully. You can now log in and start using all features."),
        ("Your direct deposit was received", "A direct deposit of $2,150.00 was received and added to your account today."),
        ("Deposit confirmed", "Your deposit of $500.00 has been confirmed and will be available in your account within one business day."),
        ("Password changed successfully", "Your password was successfully updated. If you did not make this change, please contact us immediately."),
        ("Your password has been updated", "This email confirms your password was changed. If this was not you, contact our support team right away."),
        ("Two-factor authentication enabled", "You have successfully enabled two-factor authentication on your account. Your account is now more secure."),
        ("Login from new device", "We noticed a login to your account from a new device. If this was you, no action is needed."),
        ("Your order has shipped", "Good news — your order #4821 has shipped and is on its way. Expected delivery: Thursday."),
        ("Your package was delivered", "Your package was delivered today at 3:42 PM and left at the front door."),
        ("Your delivery is scheduled", "Your delivery is confirmed for Saturday between 9 AM and 1 PM. Someone will need to be home to sign."),
        ("Order confirmation #8823", "Thank you for your order. We have received your order and will send a shipping confirmation shortly."),
        ("Shipping confirmation", "Your order has been shipped via UPS. Your tracking number is 1Z999AA10123456784."),
        ("Out for delivery today", "Your package is out for delivery today. Estimated arrival: between 2 PM and 6 PM."),
        ("Refund processed", "Your refund of $45.99 has been processed and will appear in your account within 5 business days."),
        ("Your bill is ready to view", "Your latest bill is now available online. The amount due this month is shown in your account."),
        ("Your bill for December", "Your December bill is now available. Total amount due: $89.99. Payment is due by December 28."),
        ("Payment received", "We have received your payment of $120.00. Thank you — your account is up to date."),
        ("Subscription payment received", "We received your payment. Thank you — your access continues uninterrupted."),
        ("Invoice #2041 from Acme Co", "Please find your invoice attached. Payment is due within 30 days. Thank you for your business."),
        ("Payment confirmation", "Your payment of $250.00 was successfully processed on November 15. Thank you."),
        ("Automatic payment scheduled", "Your automatic payment of $45.00 is scheduled for November 30. No action is needed."),
        ("Your credit card statement", "Your credit card statement for October is now available. Minimum payment due: $35.00."),
        ("Appointment reminder", "This is a reminder that you have an appointment scheduled for tomorrow at 2:00 PM."),
        ("Your appointment is confirmed", "Your appointment on November 18 at 10:00 AM has been confirmed. Please arrive 10 minutes early."),
        ("Your reservation is confirmed", "Your reservation at The Grand Hotel for November 22-24 is confirmed. Check-in begins at 3:00 PM."),
        ("Booking confirmation", "Your booking is confirmed. Check-in opens 24 hours before departure. Have a great trip!"),
        ("Your subscription renews soon", "Just a heads up — your annual subscription renews in 7 days. No action needed if you would like to continue."),
        ("Subscription renewal confirmation", "Your subscription has been renewed for another year. Your next renewal date is November 1, 2025."),
        ("Your membership has been renewed", "Thank you — your membership has been renewed through December 31, 2025."),
        ("Welcome to your new account", "Thanks for signing up. Your account is ready to use. Feel free to explore at your own pace."),
        ("Receipt for your purchase", "Thank you for your purchase. Your receipt is attached for your records."),
        ("Meeting notes from today", "Hi team, attached are the notes from today's meeting. Let me know if anything needs correction."),
        ("Quarterly report available", "The Q3 report is now available in the shared folder. Please review before Friday's meeting."),
        ("Thanks for contacting support", "We received your message and will get back to you within one business day. Thank you for your patience."),
        ("Your flight is confirmed", "Your flight from Atlanta to New York on November 25 is confirmed. Boarding begins at 6:45 AM."),
        ("Hotel booking confirmed", "Your hotel reservation at Marriott Downtown for 2 nights starting December 1 is confirmed."),
        ("Your timesheet has been approved", "Your timesheet for the week of November 11 has been approved by your manager."),
        ("Payroll processed", "Your payroll for the period ending November 15 has been processed. Your direct deposit will arrive Friday."),
        ("Your expense report was approved", "Your expense report submitted on November 10 has been approved. Reimbursement will be processed this week."),
        ("Your lab results are ready", "Your recent lab results are now available in your patient portal. Log in to review them with your provider."),
        ("New comment on your post", "Someone left a comment on your post. Log in to reply or manage your notifications."),
        ("Your report is ready", "The report you requested has been generated and is ready to download from your account."),
        ("Re: project update", "Thanks for the update. The timeline looks good to me. Let us sync next week to confirm next steps."),
        ("Hi, following up on our call", "It was great speaking with you earlier. As discussed I will send over the proposal by end of week."),
        ("Your download is ready", "The file you requested is ready to download. The link will be available for the next 48 hours."),
        ("Balance update", "Your account balance has been updated. Current balance: $3,412.87. Last transaction: $200.00 deposit."),
        ("Your feedback has been received", "Thank you for your feedback. We take all suggestions seriously and will review your comments."),
        ("Team update", "Hi everyone, just a quick update on the project. We are on track to meet the deadline next Friday."),
    ]
    rows = [{"subject": s, "body": b, "label": 0} for s, b in samples]
    return pd.DataFrame(rows)


def load_data() -> pd.DataFrame:
    dfs = []
    for csv_path in sorted(ARCHIVE_DIR.glob("*.csv")):
        try:
            dfs.append(_load_single_csv(csv_path))
        except ValueError:
            continue
    if not dfs:
        raise FileNotFoundError(f"No CSVs found in {ARCHIVE_DIR}/")

    dfs.append(_build_consumer_clean_emails())
    df_all = pd.concat(dfs, ignore_index=True)

    # Balance: 3x clean per phishing example
    phish_count = (df_all["label"] == 1).sum()
    clean_cap   = phish_count * 3
    clean_df    = df_all[df_all["label"] == 0].sample(
        n=min(clean_cap, (df_all["label"] == 0).sum()), random_state=42
    )
    phish_df = df_all[df_all["label"] == 1]
    df_all = pd.concat([clean_df, phish_df]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Training data: {len(df_all)} rows | "
          f"clean={( df_all['label']==0).sum()} | "
          f"phish={(df_all['label']==1).sum()}")
    return df_all


# ─── TRAINING ───────────────────────────────────────────────

def train():
    print("Loading data...")
    df = load_data()
    texts  = (df["subject"].fillna("") + " [SEP] " + df["body"].fillna("")).tolist()
    labels = df["label"].tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print("Loading DistilBERT tokenizer and model...")
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    model     = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=2
    )
    model.to(DEVICE)

    print("Tokenizing...")
    train_dataset = EmailDataset(X_train, y_train, tokenizer, MAX_LEN)
    test_dataset  = EmailDataset(X_test,  y_test,  tokenizer, MAX_LEN)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader  = DataLoader(test_dataset,  batch_size=BATCH_SIZE)

    optimizer = AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    total_steps = len(train_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=total_steps // 10,
        num_training_steps=total_steps,
    )

    print(f"\nFine-tuning DistilBERT for {EPOCHS} epochs on CPU...")
    print("This will take 30-60 minutes on CPU with 32GB RAM. Please wait.\n")

    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0
        for step, batch in enumerate(train_loader):
            optimizer.zero_grad()
            outputs = model(
                input_ids=batch["input_ids"].to(DEVICE),
                attention_mask=batch["attention_mask"].to(DEVICE),
                labels=batch["labels"].to(DEVICE),
            )
            loss = outputs.loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            total_loss += loss.item()

            if step % 50 == 0:
                print(f"  Epoch {epoch+1}/{EPOCHS} | Step {step}/{len(train_loader)} | Loss: {loss.item():.4f}")

        avg_loss = total_loss / len(train_loader)
        print(f"Epoch {epoch+1} complete. Avg loss: {avg_loss:.4f}\n")

    # Evaluation
    print("Evaluating on hold-out set...")
    model.eval()
    all_preds, all_probs, all_labels = [], [], []

    with torch.no_grad():
        for batch in test_loader:
            outputs = model(
                input_ids=batch["input_ids"].to(DEVICE),
                attention_mask=batch["attention_mask"].to(DEVICE),
            )
            probs = torch.softmax(outputs.logits, dim=1)[:, 1].cpu().numpy()
            preds = (probs >= 0.5).astype(int)
            all_probs.extend(probs)
            all_preds.extend(preds)
            all_labels.extend(batch["labels"].numpy())

    print("\n=== Evaluation on hold-out set ===")
    print(classification_report(all_labels, all_preds, digits=3))
    print(f"ROC AUC: {roc_auc_score(all_labels, all_probs):.3f}")

    # Save model and tokenizer
    print(f"\nSaving model to {MODEL_DIR.resolve()}...")
    model.save_pretrained(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)
    print("Done. Model saved.")


# ─── PREDICTION (for testing from command line) ──────────────

def predict_single(subject: str, body: str) -> float:
    tokenizer = DistilBertTokenizerFast.from_pretrained(str(MODEL_DIR))
    model     = DistilBertForSequenceClassification.from_pretrained(str(MODEL_DIR))
    model.eval()

    text = subject + " [SEP] " + body
    inputs = tokenizer(text, return_tensors="pt", truncation=True,
                       padding=True, max_length=MAX_LEN)
    with torch.no_grad():
        outputs = model(**inputs)
        proba = torch.softmax(outputs.logits, dim=1)[0, 1].item()

    print(f"Phishing probability: {proba:.3f}")
    return proba


# ─── CLI ────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="DistilBERT phishing classifier")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("train", help="Fine-tune DistilBERT and save to ./model/")

    exp = sub.add_parser("explain", help="Predict a single email")
    exp.add_argument("--subject", type=str, required=True)
    exp.add_argument("--body",    type=str, required=True)

    return p.parse_args()


def main():
    args = parse_args()
    if args.command == "train":
        train()
    elif args.command == "explain":
        predict_single(args.subject, args.body)


if __name__ == "__main__":
    main()
