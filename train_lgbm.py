# train_lgbm.py

import numpy as np
from phishing_analyzer_lgbm import ExplainableLGBMAnalyzer

# Generate synthetic training data
# In production, replace with real labeled emails
def generate_training_data(n_samples=2000):
    """Generate realistic training data"""
    
    emails = []
    labels = {
        'urgency': [],
        'fear': [],
        'manipulation': [],
        'formality': []
    }
    
    # High urgency + high fear (phishing)
    templates_high_risk = [
        "URGENT: Your account will be suspended immediately unless you verify within 24 hours! Click here now!",
        "FINAL NOTICE: Unusual activity detected. Your account has been locked. Confirm your identity NOW or lose access permanently.",
        "ACTION REQUIRED: Your payment has failed. Update immediately to avoid service termination.",
        "ALERT: Unauthorized login attempt. Click here within 1 hour to secure your account or it will be deleted.",
        "Your account expires TODAY! Verify now or lose all data permanently. Last chance!",
    ]
    
    for _ in range(n_samples // 4):
        email = np.random.choice(templates_high_risk)
        emails.append(email)
        labels['urgency'].append(2)  # high
        labels['fear'].append(2)     # high
        labels['manipulation'].append(np.random.choice([1, 2]))
        labels['formality'].append(np.random.choice([0, 1]))
    
    # High manipulation (prize scams)
    templates_manipulation = [
        "Congratulations! You've won a FREE iPhone 15! Claim your prize now before it expires!",
        "You've been selected for an exclusive offer! Limited time only - get your free gift card today!",
        "WINNER ALERT: You won $5000! Click to claim your refund immediately!",
        "Lucky you! You're our 1000th visitor. Click here for your FREE prize!",
    ]
    
    for _ in range(n_samples // 4):
        email = np.random.choice(templates_manipulation)
        emails.append(email)
        labels['urgency'].append(np.random.choice([1, 2]))
        labels['fear'].append(np.random.choice([0, 1]))
        labels['manipulation'].append(2)  # high
        labels['formality'].append(np.random.choice([0, 1]))
    
    # Legitimate but urgent (medium)
    templates_medium = [
        "Reminder: Your subscription renews in 7 days. Update payment method if needed.",
        "Important: Please review and approve the attached document at your earliest convenience.",
        "Meeting rescheduled to tomorrow at 2pm. Please confirm your availability.",
        "Your order has shipped. Track your package using the link below.",
    ]
    
    for _ in range(n_samples // 4):
        email = np.random.choice(templates_medium)
        emails.append(email)
        labels['urgency'].append(np.random.choice([0, 1]))
        labels['fear'].append(0)  # low
        labels['manipulation'].append(0)  # low
        labels['formality'].append(np.random.choice([1, 2]))
    
    # Legitimate professional (low risk)
    templates_low = [
        "Dear valued customer, thank you for your recent purchase. We appreciate your business.",
        "Please find attached the quarterly report for your review. Let me know if you have questions.",
        "Following up on our conversation last week. Looking forward to hearing from you.",
        "Your invoice is ready. Payment is due within 30 days as per our standard terms.",
    ]
    
    for _ in range(n_samples // 4):
        email = np.random.choice(templates_low)
        emails.append(email)
        labels['urgency'].append(0)  # low
        labels['fear'].append(0)     # low
        labels['manipulation'].append(0)  # low
        labels['formality'].append(2)  # high
    
    return emails, labels

# Train the model
print("Generating training data...")
emails, labels = generate_training_data(n_samples=2000)

print("\nInitializing LightGBM analyzer...")
analyzer = ExplainableLGBMAnalyzer()

print("\nTraining models...")
analyzer.train(emails, labels)

print("\nSaving model...")
analyzer.save('lgbm_phishing_model.pkl')

print("\n" + "="*50)
print("Testing on sample email...")
print("="*50)

test_email = """
URGENT ACTION REQUIRED! Your account has been suspended due to suspicious 
activity. Click here immediately to verify your identity or your account 
will be permanently terminated within 24 hours!
"""

result = analyzer.predict_with_explanation(test_email)

print(f"\nOverall Risk: {result['overall_risk']['level'].upper()}")
print(f"Risk Score: {result['overall_risk']['score']:.2f}")
print(f"\nKey Findings:")
for finding in result['key_findings']:
    print(f"  [{finding['severity'].upper()}] {finding['finding']}")
    print(f"      → {finding['explanation']}")

print("\n✓ Training complete!")