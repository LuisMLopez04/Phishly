import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import pickle
import shap
import re

class ExplainableLGBMAnalyzer:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            min_df=2,
            sublinear_tf=True
        )
        
        # LightGBM params optimized for text classification
        self.lgbm_params = {
            'objective': 'multiclass',
            'num_class': 3,  # low, medium, high
            'metric': 'multi_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.8,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'verbose': -1,
            'max_depth': 7
        }
        
        self.models = {}
        self.explainers = {}
        
        self.explanation_templates = {
            'urgency': {
                'high': "This message uses extreme time pressure to force hasty decisions.",
                'medium': "This message contains time-sensitive language.",
                'low': "This message doesn't create artificial urgency."
            },
            'fear': {
                'high': "This message uses threats and alarming language to manipulate you.",
                'medium': "This message contains concerning or warning language.",
                'low': "This message doesn't use fear-based tactics."
            },
            'manipulation': {
                'high': "This message exploits emotions (greed/excitement) common in scams.",
                'medium': "This message contains emotionally charged language.",
                'low': "This message appears straightforward without manipulation."
            },
            'formality': {
                'high': "This message uses professional, formal language.",
                'medium': "This message has a neutral tone.",
                'low': "This message uses unprofessional language unusual for legitimate business."
            }
        }
    
    def train(self, emails, labels, validation_split=0.2):
        """
        Train LightGBM models with early stopping
        
        emails: list of email texts
        labels: dict with keys ['urgency', 'fear', 'manipulation', 'formality']
                each value is array of 0 (low), 1 (medium), 2 (high)
        """
        # Vectorize
        X = self.vectorizer.fit_transform(emails)
        
        # Split for validation
        split_idx = int(len(emails) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        
        for sentiment in ['urgency', 'fear', 'manipulation', 'formality']:
            print(f"\n{'='*50}")
            print(f"Training {sentiment.upper()} model...")
            print(f"{'='*50}")
            
            y_train = labels[sentiment][:split_idx]
            y_val = labels[sentiment][split_idx:]
            
            # Create LightGBM datasets
            train_data = lgb.Dataset(X_train, label=y_train)
            val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
            
            # Train with early stopping
            self.models[sentiment] = lgb.train(
                self.lgbm_params,
                train_data,
                num_boost_round=500,
                valid_sets=[train_data, val_data],
                valid_names=['train', 'valid'],
                callbacks=[
                    lgb.early_stopping(stopping_rounds=50),
                    lgb.log_evaluation(period=50)
                ]
            )
            
            # Create SHAP explainer for this model
            # Use TreeExplainer - much faster than KernelExplainer
            self.explainers[sentiment] = shap.TreeExplainer(self.models[sentiment])
            
            # Evaluate
            val_preds = self.models[sentiment].predict(X_val)
            val_pred_classes = np.argmax(val_preds, axis=1)
            accuracy = np.mean(val_pred_classes == y_val)
            print(f"✓ {sentiment} validation accuracy: {accuracy*100:.2f}%")
    
    def predict_with_explanation(self, email_text):
        """
        Predict with SHAP-based explanations
        """
        X = self.vectorizer.transform([email_text])
        
        results = {
            'analyzed_text': email_text[:200] + '...' if len(email_text) > 200 else email_text,
            'sentiments': {},
            'overall_risk': None,
            'key_findings': []
        }
        
        risk_score = 0
        
        for sentiment, model in self.models.items():
            # Get prediction
            probs = model.predict(X)[0]
            prediction = int(np.argmax(probs))
            level = ['low', 'medium', 'high'][prediction]
            confidence = float(probs[prediction])
            
            # Get SHAP explanation
            shap_values = self.explainers[sentiment].shap_values(X)
            explanation = self._generate_shap_explanation(
                email_text, X, shap_values, prediction, sentiment
            )
            
            results['sentiments'][sentiment] = {
                'level': level,
                'confidence': confidence,
                'probabilities': {
                    'low': float(probs[0]),
                    'medium': float(probs[1]),
                    'high': float(probs[2])
                },
                'explanation': self.explanation_templates[sentiment][level],
                'evidence': explanation['evidence'],
                'top_indicators': explanation['top_words'],
                'shap_score': explanation['shap_score']
            }
            
            # Accumulate risk
            if sentiment in ['urgency', 'fear', 'manipulation']:
                risk_score += prediction * confidence
        
        results['overall_risk'] = self._calculate_overall_risk(risk_score)
        results['key_findings'] = self._generate_key_findings(results['sentiments'])
        
        return results
    
    def _generate_shap_explanation(self, text, X, shap_values, prediction, sentiment):
        """
        Convert SHAP values into human-readable explanations
        
        SHAP values tell us exactly how much each word contributed to the prediction
        """
        feature_names = self.vectorizer.get_feature_names_out()
        
        # For multiclass, get SHAP values for the predicted class
        if isinstance(shap_values, list):
            shap_for_class = shap_values[prediction][0]
        else:
            shap_for_class = shap_values[0]
        
        # Get non-zero features (words present in this text)
        word_indices = X.nonzero()[1]
        
        # Build contributions
        contributions = []
        for idx in word_indices:
            word = feature_names[idx]
            shap_value = shap_for_class[idx]
            
            if shap_value > 0:  # Only positive contributions
                contributions.append({
                    'word': word,
                    'impact': float(shap_value),
                    'impact_pct': 0  # Will calculate after sorting
                })
        
        # Sort by impact
        contributions.sort(key=lambda x: x['impact'], reverse=True)
        
        # Calculate percentage impact
        total_impact = sum(c['impact'] for c in contributions)
        if total_impact > 0:
            for c in contributions:
                c['impact_pct'] = (c['impact'] / total_impact) * 100
        
        # Generate evidence with context
        evidence = []
        text_lower = text.lower()
        
        for contrib in contributions[:5]:  # Top 5
            word = contrib['word']
            
            # Find word in context
            pattern = r'(.{0,40})\b' + re.escape(word) + r'\b(.{0,40})'
            match = re.search(pattern, text_lower, re.IGNORECASE)
            
            if match:
                context = match.group(0)
                evidence.append({
                    'indicator': word,
                    'context': f"...{context}...",
                    'reason': self._get_word_reason(word, sentiment),
                    'impact': f"{contrib['impact_pct']:.1f}% of total score",
                    'strength': 'strong' if contrib['impact_pct'] > 15 else 'moderate'
                })
        
        return {
            'top_words': [c['word'] for c in contributions[:3]],
            'evidence': evidence,
            'shap_score': float(sum(c['impact'] for c in contributions))
        }
    
    def _get_word_reason(self, word, sentiment):
        """Explain why a word matters"""
        reasons = {
            'urgency': {
                'urgent': "Creates artificial time pressure",
                'immediately': "Demands instant action",
                'expire': "Implies a deadline to rush decisions",
                'last chance': "Suggests scarcity and urgency",
                'act now': "Classic high-pressure tactic",
                'final notice': "Implies consequences for inaction",
                'limited time': "Creates false scarcity",
                'today': "When combined with threats, creates pressure",
                'within 24': "Short deadline to prevent careful thought"
            },
            'fear': {
                'suspended': "Threatens loss of access",
                'terminated': "Threatens permanent consequences",
                'unauthorized': "Implies security breach to create panic",
                'alert': "Designed to trigger alarm",
                'warning': "Creates sense of danger",
                'locked': "Suggests loss of control",
                'compromised': "Security scare tactic",
                'breach': "Implies serious security issue",
                'unusual activity': "Generic threat to create concern"
            },
            'manipulation': {
                'won': "Appeals to desire for unearned rewards",
                'free': "Too-good-to-be-true offer",
                'congratulations': "Creates false sense of being special",
                'claim': "Pressures action on fake opportunity",
                'prize': "Emotional appeal through greed",
                'refund': "Creates false expectation of money",
                'selected': "Makes you feel specially chosen",
                'exclusive': "Appeals to desire for special treatment",
                'lucky': "Exploits gambling psychology"
            },
            'formality': {
                'hey': "Too casual for business",
                'gonna': "Unprofessional contraction",
                'asap': "Informal abbreviation",
                'btw': "Too casual for legitimate business",
                'dear': "Professional greeting",
                'hereby': "Formal legal language",
                'pursuant': "Formal business language",
                'regards': "Professional closing"
            }
        }
        
        return reasons.get(sentiment, {}).get(
            word, 
            f"Learned pattern associated with {sentiment}"
        )
    
    def _calculate_overall_risk(self, risk_score):
        """Convert risk score to assessment"""
        if risk_score > 4.5:
            level = 'high'
            message = "Multiple strong red flags detected. This message shows hallmarks of phishing or manipulation."
        elif risk_score > 2.5:
            level = 'medium'
            message = "Some concerning signals detected. Verify through official channels before acting."
        else:
            level = 'low'
            message = "Few automated red flags, but always verify unexpected messages independently."
        
        return {
            'level': level,
            'score': float(risk_score),
            'message': message
        }
    
    def _generate_key_findings(self, sentiments):
        """Prioritized list of key findings"""
        findings = []
        
        # Check dangerous combinations
        if (sentiments['urgency']['level'] == 'high' and 
            sentiments['fear']['level'] in ['high', 'medium']):
            findings.append({
                'severity': 'high',
                'finding': "Combines urgency and fear tactics",
                'explanation': "Legitimate organizations rarely combine time pressure with threats. This is a classic phishing pattern.",
                'confidence': min(sentiments['urgency']['confidence'], 
                                sentiments['fear']['confidence'])
            })
        
        if (sentiments['manipulation']['level'] == 'high' and
            sentiments['urgency']['level'] == 'high'):
            findings.append({
                'severity': 'high',
                'finding': "Emotional manipulation with time pressure",
                'explanation': "Combining greed/excitement with urgency prevents rational decision-making.",
                'confidence': sentiments['manipulation']['confidence']
            })
        
        if sentiments['formality']['level'] == 'low':
            findings.append({
                'severity': 'medium',
                'finding': "Unprofessional language",
                'explanation': "Legitimate business communications maintain professional tone.",
                'confidence': sentiments['formality']['confidence']
            })
        
        # Add high-confidence individual findings
        for sentiment, data in sentiments.items():
            if data['level'] == 'high' and data['confidence'] > 0.8:
                if data['evidence']:
                    top = data['evidence'][0]
                    findings.append({
                        'severity': 'medium',
                        'finding': f"Strong {sentiment} signal",
                        'explanation': f"'{top['indicator']}' accounts for {top['impact']} — {top['reason']}",
                        'confidence': data['confidence']
                    })
        
        # Sort by severity and confidence
        findings.sort(key=lambda x: (
            0 if x['severity'] == 'high' else 1,
            -x['confidence']
        ))
        
        return findings[:5]
    
    def get_feature_importance(self, sentiment='urgency', top_n=20):
        """Get overall feature importance from the model"""
        importance = self.models[sentiment].feature_importance(importance_type='gain')
        feature_names = self.vectorizer.get_feature_names_out()
        
        # Sort by importance
        indices = np.argsort(importance)[::-1][:top_n]
        
        return [
            {
                'feature': feature_names[i],
                'importance': float(importance[i])
            }
            for i in indices
        ]
    
    def save(self, path='lgbm_phishing_model.pkl'):
        """Save model and vectorizer"""
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.vectorizer,
                'models': self.models,
                'params': self.lgbm_params
            }, f)
        print(f"✓ Model saved to {path}")
    
    def load(self, path='lgbm_phishing_model.pkl'):
        """Load pre-trained model"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.vectorizer = data['vectorizer']
            self.models = data['models']
            
            # Recreate explainers
            for sentiment, model in self.models.items():
                self.explainers[sentiment] = shap.TreeExplainer(model)
        
        print(f"✓ Model loaded from {path}")