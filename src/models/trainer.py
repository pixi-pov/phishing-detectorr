"""
Phishing Detection Model Trainer
Trains Random Forest classifier on URL features
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features.extractor import URLFeatureExtractor


class FastFeatureExtractor(URLFeatureExtractor):
    """Feature extractor without slow network calls"""
    
    def extract_all_features(self, url):
        """Extract features without network checks"""
        features = {}
        
        # Basic URL parsing
        from urllib.parse import urlparse
        parsed = urlparse(url)
        ext = __import__('tldextract').extract(url)
        
        # Build domain
        full_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        
        # 1. URL Length Features
        features['url_length'] = len(url)
        features['hostname_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        
        # 2. Count Features
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['at_count'] = url.count('@')
        features['and_count'] = url.count('&')
        features['exclamation_count'] = url.count('!')
        features['space_count'] = url.count(' ') + url.count('%20')
        features['tilde_count'] = url.count('~')
        features['comma_count'] = url.count(',')
        features['plus_count'] = url.count('+')
        features['asterisk_count'] = url.count('*')
        features['hash_count'] = url.count('#')
        features['dollar_count'] = url.count('$')
        features['percent_count'] = url.count('%')
        
        # 3. Binary Features
        features['has_ip_address'] = self._has_ip_address(url)
        features['has_suspicious_words'] = self._has_suspicious_words(url)
        features['is_shortened'] = self._is_shortened(url)
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_brand_name'] = self._has_brand_name(url)
        features['has_multiple_subdomains'] = self._has_multiple_subdomains(ext)
        features['has_suspicious_tld'] = self._has_suspicious_tld(ext)
        
        # 4. Domain Features
        features['domain_in_ip_format'] = self._domain_in_ip_format(parsed.netloc)
        features['is_localhost'] = 1 if 'localhost' in parsed.netloc else 0
        features['suspicious_keyword_count'] = self._count_suspicious_keywords(url)
        
        # 5. Advanced Features
        features['url_entropy'] = self._calculate_entropy(url)
        features['digit_ratio'] = self._digit_ratio(url)
        features['letter_ratio'] = self._letter_ratio(url)
        features['domain_token_count'] = len(ext.domain)
        features['path_token_count'] = len(parsed.path.split('/'))
        
        # 6. SKIP slow network checks - set defaults
        features['domain_age_days'] = -1
        features['has_dns_record'] = -1
        features['has_ssl'] = -1
        
        return features


class PhishingModelTrainer:
    def __init__(self):
        self.model = None
        self.extractor = FastFeatureExtractor()
        self.feature_names = None
        
    def create_sample_dataset(self):
        """Create sample dataset quickly without network delays"""
        print("Creating sample dataset...")
        
        legitimate_urls = [
            "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
            "https://www.amazon.com", "https://www.wikipedia.org", "https://www.twitter.com",
            "https://www.linkedin.com", "https://www.github.com", "https://www.stackoverflow.com",
            "https://www.reddit.com", "https://www.apple.com", "https://www.microsoft.com",
            "https://www.netflix.com", "https://www.spotify.com", "https://www.adobe.com",
            "https://www.dropbox.com", "https://www.salesforce.com", "https://www.shopify.com",
            "https://www.wordpress.com", "https://www.medium.com", "https://www.nytimes.com",
            "https://www.bbc.com", "https://www.cnn.com", "https://www.weather.com",
            "https://www.espn.com", "https://www.twitch.tv", "https://www.pinterest.com",
            "https://www.quora.com", "https://www.zoom.us", "https://www.slack.com"
        ]
        
        phishing_urls = [
            "http://192.168.1.1/login.php", "https://paypa1-secure.verify-account.tk/login",
            "http://faceb00k-login.verify.net", "https://amaz0n-security.update-info.ml",
            "http://bankofamerica-login.com.verify-session.xyz", "https://google-drive.share-document.tk",
            "http://apple-id.verify-account.ga", "https://netflix-billing.update-payment.cf",
            "http://microsoft-verify.login-secure.top", "https://chase-online.banking-verify.work",
            "http://verify-paypal.account-limited.date", "https://secure-login.facebook-verify.xyz",
            "http://amazon-gift.winner-claim.ml", "https://update-banking.wellsfargo-verify.tk",
            "http://confirm-identity.irs-gov.verify.ga", "https://secure-login.apple-id.verify.top",
            "http://verify-account.microsoft-update.cf", "https://login-verify.netflix-billing.xyz",
            "http://security-alert.bankofamerica.verify.work", "https://document-share.google-drive.view.date",
            "http://limited-account.paypal-verify.tk", "https://update-info.amazon-security.ml",
            "http://verify-session.chase-online.ga", "https://winner-claim.google-prize.top",
            "http://login-secure.facebook-confirm.cf", "https://account-verify.apple-login.ml",
            "http://billing-update.netflix-secure.tk", "https://signin-verify.microsoft-update.ga",
            "http://alert-paypal.account-verify.xyz", "https://login-confirm.amazon-security.top"
        ]
        
        data = []
        print("Extracting features for legitimate URLs...")
        for url in legitimate_urls:
            features = self.extractor.extract_all_features(url)
            features['label'] = 0
            data.append(features)
            
        print("Extracting features for phishing URLs...")
        for url in phishing_urls:
            features = self.extractor.extract_all_features(url)
            features['label'] = 1
            data.append(features)
        
        return pd.DataFrame(data)
    
    def train_model(self, df=None, test_size=0.2):
        """Train the Random Forest model"""
        if df is None:
            df = self.create_sample_dataset()
        
        X = df.drop('label', axis=1)
        y = df['label']
        self.feature_names = X.columns.tolist()
        
        print(f"\nDataset: {X.shape[0]} samples, {X.shape[1]} features")
        print(f"Legitimate: {(y==0).sum()}, Phishing: {(y==1).sum()}")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print("Training Random Forest...")
        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=10, min_samples_split=5,
            min_samples_leaf=2, random_state=42, n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_acc = accuracy_score(y_train, self.model.predict(X_train))
        test_acc = accuracy_score(y_test, self.model.predict(X_test))
        
        print(f"\n✅ Training Accuracy: {train_acc:.2%}")
        print(f"✅ Testing Accuracy: {test_acc:.2%}")
        
        # Feature importance
        importances = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 5 Important Features:")
        for idx, row in importances.head(5).iterrows():
            print(f"  {row['feature']}: {row['importance']:.3f}")
        
        return self.model
    
    def save_model(self, filepath='models/phishing_model.pkl'):
        """Save trained model"""
        if self.model is None:
            raise ValueError("No model trained!")
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({'model': self.model, 'feature_names': self.feature_names}, filepath)
        print(f"\n💾 Model saved: {filepath}")
    
    def load_model(self, filepath='models/phishing_model.pkl'):
        """Load model"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.feature_names = data['feature_names']
        return self.model


class PhishingDetector:
    """Real-time detector"""
    
    def __init__(self, model_path='models/phishing_model.pkl'):
        self.trainer = PhishingModelTrainer()
        
        if os.path.exists(model_path):
            self.trainer.load_model(model_path)
            print("✅ Loaded existing model")
        else:
            print("🚀 Training new model...")
            self.trainer.train_model()
            self.trainer.save_model(model_path)
        
        self.model = self.trainer.model
        self.feature_names = self.trainer.feature_names
        # Use full extractor for predictions (with network checks)
        self.extractor = URLFeatureExtractor()
    
    def predict(self, url):
        """Predict URL"""
        features = self.extractor.extract_all_features(url)
        features_df = pd.DataFrame([features])[self.feature_names]
        
        pred = self.model.predict(features_df)[0]
        prob = self.model.predict_proba(features_df)[0]
        
        return {
            'url': url,
            'is_phishing': bool(pred),
            'confidence': float(max(prob)),
            'phishing_probability': float(prob[1])
        }


def test():
    print("=" * 60)
    print("🛡️ PHISHING DETECTOR TEST")
    print("=" * 60)
    
    detector = PhishingDetector()
    
    test_urls = [
        ("https://www.google.com", "legitimate"),
        ("https://www.facebook.com", "legitimate"),
        ("http://192.168.1.1/login.php", "phishing"),
        ("https://paypa1-secure.verify-account.tk/login", "phishing"),
        ("https://github.com", "legitimate"),
        ("https://amaz0n-security.update-info.ml", "phishing")
    ]
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    correct = 0
    for url, expected in test_urls:
        result = detector.predict(url)
        status = "🚨 PHISHING" if result['is_phishing'] else "✅ LEGIT"
        match = "✓" if (result['is_phishing'] == (expected == "phishing")) else "✗"
        if match == "✓":
            correct += 1
        
        print(f"\n{match} {url}")
        print(f"   Prediction: {status} ({result['confidence']:.1%} confidence)")
    
    print(f"\n{'=' * 60}")
    print(f"Accuracy: {correct}/{len(test_urls)} correct")


if __name__ == "__main__":
    test()