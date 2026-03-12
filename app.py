"""
Phishing Detector Web Application - Ultimate Edition
Features: ML Detection + Reputation Check + Retraining + Dashboard
"""

from flask import Flask, render_template, request, jsonify
import sys
import os
import json
import csv
import io
import shutil
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter
import difflib
import joblib
import pandas as pd

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from models.trainer import PhishingDetector, PhishingModelTrainer
from utils.reputation_checker import ReputationChecker

app = Flask(__name__)

# Initialize as None so the server can boot up instantly
detector = None
reputation_checker = None

@app.before_request
def initialize_models():
    """This loads the heavy ML models only when the first person visits the site"""
    global detector, reputation_checker
    if detector is None:
        print("First visitor detected! Loading heavy ML models now...")
        detector = PhishingDetector()
        reputation_checker = ReputationChecker()
        print("Systems ready!")

# Storage
scan_history = []
trusted_domains = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 
                   'wikipedia.org', 'twitter.com', 'linkedin.com', 'github.com']


def check_typosquatting(url):
    """Check if domain is typosquatting a trusted brand"""
    ext = __import__('tldextract').extract(url)
    domain = ext.domain.lower()
    
    similarities = []
    for trusted in trusted_domains:
        trusted_name = trusted.split('.')[0]
        similarity = difflib.SequenceMatcher(None, domain, trusted_name).ratio()
        if similarity > 0.7 and similarity < 1.0:
            similarities.append({
                'original': trusted_name,
                'detected': domain,
                'similarity': round(similarity * 100, 2),
                'type': 'Typosquatting' if similarity > 0.8 else 'Suspicious Similarity'
            })
    
    return similarities


def get_feature_breakdown(url):
    """Get detailed breakdown of suspicious features"""
    from features.extractor import URLFeatureExtractor
    extractor = URLFeatureExtractor()
    features = extractor.extract_all_features(url)
    
    breakdown = []
    
    if features['has_ip_address']:
        breakdown.append({
            'feature': 'IP Address in URL',
            'severity': 'high',
            'description': 'URL uses IP address instead of domain name'
        })
    
    if features['has_suspicious_words']:
        words = []
        url_lower = url.lower()
        suspicious = ['login', 'verify', 'account', 'update', 'confirm', 'secure', 'banking']
        for word in suspicious:
            if word in url_lower:
                words.append(word)
        breakdown.append({
            'feature': 'Suspicious Keywords',
            'severity': 'medium',
            'description': f"Found: {', '.join(words)}"
        })
    
    if features['is_shortened']:
        breakdown.append({
            'feature': 'URL Shortener',
            'severity': 'medium',
            'description': 'URL uses a shortening service'
        })
    
    if features['has_multiple_subdomains']:
        breakdown.append({
            'feature': 'Multiple Subdomains',
            'severity': 'medium',
            'description': 'Excessive subdomains detected'
        })
    
    if features['has_suspicious_tld']:
        breakdown.append({
            'feature': 'Suspicious TLD',
            'severity': 'low',
            'description': 'High-risk top-level domain'
        })
    
    if not features['has_https']:
        breakdown.append({
            'feature': 'No HTTPS',
            'severity': 'high',
            'description': 'Connection not encrypted'
        })
    
    if features['url_entropy'] > 4.5:
        breakdown.append({
            'feature': 'High Randomness',
            'severity': 'medium',
            'description': 'URL contains random characters'
        })
    
    return breakdown


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Full analysis with ML + Reputation check"""
    data = request.get_json()
    url = data.get('url', '').strip()
    check_reputation = data.get('check_reputation', True)
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # ML Prediction
        ml_result = detector.predict(url)
        
        # Reputation check (if enabled)
        reputation = None
        if check_reputation:
            try:
                reputation = reputation_checker.check_url(url)
            except Exception as e:
                reputation = {'error': str(e)}
        
        # Other analysis
        typosquatting = check_typosquatting(url)
        feature_breakdown = get_feature_breakdown(url)
        
        # Combined risk score
        ml_score = ml_result['phishing_probability'] * 100
        rep_score = reputation.get('reputation_score', 50) if reputation else 50
        combined_score = (ml_score * 0.7) + (rep_score * 0.3)
        
        # Final risk level
        if combined_score < 30:
            risk_level = 'low'
        elif combined_score < 70:
            risk_level = 'medium'
        else:
            risk_level = 'high'
        
        response = {
            'url': url,
            'is_phishing': combined_score > 50,
            'confidence': round(ml_result['confidence'] * 100, 2),
            'ml_probability': round(ml_score, 2),
            'reputation_score': round(rep_score, 2),
            'combined_score': round(combined_score, 2),
            'risk_level': risk_level,
            'ml_analysis': {
                'is_phishing': ml_result['is_phishing'],
                'confidence': round(ml_result['confidence'] * 100, 2)
            },
            'reputation': reputation,
            'typosquatting': typosquatting,
            'feature_breakdown': feature_breakdown,
            'scan_time': datetime.now().isoformat()
        }
        
        scan_history.append(response)
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/reputation-check', methods=['POST'])
def reputation_check():
    """Standalone reputation check"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        result = reputation_checker.check_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/batch', methods=['POST'])
def batch_analyze():
    """Batch analysis"""
    if 'file' in request.files:
        file = request.files['file']
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_reader = csv.DictReader(stream)
            urls = [row['url'] for row in csv_reader if 'url' in row]
        else:
            return jsonify({'error': 'Only CSV files supported'}), 400
    else:
        data = request.get_json()
        urls = data.get('urls', [])
    
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    
    results = []
    for url in urls[:50]:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            result = detector.predict(url)
            typosquatting = check_typosquatting(url)
            
            results.append({
                'url': url,
                'is_phishing': result['is_phishing'],
                'confidence': round(result['confidence'] * 100, 2),
                'risk_score': round(result['phishing_probability'] * 100, 1),
                'typosquatting_detected': len(typosquatting) > 0
            })
        except Exception as e:
            results.append({'url': url, 'error': str(e)})
    
    total = len(results)
    phishing_count = sum(1 for r in results if r.get('is_phishing', False))
    
    return jsonify({
        'summary': {
            'total_scanned': total,
            'phishing_detected': phishing_count,
            'safe_sites': total - phishing_count
        },
        'results': results
    })


@app.route('/email-analyze', methods=['POST'])
def analyze_email():
    """Email phishing analysis"""
    data = request.get_json()
    email_content = data.get('email', '')
    subject = data.get('subject', '')
    
    import re
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, email_content)
    
    email_flags = []
    
    urgent_words = ['urgent', 'immediate', 'action required', 'verify now', 'suspended']
    if any(word in subject.lower() for word in urgent_words):
        email_flags.append({
            'type': 'Urgent Language',
            'description': 'Subject uses urgency to pressure action'
        })
    
    if 'href' in email_content:
        email_flags.append({
            'type': 'HTML Links',
            'description': 'Email contains HTML links that may hide true destinations'
        })
    
    url_results = []
    for url in urls[:10]:
        try:
            result = detector.predict(url)
            url_results.append({
                'url': url,
                'is_phishing': result['is_phishing'],
                'confidence': round(result['confidence'] * 100, 2)
            })
        except:
            url_results.append({'url': url, 'error': 'Failed to analyze'})
    
    phishing_links = sum(1 for r in url_results if r.get('is_phishing', False))
    
    return jsonify({
        'urls_found': len(urls),
        'phishing_links': phishing_links,
        'suspicious_patterns': email_flags,
        'url_analysis': url_results,
        'recommendation': 'DANGER' if phishing_links > 0 else 'CAUTION' if email_flags else 'SAFE'
    })


@app.route('/retrain')
def retrain_page():
    """Model retraining interface"""
    return render_template('retrain.html')


@app.route('/upload-training-data', methods=['POST'])
def upload_training_data():
    """Upload new data to retrain model"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    label_column = request.form.get('label_column', 'label')
    url_column = request.form.get('url_column', 'url')
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Only CSV files supported'}), 400
    
    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        df = pd.read_csv(stream)
        
        if url_column not in df.columns or label_column not in df.columns:
            return jsonify({
                'error': f'Columns not found. Available: {list(df.columns)}'
            }), 400
        
        valid_labels = df[label_column].isin([0, 1, '0', '1', 'legitimate', 'phishing'])
        if not valid_labels.all():
            return jsonify({
                'error': 'Labels must be 0/1 or legitimate/phishing'
            }), 400
        
        label_map = {'legitimate': 0, 'phishing': 1, '0': 0, '1': 1, 0: 0, 1: 1}
        df[label_column] = df[label_column].map(label_map)
        
        from features.extractor import URLFeatureExtractor
        extractor = URLFeatureExtractor()
        
        feature_rows = []
        for idx, row in df.iterrows():
            try:
                features = extractor.extract_all_features(row[url_column])
                features['label'] = row[label_column]
                feature_rows.append(features)
            except Exception as e:
                print(f"Error processing row {idx}: {e}")
                continue
        
        feature_df = pd.DataFrame(feature_rows)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dataset_path = f"data/training_data_{timestamp}.csv"
        os.makedirs("data", exist_ok=True)
        feature_df.to_csv(dataset_path, index=False)
        
        return jsonify({
            'success': True,
            'samples_processed': len(feature_df),
            'phishing_samples': int((feature_df['label'] == 1).sum()),
            'legitimate_samples': int((feature_df['label'] == 0).sum()),
            'dataset_path': dataset_path,
            'message': 'Data processed successfully. Ready for training.'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/retrain-model', methods=['POST'])
def retrain_model():
    """Retrain model with uploaded data"""
    data = request.get_json()
    dataset_path = data.get('dataset_path')
    
    if not dataset_path or not os.path.exists(dataset_path):
        trainer = PhishingModelTrainer()
        df = trainer.create_sample_dataset()
    else:
        df = pd.read_csv(dataset_path)
        trainer = PhishingModelTrainer()
    
    try:
        print("Starting model retraining...")
        model = trainer.train_model(df)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = f"models/phishing_model_{timestamp}.pkl"
        trainer.save_model(model_path)
        
        trainer.save_model('models/phishing_model.pkl')
        
        global detector
        detector = PhishingDetector()
        
        return jsonify({
            'success': True,
            'message': 'Model retrained successfully',
            'model_path': model_path,
            'samples_used': len(df),
            'accuracy': 'See training logs'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/model-status')
def model_status():
    """Get current model info"""
    from pathlib import Path
    
    models_dir = Path("models")
    if not models_dir.exists():
        return jsonify({'models': []})
    
    models = []
    for model_file in models_dir.glob("*.pkl"):
        stat = model_file.stat()
        models.append({
            'filename': model_file.name,
            'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'size_kb': round(stat.st_size / 1024, 2)
        })
    
    models.sort(key=lambda x: x['created'], reverse=True)
    
    return jsonify({
        'current_model': 'phishing_model.pkl',
        'available_models': models,
        'total_models': len(models)
    })


@app.route('/switch-model', methods=['POST'])
def switch_model():
    """Switch to a different saved model"""
    data = request.get_json()
    model_name = data.get('model')
    
    if not model_name:
        return jsonify({'error': 'No model specified'}), 400
    
    model_path = f"models/{model_name}"
    if not os.path.exists(model_path):
        return jsonify({'error': 'Model not found'}), 404
    
    try:
        if os.path.exists('models/phishing_model.pkl'):
            shutil.copy('models/phishing_model.pkl', 'models/phishing_model_backup.pkl')
        
        shutil.copy(model_path, 'models/phishing_model.pkl')
        
        global detector
        detector = PhishingDetector()
        
        return jsonify({
            'success': True,
            'message': f'Switched to {model_name}',
            'current_model': model_name
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history')
def get_history():
    return jsonify({
        'total_scans': len(scan_history),
        'history': scan_history[-100:]
    })


@app.route('/clear-history', methods=['POST'])
def clear_history():
    global scan_history
    scan_history = []
    return jsonify({'message': 'History cleared'})


@app.route('/dashboard')
def dashboard():
    """Analytics dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    if not scan_history:
        return jsonify({
            'total_scans': 0,
            'threats_blocked': 0,
            'safe_sites': 0,
            'average_confidence': 0,
            'top_targeted_brands': [],
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0},
            'recent_scans': []
        })
    
    total = len(scan_history)
    threats = sum(1 for s in scan_history if s.get('is_phishing', False))
    safe = total - threats
    
    risk_dist = Counter(s.get('risk_level', 'unknown') for s in scan_history)
    
    brands = []
    for scan in scan_history:
        for typo in scan.get('typosquatting', []):
            brands.append(typo['original'])
    top_brands = Counter(brands).most_common(5)
    
    recent = scan_history[-10:]
    
    hourly = {}
    for scan in scan_history:
        scan_time = datetime.fromisoformat(scan['scan_time'])
        hour_key = scan_time.strftime('%H:00')
        hourly[hour_key] = hourly.get(hour_key, 0) + 1
    
    return jsonify({
        'total_scans': total,
        'threats_blocked': threats,
        'safe_sites': safe,
        'detection_rate': round((threats / total) * 100, 2) if total > 0 else 0,
        'average_confidence': round(
            sum(s.get('confidence', 0) for s in scan_history) / total, 2
        ) if total > 0 else 0,
        'risk_distribution': dict(risk_dist),
        'top_targeted_brands': [{'brand': b, 'count': c} for b, c in top_brands],
        'recent_scans': recent,
        'hourly_activity': hourly
    })


@app.route('/api/export', methods=['POST'])
def export_data():
    """Export scan history to CSV"""
    if not scan_history:
        return jsonify({'error': 'No data to export'}), 400
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'timestamp', 'url', 'is_phishing', 'risk_level', 
        'confidence', 'combined_score', 'typosquatting_detected'
    ])
    
    for scan in scan_history:
        writer.writerow([
            scan.get('scan_time'),
            scan.get('url'),
            scan.get('is_phishing'),
            scan.get('risk_level'),
            scan.get('confidence'),
            scan.get('combined_score'),
            len(scan.get('typosquatting', [])) > 0
        ])
    
    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=scan_history.csv'
    }


@app.route('/api/clear-all', methods=['POST'])
def clear_all_data():
    """Clear all history and reset"""
    global scan_history
    scan_history = []
    reputation_checker.cache.clear()
    return jsonify({'message': 'All data cleared'})


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ PHISHING DETECTOR PRO - ULTIMATE EDITION")
    print("Features: ML + Reputation + Retraining + Dashboard")
    print("=" * 60)
    print("Main App:  http://127.0.0.1:5000")
    print("Retrain:   http://127.0.0.1:5000/retrain")
    print("Dashboard: http://127.0.0.1:5000/dashboard")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)