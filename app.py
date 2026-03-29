"""
Phishing Detector Web Application - Professional Edition
Features: Heuristic Analysis + Reputation Check + Dashboard
"""

from flask import Flask, render_template, request, jsonify
import sys
import os
import json
import csv
import io
import shutil
import traceback
import tldextract
import difflib
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter
import tldextract

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from features.extractor import URLFeatureExtractor
from utils.reputation_checker import ReputationChecker

app = Flask(__name__)

# Initialize components
extractor = URLFeatureExtractor()
reputation_checker = ReputationChecker()

# Storage
scan_history = []
trusted_domains = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 
                   'wikipedia.org', 'twitter.com', 'linkedin.com', 'github.com']


def check_typosquatting(url):
    """Check if domain is typosquatting a trusted brand"""
    import tldextract
    ext = tldextract.extract(url)
    domain = ext.domain.lower()
    
    similarities = []
    for trusted in trusted_domains:
        trusted_name = trusted.split('.')[0]
        similarity = difflib.SequenceMatcher(None, domain, trusted_name).ratio()
        if similarity > 0.75 and similarity < 1.0:
            similarities.append({
                'original': trusted_name,
                'detected': domain,
                'similarity': round(similarity * 100, 2),
                'type': 'Typosquatting' if similarity > 0.85 else 'Suspicious Similarity'
            })
    
    return similarities


def calculate_heuristic_score(url):
    """Calculate a risk score (0-100) based on URL features"""
    features = extractor.extract_all_features(url)
    score = 0
    
    # Base score
    score = 0
    
    # Weights for different features - AGGRESSIVE MODE
    if features['has_ip_address']: 
        score += 60 # IP Address is very risky in a scanner
    if features['is_shortened']: 
        score += 30 # Shortened URLs hide danger
    if features['has_multiple_subdomains']: 
        score += 25 # login.secure.bank.com...
    if features['has_suspicious_tld']: 
        score += 35 # .tk, .ml, .ga, etc.
    if not features['has_https']: 
        score += 30 # Encryption is mandatory for security
    if features['url_entropy'] > 4.8: 
        score += 25 # High randomness suggests generated malicious URLs
    if features['digit_ratio'] > 0.4: 
        score += 15 # Excessive digits (often in tracking IDs of phishing)
        
    # Advanced Heuristics
    url_lower = url.lower()
    
    # 1. Non-standard ports
    parsed = urlparse(url)
    if parsed.port and parsed.port not in [80, 443]:
        score += 20
        features['has_unusual_port'] = True
    else:
        features['has_unusual_port'] = False

    # 2. Homoglyph Detection (Simple check for non-ASCII in domain)
    domain_part = tldextract.extract(url).domain
    if any(ord(c) > 127 for c in domain_part):
        score += 50 # Homoglyphs are a critical high-confidence signal
        features['is_homoglyph'] = True
    else:
        features['is_homoglyph'] = False
        
    # 3. Aggressive Keywords
    keywords = [
        'login', 'verify', 'account', 'update', 'confirm', 'secure', 'banking', 
        'validate', 'auth', 'signin', 'support', 'billing', 'wallet', 'crypto',
        'paypal', 'ebay', 'amazon', 'netflix', 'microsoft', 'apple', 'office'
    ]
    found_keywords = [w for w in keywords if w in url_lower]
    score += len(found_keywords) * 15 # Each sensitive keyword adds risk
    
    # 4. Suspicious Extensions in long URLs
    suspicious_exts = ['.exe', '.zip', '.rar', '.js', '.scr', '.vbs', '.iso', '.dmg']
    if any(url_lower.endswith(ext) for ext in suspicious_exts):
        score += 40
        features['has_suspicious_ext'] = True
    else:
        features['has_suspicious_ext'] = False

    # Age Analysis (AGGRESSIVE)
    domain_age = features.get('domain_age_days', -1)
    if 0 <= domain_age < 30:
        score += 50 # Tiny age is a huge red flag
        features['is_brand_new'] = True
    elif 30 <= domain_age < 365:
        score += 15 # Less than a year old
    elif domain_age > 3650:
        score -= 20 # 10+ years old (Very trusted)
        
    typos = check_typosquatting(url)
    if typos: score += 60 # Major threat signal
    
    # Immediate Vector: IP + No HTTPS = Critical
    if features['has_ip_address'] and not features['has_https']:
        score = max(score, 95)
        
    # Vector: Typosquatting + Suspicious TLD = High
    if typos and features['has_suspicious_tld']:
        score = max(score, 90)

    # Clamp to 100
    return min(100, score), features


def get_feature_breakdown(url, features):
    """Get detailed breakdown of suspicious features for the UI"""
    breakdown = []
    
    if features['has_ip_address']:
        breakdown.append({
            'feature': 'IP Address in URL',
            'severity': 'high',
            'description': 'URL uses an IP address instead of a domain name, often used in phishing.'
        })
    
    keywords = ['login', 'verify', 'account', 'update', 'confirm', 'secure', 'banking']
    found = [w for w in keywords if w in url.lower()]
    if found:
        breakdown.append({
            'feature': 'Suspicious Keywords',
            'severity': 'medium',
            'description': f"Found sensitive keywords: {', '.join(found)}"
        })
    
    if features['is_shortened']:
        breakdown.append({
            'feature': 'URL Shortener',
            'severity': 'medium',
            'description': 'URL uses a shortening service which can hide the final destination.'
        })
    
    if features['has_multiple_subdomains']:
        breakdown.append({
            'feature': 'Multiple Subdomains',
            'severity': 'medium',
            'description': 'Excessive subdomains are often used to mimic legitimate sites.'
        })
    
    if features['has_suspicious_tld']:
        breakdown.append({
            'feature': 'Suspicious TLD',
            'severity': 'medium',
            'description': f"Uses a high-risk top-level domain."
        })
    
    if not features['has_https']:
        breakdown.append({
            'feature': 'No HTTPS',
            'severity': 'high',
            'description': 'The connection is not encrypted. Never enter sensitive data here.'
        })
    
    if features['url_entropy'] > 4.8:
        breakdown.append({
            'feature': 'High Randomness',
            'severity': 'medium',
            'description': 'The URL structure contains excessive random segments.'
        })

    if features.get('has_unusual_port'):
        breakdown.append({
            'feature': 'Non-Standard Port',
            'severity': 'high',
            'description': f"Using port {urlparse(url).port}. Standard web ports are 80 or 443."
        })

    if features.get('is_homoglyph'):
        breakdown.append({
            'feature': 'Homoglyph (IDN)',
            'severity': 'critical',
            'description': 'Detected look-alike characters in the domain used for impersonation.'
        })

    if features.get('has_suspicious_ext'):
        breakdown.append({
            'feature': 'Executable/Archive in URL',
            'severity': 'high',
            'description': 'The link points directly to a potential payload file (.exe, .zip, etc.).'
        })
        
    typos = check_typosquatting(url)
    for t in typos:
        breakdown.append({
            'feature': 'Brand Impersonation',
            'severity': 'high',
            'description': f"Detected potential typosquatting of '{t['original']}' (Similarity: {t['similarity']}%)."
        })
    
    return breakdown


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Full analysis with Heuristics + Reputation check"""
    data = request.get_json()
    url = data.get('url', '').strip()
    check_rep = data.get('check_reputation', True)
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Heuristic Analysis
        h_score, features = calculate_heuristic_score(url)
        
        # Reputation check
        reputation = None
        r_score = 0
        if check_rep:
            try:
                reputation = reputation_checker.check_url(url)
                r_score = reputation.get('reputation_score', 0)
            except Exception as e:
                reputation = {'error': str(e)}
        
        # Geolocation for Map
        geo_data = {}
        try:
            domain = tldextract.extract(url).fqdn or tldextract.extract(url).domain
            ip_addr = socket.gethostbyname(domain)
            geo_res = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=status,message,country,city,lat,lon", timeout=3).json()
            if geo_res.get('status') == 'success':
                geo_data = {
                    'ip': ip_addr,
                    'country': geo_res.get('country'),
                    'city': geo_res.get('city'),
                    'lat': geo_res.get('lat'),
                    'lon': geo_res.get('lon')
                }
        except:
            pass

        typosquatting = check_typosquatting(url)
        feature_breakdown = get_feature_breakdown(url, features)
        
        # Build risk summary
        reasons = []
        if features.get('is_homoglyph'): reasons.append("uses look-alike 'homoglyph' characters")
        if features['has_ip_address']: reasons.append("uses an IP address instead of a domain")
        if features.get('has_suspicious_ext'): reasons.append("points to a suspicious file download")
        if features['has_suspicious_tld']: reasons.append("uses a high-risk TLD")
        if not features['has_https']: reasons.append("is not encrypted")
        if typosquatting: reasons.append(f"appears to mimic {typosquatting[0]['original']}")
        if features.get('has_unusual_port'): reasons.append("uses an unusual network port")
        if features.get('is_brand_new'): reasons.append("was registered less than 30 days ago")
        
        r_summary = "Site appears safe based on current telemetry."
        if h_score > 0 or r_score > 0:
            if reasons:
                # Prioritize first 2 critical reasons
                r_summary = f"Flagged because it {' and '.join(reasons[:2])}."
            elif r_score > 70:
                r_summary = "Security databases have officially blacklisted this domain."
            elif 1 <= r_score <= 50:
                r_summary = "Domain has neutral reputation; it is neither whitelisted nor blacklisted."
            elif r_score == 0 and h_score == 0:
                r_summary = "Verified safe domain (whitelisted brand)."
            elif h_score > 0:
                r_summary = "Heuristic analysis detected multiple suspicious patterns."
        
        # Combined Risk Score (Weighted average)
        # If reputation returns a high risk, it heavily weights the result
        combined_score = (h_score * 0.4) + (r_score * 0.6)
        
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
            'confidence': 100 - abs(50 - combined_score) * 2, # Heuristic "confidence"
            'heuristic_score': round(h_score, 2),
            'reputation_score': round(r_score, 2),
            'combined_score': round(combined_score, 2),
            'risk_level': risk_level,
            'risk_summary': r_summary,
            'reputation': reputation,
            'features': features,
            'feature_breakdown': feature_breakdown,
            'geo': geo_data,
            'scan_time': datetime.now().isoformat()
        }
        
        # Log to history
        scan_history.append(response)
        
        return jsonify(response)
        
    except Exception as e:
        # Log the full traceback for debugging
        print("CRITICAL ERROR IN ANALYZE:")
        traceback.print_exc()
        return jsonify({
            'error': f"Internal Analysis Error: {str(e)}",
            'status': 'error',
            'details': traceback.format_exc().splitlines()[-1]
        }), 500


@app.route('/reputation-check', methods=['POST'])
def reputation_check():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url: return jsonify({'error': 'No URL provided'}), 400
    try:
        result = reputation_checker.check_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/batch', methods=['POST'])
def batch_analyze():
    """Batch analysis using heuristics"""
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
            h_score, features = calculate_heuristic_score(url)
            # Simple summary for batch
            reasons = []
            if features['has_ip_address']: reasons.append("IP Address")
            if features['has_suspicious_tld']: reasons.append("Risk TLD")
            if not features['has_https']: reasons.append("No HTTPS")
            
            results.append({
                'url': url,
                'is_phishing': h_score > 50,
                'risk_score': round(h_score, 1),
                'risk_level': 'high' if h_score > 70 else 'medium' if h_score > 30 else 'low',
                'risk_summary': ", ".join(reasons) if reasons else "Clear"
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
    """Email phishing analysis via heuristics"""
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
            h_score, features = calculate_heuristic_score(url)
            url_results.append({
                'url': url,
                'is_phishing': h_score > 50,
                'risk_score': h_score,
                'flag': "Suspicious" if h_score > 30 else "Safe"
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


@app.route('/history')
def get_history():
    return jsonify({
        'total_scans': len(scan_history),
        'history': scan_history[-100:]
    })


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/stats')
def get_stats():
    """Get system statistics from history"""
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
    
    recent = scan_history[-10:]
    
    hourly = {}
    for scan in scan_history:
        scan_time = datetime.fromisoformat(scan['scan_time'])
        hour_key = scan_time.strftime('%H:00')
        hourly[hour_key] = hourly.get(hour_key, 0) + 1
    
    # Generate Live Logs for Dashboard
    live_logs = []
    for scan in scan_history[-20:]:
        # Extract features that were flagged
        features = scan.get('features', {})
        reasons = []
        if features.get('is_homoglyph'): reasons.append("Homoglyph Detected")
        if features.get('has_ip_address'): reasons.append("IP Address Host")
        if features.get('is_brand_new'): reasons.append("New Domain (<30d)")
        if features.get('has_suspicious_tld'): reasons.append("High-Risk TLD")
        
        if reasons:
            live_logs.append({
                'time': scan.get('scan_time'),
                'url': scan.get('url'),
                'action': ", ".join(reasons)
            })

    return jsonify({
        'total_scans': total,
        'threats_blocked': threats,
        'safe_sites': safe,
        'detection_rate': round((threats / total) * 100, 2) if total > 0 else 0,
        'average_risk_score': round(
            sum(s.get('combined_score', 0) for s in scan_history) / total, 2
        ) if total > 0 else 0,
        'risk_distribution': dict(risk_dist),
        'recent_scans': recent,
        'hourly_activity': hourly,
        'live_logs': live_logs
    })


@app.route('/api/export', methods=['POST'])
def export_data():
    if not scan_history:
        return jsonify({'error': 'No data to export'}), 400
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'url', 'is_phishing', 'risk_level', 'heuristic_score', 'reputation_score'])
    
    for scan in scan_history:
        writer.writerow([
            scan.get('scan_time'),
            scan.get('url'),
            scan.get('is_phishing'),
            scan.get('risk_level'),
            scan.get('heuristic_score'),
            scan.get('reputation_score')
        ])
    
    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=scan_history.csv'
    }


@app.route('/api/clear-all', methods=['POST'])
def clear_all_data():
    global scan_history
    scan_history = []
    reputation_checker.cache.clear()
    return jsonify({'message': 'All data cleared'})


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ PHISHING SHIELD - PROFESSIONAL EDITION")
    print("Engine: Heuristics + Reputation Tracking")
    print("=" * 60)
    print("Main App:  http://127.0.0.1:5000")
    print("Dashboard: http://127.0.0.1:5000/dashboard")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.1' if os.environ.get('PORT') else '0.0.0.0', port=5000)