"""
Phishing URL Feature Extractor
Extracts 30+ features from URLs for ML classification
"""

import re
import ssl
import socket
import requests
import tldextract
import whois
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import math


class URLFeatureExtractor:
    def __init__(self):
        # Suspicious keywords commonly found in phishing URLs
        self.suspicious_words = [
            'login', 'signin', 'verify', 'account', 'update', 'confirm',
            'banking', 'secure', 'ebayisapi', 'webscr', 'password',
            'credential', 'wallet', 'alert', 'limited', 'suspend',
            'unusual', 'activity', 'access', 'confirm', 'identity',
            'verification', 'customer', 'service', 'resolution', 'hack',
            'steal', 'fake', 'phish', 'scam', 'fraud'
        ]
        
        # Shortening services
        self.shortening_services = [
            'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 
            'buff.ly', 'is.gd', 'short.link', 'rebrand.ly',
            'cutt.ly', 'short.io', 'bl.ink'
        ]
        
        # Brand names often targeted
        self.brands = [
            'paypal', 'apple', 'microsoft', 'amazon', 'facebook',
            'google', 'netflix', 'chase', 'wellsfargo', 'citi',
            'amex', 'visa', 'mastercard', 'linkedin', 'twitter'
        ]

    def extract_all_features(self, url):
        """Extract all features from a URL and return as dictionary"""
        features = {}
        
        # Basic URL parsing
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        # Build domain properly (fix deprecation warning)
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
        
        # 6. External checks (might fail, so wrapped in try-except)
        try:
            features['domain_age_days'] = self._get_domain_age(full_domain)
        except:
            features['domain_age_days'] = -1
            
        try:
            features['has_dns_record'] = self._check_dns(full_domain)
        except:
            features['has_dns_record'] = -1
            
        try:
            features['has_ssl'] = self._check_ssl(full_domain)
        except:
            features['has_ssl'] = -1
        
        return features

    def _has_ip_address(self, url):
        """Check if URL contains IP address instead of domain"""
        ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
        return 1 if re.search(ip_pattern, url) else 0
    
    def _has_suspicious_words(self, url):
        """Check for suspicious keywords in URL"""
        url_lower = url.lower()
        for word in self.suspicious_words:
            if word in url_lower:
                return 1
        return 0
    
    def _count_suspicious_keywords(self, url):
        """Count how many suspicious keywords appear"""
        url_lower = url.lower()
        count = 0
        for word in self.suspicious_words:
            if word in url_lower:
                count += 1
        return count
    
    def _is_shortened(self, url):
        """Check if URL uses shortening service"""
        url_lower = url.lower()
        for service in self.shortening_services:
            if service in url_lower:
                return 1
        return 0
    
    def _has_brand_name(self, url):
        """Check if URL contains brand names (possible impersonation)"""
        url_lower = url.lower()
        for brand in self.brands:
            if brand in url_lower:
                return 1
        return 0
    
    def _has_multiple_subdomains(self, ext):
        """Check if domain has multiple subdomains (suspicious)"""
        subdomain = ext.subdomain
        if subdomain:
            parts = subdomain.split('.')
            return 1 if len(parts) > 1 else 0
        return 0
    
    def _has_suspicious_tld(self, ext):
        """Check for suspicious top-level domains"""
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'xyz', 'work', 'date']
        return 1 if ext.suffix in suspicious_tlds else 0
    
    def _domain_in_ip_format(self, netloc):
        """Check if domain is in IP format"""
        try:
            socket.inet_aton(netloc.split(':')[0])
            return 1
        except:
            return 0
    
    def _calculate_entropy(self, url):
        """Calculate Shannon entropy of URL (higher = more random/suspicious)"""
        if not url:
            return 0
        prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    
    def _digit_ratio(self, url):
        """Ratio of digits in URL"""
        if not url:
            return 0
        digits = sum(c.isdigit() for c in url)
        return digits / len(url)
    
    def _letter_ratio(self, url):
        """Ratio of letters in URL"""
        if not url:
            return 0
        letters = sum(c.isalpha() for c in url)
        return letters / len(url)
    
    def _get_domain_age(self, domain):
        """Get domain age in days"""
        if not domain or '.' not in domain:
            return -1
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age = (datetime.now() - creation_date).days
                return age
        except:
            pass
        return -1
    
    def _check_dns(self, domain):
        """Check if domain has DNS records"""
        if not domain:
            return 0
        try:
            socket.gethostbyname(domain)
            return 1
        except:
            return 0
    
    def _check_ssl(self, domain):
        """Check if domain has valid SSL certificate"""
        if not domain:
            return 0
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return 1
        except:
            return 0


# Test function
def test_extractor():
    extractor = URLFeatureExtractor()
    
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/login.php",
        "https://paypa1-secure.verify-account.tk/login",
        "https://bit.ly/3xyz123",
        "https://www.bankofamerica.com/login"
    ]
    
    print("Testing Feature Extractor...\n")
    
    for url in test_urls:
        print(f"URL: {url}")
        features = extractor.extract_all_features(url)
        print(f"  Length: {features['url_length']}, Has IP: {features['has_ip_address']}")
        print(f"  Suspicious words: {features['has_suspicious_words']}, HTTPS: {features['has_https']}")
        print(f"  Entropy: {features['url_entropy']:.2f}, Domain age: {features['domain_age_days']}")
        print("-" * 60)

if __name__ == "__main__":
    test_extractor()