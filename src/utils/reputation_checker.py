"""
Domain Reputation Checker
Queries multiple security APIs for domain reputation
"""

import requests
import json
import time
from urllib.parse import urlparse
import tldextract


class ReputationChecker:
    def __init__(self):
        # Store API keys here (use environment variables in production!)
        self.apis = {
            'virustotal': None,  # Free: virustotal.com/gui/join-us
            'google_safe_browsing': None,  # Free: developers.google.com/safe-browsing
            'urlhaus': None,  # Free, no key needed for lookup
            'phishtank': None,  # Free, no key needed
            'abuseipdb': None  # Free: abuseipdb.com/register
        }
        
        # Cache results to avoid rate limits
        self.cache = {}
        self.cache_timeout = 300  # 5 minutes
    
    def check_url(self, url):
        """Check URL against all available reputation sources"""
        # Extract domain
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Check cache
        if domain in self.cache:
            cached_time, result = self.cache[domain]
            if time.time() - cached_time < self.cache_timeout:
                return result
        
        results = {
            'domain': domain,
            'overall_risk': 'unknown',
            'sources_checked': [],
            'details': {}
        }
        
        # Check each API (continue even if some fail)
        try:
            vt_result = self._check_virustotal(domain)
            results['details']['virustotal'] = vt_result
            results['sources_checked'].append('virustotal')
        except Exception as e:
            results['details']['virustotal'] = {'error': str(e)}
        
        try:
            gs_result = self._check_google_safe_browsing(url)
            results['details']['google_safe_browsing'] = gs_result
            results['sources_checked'].append('google_safe_browsing')
        except Exception as e:
            results['details']['google_safe_browsing'] = {'error': str(e)}
        
        try:
            uh_result = self._check_urlhaus(domain)
            results['details']['urlhaus'] = uh_result
            results['sources_checked'].append('urlhaus')
        except Exception as e:
            results['details']['urlhaus'] = {'error': str(e)}
        
        try:
            pt_result = self._check_phishtank(url)
            results['details']['phishtank'] = pt_result
            results['sources_checked'].append('phishtank')
        except Exception as e:
            results['details']['phishtank'] = {'error': str(e)}
        
        # Calculate overall risk
        results['overall_risk'] = self._calculate_overall_risk(results['details'])
        results['reputation_score'] = self._calculate_score(results['details'])
        
        # Cache result
        self.cache[domain] = (time.time(), results)
        
        return results
    
    def _check_virustotal(self, domain):
        """Check VirusTotal (requires API key)"""
        if not self.apis['virustotal']:
            return {'status': 'no_api_key', 'message': 'Add VirusTotal API key for this check'}
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': self.apis['virustotal'], 'domain': domain}
        
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        detections = data.get('detected_urls', [])
        positives = sum(1 for d in detections if d.get('positives', 0) > 0)
        
        return {
            'status': 'checked',
            'detected_urls': len(detections),
            'malicious_detections': positives,
            'risk': 'high' if positives > 5 else 'medium' if positives > 0 else 'low'
        }
    
    def _check_google_safe_browsing(self, url):
        """Check Google Safe Browsing (requires API key)"""
        if not self.apis['google_safe_browsing']:
            return {'status': 'no_api_key', 'message': 'Add Google API key for this check'}
        
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.apis['google_safe_browsing']}"
        
        payload = {
            'client': {'clientId': 'phishing-detector', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        data = response.json()
        
        matches = data.get('matches', [])
        
        return {
            'status': 'checked',
            'threats_found': len(matches),
            'threat_types': [m.get('threatType') for m in matches],
            'risk': 'high' if matches else 'low'
        }
    
    def _check_urlhaus(self, domain):
        """Check URLhaus (no API key needed)"""
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = {'host': domain}
        
        response = requests.post(url, data=payload, timeout=10)
        data = response.json()
        
        if data.get('query_status') == 'no_results':
            return {'status': 'clean', 'urls_found': 0, 'risk': 'low'}
        
        urls = data.get('urls', [])
        malware_urls = [u for u in urls if u.get('url_status') == 'online']
        
        return {
            'status': 'listed',
            'urls_found': len(urls),
            'active_malware': len(malware_urls),
            'first_seen': urls[0].get('dateadded') if urls else None,
            'risk': 'high' if malware_urls else 'medium' if urls else 'low'
        }
    
    def _check_phishtank(self, url):
        """Check PhishTank (no API key needed for limited use)"""
        # PhishTank requires specific format
        api_url = "https://checkurl.phishtank.com/checkurl/"
        payload = {
            'url': url,
            'format': 'json',
            'app_key': self.apis['phishtank'] or 'demo'  # 'demo' for testing
        }
        
        response = requests.post(api_url, data=payload, timeout=10)
        data = response.json()
        
        result = data.get('results', {})
        
        return {
            'status': 'checked',
            'in_database': result.get('in_database', False),
            'is_phishing': result.get('valid', False),
            'verified': result.get('verified', False),
            'risk': 'high' if result.get('valid') else 'low'
        }
    
    def _calculate_overall_risk(self, details):
        """Calculate overall risk level from all sources"""
        risks = []
        
        for source, data in details.items():
            if 'risk' in data:
                risks.append(data['risk'])
            elif 'error' in data:
                continue  # Skip failed checks
        
        if not risks:
            return 'unknown'
        
        if 'high' in risks:
            return 'high'
        elif 'medium' in risks:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_score(self, details):
        """Calculate reputation score (0-100, higher = more risky)"""
        score = 50  # Neutral starting point
        
        for source, data in details.items():
            if 'risk' in data:
                if data['risk'] == 'high':
                    score += 25
                elif data['risk'] == 'medium':
                    score += 10
                elif data['risk'] == 'low':
                    score -= 10
        
        # Clamp to 0-100
        return max(0, min(100, score))
    
    def set_api_key(self, service, key):
        """Set API key for a service"""
        if service in self.apis:
            self.apis[service] = key
            return True
        return False


# Test
if __name__ == "__main__":
    checker = ReputationChecker()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://paypa1-secure.verify-account.tk/login",
        "http://192.168.1.1/login.php"
    ]
    
    print("Testing Reputation Checker...\n")
    for url in test_urls:
        print(f"Checking: {url}")
        result = checker.check_url(url)
        print(f"  Overall Risk: {result['overall_risk']}")
        print(f"  Reputation Score: {result['reputation_score']}/100")
        print(f"  Sources: {', '.join(result['sources_checked'])}")
        print()