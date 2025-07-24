import re
import requests
from urllib.parse import urlparse, parse_qs
import whois
from datetime import datetime, timedelta
import logging
import hashlib
import dns.resolver
from ipaddress import ip_address, AddressValueError

logger = logging.getLogger(__name__)

class URLAnalyzer:
    def __init__(self):
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.loan', '.win', '.men', '.party', '.science', '.work'
        ]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'lnk.to'
        ]
        
        self.phishing_keywords = [
            'login', 'secure', 'account', 'update', 'verify', 'confirm',
            'suspended', 'urgent', 'immediate', 'click', 'banking',
            'paypal', 'amazon', 'microsoft', 'google', 'apple'
        ]
        
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Multiple hyphens
            r'[a-zA-Z]{20,}',  # Very long domain names
            r'[0-9]{5,}',  # Long number sequences
        ]
    
    def analyze_url(self, url):
        """Main URL analysis function"""
        try:
            # Parse URL
            parsed = urlparse(url)
            
            risk_factors = []
            threat_score = 0.0
            detected_threats = []
            
            # Domain analysis
            domain_risk = self._analyze_domain(parsed.netloc)
            risk_factors.extend(domain_risk['factors'])
            threat_score += domain_risk['score']
            detected_threats.extend(domain_risk['threats'])
            
            # Path analysis
            path_risk = self._analyze_path(parsed.path)
            risk_factors.extend(path_risk['factors'])
            threat_score += path_risk['score']
            detected_threats.extend(path_risk['threats'])
            
            # Query parameters analysis
            query_risk = self._analyze_query_params(parsed.query)
            risk_factors.extend(query_risk['factors'])
            threat_score += query_risk['score']
            detected_threats.extend(query_risk['threats'])
            
            # URL structure analysis
            structure_risk = self._analyze_url_structure(url)
            risk_factors.extend(structure_risk['factors'])
            threat_score += structure_risk['score']
            detected_threats.extend(structure_risk['threats'])
            
            # HTTPS check
            if parsed.scheme != 'https':
                risk_factors.append('Non-HTTPS connection')
                threat_score += 0.2
                detected_threats.append({
                    'type': 'Insecure Connection',
                    'severity': 'Medium',
                    'description': 'URL uses HTTP instead of HTTPS'
                })
            
            # Normalize threat score
            threat_score = min(threat_score, 1.0)
            
            # Determine threat level
            if threat_score >= 0.8:
                threat_level = 'CRITICAL'
            elif threat_score >= 0.6:
                threat_level = 'HIGH'
            elif threat_score >= 0.4:
                threat_level = 'MEDIUM'
            elif threat_score >= 0.2:
                threat_level = 'LOW'
            else:
                threat_level = 'SAFE'
            
            # Generate recommendations
            recommendations = self._generate_recommendations(risk_factors, threat_score)
            
            return {
                'url': url,
                'threat_score': threat_score,
                'threat_level': threat_level,
                'is_phishing': threat_score >= 0.5,
                'confidence': min(0.95, 0.7 + (threat_score * 0.3)),
                'risk_factors': list(set(risk_factors)),
                'detected_threats': detected_threats,
                'recommendations': recommendations,
                'domain_info': self._get_domain_info(parsed.netloc)
            }
            
        except Exception as e:
            logger.error(f"URL analysis error: {str(e)}")
            return {
                'url': url,
                'threat_score': 0.5,
                'threat_level': 'UNKNOWN',
                'is_phishing': False,
                'confidence': 0.3,
                'risk_factors': ['Analysis failed'],
                'detected_threats': [],
                'recommendations': ['Manual review required'],
                'error': str(e)
            }
    
    def _analyze_domain(self, domain):
        """Analyze domain for suspicious characteristics"""
        factors = []
        score = 0.0
        threats = []
        
        if not domain:
            return {'factors': ['Invalid domain'], 'score': 0.8, 'threats': []}
        
        # Check for IP address
        try:
            ip_address(domain)
            factors.append('IP address instead of domain')
            score += 0.4
            threats.append({
                'type': 'IP Address Usage',
                'severity': 'High',
                'description': 'Using IP address instead of domain name'
            })
        except AddressValueError:
            pass
        
        # Check suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                factors.append(f'Suspicious TLD: {tld}')
                score += 0.3
                threats.append({
                    'type': 'Suspicious TLD',
                    'severity': 'Medium',
                    'description': f'Domain uses suspicious TLD: {tld}'
                })
                break
        
        # Check for URL shorteners
        for shortener in self.url_shorteners:
            if shortener in domain:
                factors.append('URL shortener detected')
                score += 0.2
                threats.append({
                    'type': 'URL Shortener',
                    'severity': 'Low',
                    'description': 'URL uses shortening service'
                })
                break
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain):
                factors.append('Suspicious domain pattern')
                score += 0.25
                threats.append({
                    'type': 'Suspicious Pattern',
                    'severity': 'Medium',
                    'description': 'Domain contains suspicious character patterns'
                })
                break
        
        # Check for homograph attacks (simplified)
        if self._check_homograph_attack(domain):
            factors.append('Possible homograph attack')
            score += 0.5
            threats.append({
                'type': 'Homograph Attack',
                'severity': 'High',
                'description': 'Domain may be impersonating legitimate site'
            })
        
        # Check domain length
        if len(domain) > 50:
            factors.append('Unusually long domain')
            score += 0.1
        
        # Check for multiple subdomains
        if domain.count('.') > 3:
            factors.append('Multiple subdomains')
            score += 0.15
        
        return {'factors': factors, 'score': score, 'threats': threats}
    
    def _analyze_path(self, path):
        """Analyze URL path for suspicious elements"""
        factors = []
        score = 0.0
        threats = []
        
        if not path or path == '/':
            return {'factors': [], 'score': 0.0, 'threats': []}
        
        # Check for phishing keywords in path
        path_lower = path.lower()
        for keyword in self.phishing_keywords:
            if keyword in path_lower:
                factors.append(f'Phishing keyword in path: {keyword}')
                score += 0.15
                threats.append({
                    'type': 'Phishing Keywords',
                    'severity': 'Medium',
                    'description': f'Path contains phishing keyword: {keyword}'
                })
        
        # Check for suspicious file extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif']
        for ext in suspicious_extensions:
            if path.endswith(ext):
                factors.append(f'Suspicious file extension: {ext}')
                score += 0.4
                threats.append({
                    'type': 'Malicious File',
                    'severity': 'High',
                    'description': f'Path leads to potentially malicious file: {ext}'
                })
        
        # Check for encoded characters
        if '%' in path:
            factors.append('URL encoding detected')
            score += 0.1
        
        # Check for very long paths
        if len(path) > 100:
            factors.append('Unusually long URL path')
            score += 0.1
        
        return {'factors': factors, 'score': score, 'threats': threats}
    
    def _analyze_query_params(self, query):
        """Analyze query parameters for suspicious content"""
        factors = []
        score = 0.0
        threats = []
        
        if not query:
            return {'factors': [], 'score': 0.0, 'threats': []}
        
        params = parse_qs(query)
        
        # Check for redirect parameters
        redirect_params = ['redirect', 'url', 'goto', 'next', 'return']
        for param in redirect_params:
            if param in params:
                factors.append('Redirect parameter detected')
                score += 0.2
                threats.append({
                    'type': 'URL Redirection',
                    'severity': 'Medium',
                    'description': 'URL contains redirect parameters'
                })
                break
        
        # Check for suspicious parameter names
        suspicious_params = ['login', 'password', 'token', 'key', 'auth']
        for param in suspicious_params:
            if param in params:
                factors.append(f'Suspicious parameter: {param}')
                score += 0.15
        
        # Check for base64 encoded data
        for param_values in params.values():
            for value in param_values:
                if len(value) > 20 and self._is_base64(value):
                    factors.append('Base64 encoded data detected')
                    score += 0.1
                    break
        
        return {'factors': factors, 'score': score, 'threats': threats}
    
    def _analyze_url_structure(self, url):
        """Analyze overall URL structure"""
        factors = []
        score = 0.0
        threats = []
        
        # Check URL length
        if len(url) > 200:
            factors.append('Very long URL')
            score += 0.1
        
        # Check for suspicious characters
        if '@' in url:
            factors.append('@ symbol in URL')
            score += 0.3
            threats.append({
                'type': 'URL Obfuscation',
                'severity': 'High',
                'description': 'URL contains @ symbol (possible obfuscation)'
            })
        
        # Check for multiple protocols
        if url.count('://') > 1:
            factors.append('Multiple protocols detected')
            score += 0.4
        
        # Check for suspicious port numbers
        parsed = urlparse(url)
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            factors.append(f'Unusual port number: {parsed.port}')
            score += 0.2
        
        return {'factors': factors, 'score': score, 'threats': threats}
    
    def _check_homograph_attack(self, domain):
        """Check for possible homograph attacks (simplified)"""
        # This is a simplified check - in production, you'd use a comprehensive
        # list of lookalike characters and domains
        suspicious_chars = ['а', 'о', 'р', 'е', 'х', 'у', 'с', 'в', 'н', 'к']
        return any(char in domain for char in suspicious_chars)
    
    def _is_base64(self, s):
        """Check if string is base64 encoded"""
        try:
            import base64
            return base64.b64encode(base64.b64decode(s)).decode() == s
        except:
            return False
    
    def _get_domain_info(self, domain):
        """Get domain information (whois, DNS, etc.)"""
        try:
            # Basic domain info
            info = {
                'domain': domain,
                'registered': False,
                'creation_date': None,
                'expiry_date': None,
                'registrar': None,
                'country': None
            }
            
            # Try to get whois information
            try:
                w = whois.whois(domain)
                if w:
                    info['registered'] = True
                    info['creation_date'] = w.creation_date
                    info['expiry_date'] = w.expiration_date
                    info['registrar'] = w.registrar
                    info['country'] = w.country
            except:
                pass
            
            return info
            
        except Exception as e:
            logger.error(f"Domain info error: {str(e)}")
            return {'domain': domain, 'error': str(e)}
    
    def _generate_recommendations(self, risk_factors, threat_score):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if threat_score >= 0.8:
            recommendations.extend([
                'Block this URL immediately',
                'Report to security team',
                'Do not click or visit this link',
                'Scan system for malware if already visited'
            ])
        elif threat_score >= 0.6:
            recommendations.extend([
                'Exercise extreme caution',
                'Verify URL authenticity through official channels',
                'Do not enter personal information',
                'Use URL scanner tools for verification'
            ])
        elif threat_score >= 0.4:
            recommendations.extend([
                'Proceed with caution',
                'Verify the website\'s legitimacy',
                'Check for HTTPS encryption',
                'Be wary of requests for personal information'
            ])
        elif threat_score >= 0.2:
            recommendations.extend([
                'URL appears suspicious',
                'Verify through official channels if unsure',
                'Monitor for unusual behavior'
            ])
        else:
            recommendations.append('URL appears safe')
        
        # Add specific recommendations based on risk factors
        if 'Non-HTTPS connection' in risk_factors:
            recommendations.append('Avoid entering sensitive information on non-HTTPS sites')
        
        if any('redirect' in factor.lower() for factor in risk_factors):
            recommendations.append('Be cautious of redirect links')
        
        if any('shortener' in factor.lower() for factor in risk_factors):
            recommendations.append('Consider expanding shortened URLs before clicking')
        
        return recommendations