# scanner/utils/phishing_detector.py
import re
import time
import logging
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from transformers import pipeline
import torch

logger = logging.getLogger(__name__)

class PhishingDetector:
    """AI-powered phishing detection system"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.threat_keywords = self._load_threat_keywords()
        self.suspicious_domains = self._load_suspicious_domains()
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize AI models for phishing detection"""
        try:
            # Try to load HuggingFace transformer model
            self.model = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
                device=0 if torch.cuda.is_available() else -1
            )
            logger.info("HuggingFace model loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load HuggingFace model: {e}")
            logger.info("Falling back to traditional ML model")
            self._initialize_fallback_model()
    
    def _initialize_fallback_model(self):
        """Initialize fallback ML model if HuggingFace fails
        upcoming pretrained model
        """
        try:
            # Try to load pre-trained models
            self.model = joblib.load('models/phishing_model.pkl')
            self.vectorizer = joblib.load('models/vectorizer.pkl')
        except FileNotFoundError:
            logger.warning("No pre-trained models found, using rule-based detection")
            self.model = None
            self.vectorizer = None
    
    def _load_threat_keywords(self) -> Dict[str, List[str]]:
        """Load threat keywords by category"""
        return {
            'urgency': [
                'urgent', 'immediate', 'expires', 'suspended', 'locked',
                'verify now', 'act now', 'limited time', 'expires today',
                'deadline', 'final notice', 'last chance'
            ],
            'financial': [
                'refund', 'payment', 'credit card', 'bank account', 'wire transfer',
                'paypal', 'amazon', 'apple', 'microsoft', 'google pay',
                'cryptocurrency', 'bitcoin', 'investment', 'prize', 'lottery'
            ],
            'social': [
                'click here', 'download now', 'free', 'congratulations',
                'winner', 'selected', 'qualified', 'exclusive', 'limited offer',
                'no obligation', 'risk free', 'guarantee'
            ],
            'technical': [
                'virus', 'malware', 'security alert', 'compromised', 'breach',
                'update required', 'patch', 'vulnerability', 'infected',
                'trojan', 'spyware', 'antivirus'
            ],
            'impersonation': [
                'dear customer', 'dear user', 'dear member', 'account holder',
                'from security team', 'from support', 'from admin', 'noreply'
            ]
        }
    
    def _load_suspicious_domains(self) -> List[str]:
        """Load list of suspicious domain patterns"""
        return [
            'bit.ly', 'tinyurl.com', 'shortened.link', 'click.here',
            'secure-update', 'account-verify', 'login-check', 'security-alert',
            'paypal-secure', 'amazon-security', 'apple-support', 'microsoft-update'
        ]
    
    def analyze_text(self, subject: str, body: str) -> Dict[str, Any]:
        """Main analysis function for text content"""
        start_time = time.time()
        
        # Combine subject and body
        full_text = f"{subject}\n{body}".strip()
        
        # Get AI model prediction
        ai_result = self._get_ai_prediction(full_text)
        
        # Get rule-based analysis
        rule_result = self._rule_based_analysis(subject, body)
        
        # Combine results
        final_score = self._combine_scores(ai_result, rule_result)
        
        # Get detailed analysis
        risk_factors = self._identify_risk_factors(subject, body)
        highlighted_phrases = self._highlight_suspicious_phrases(full_text)
        recommendations = self._generate_recommendations(final_score, risk_factors)
        
        processing_time = time.time() - start_time
        
        return {
            'threat_score': final_score,
            'confidence': ai_result.get('confidence', 0.8),
            'is_phishing': final_score > 0.5,
            'threat_level': self._get_threat_level(final_score),
            'risk_factors': risk_factors,
            'highlighted_phrases': highlighted_phrases,
            'recommendations': recommendations,
            'processing_time': processing_time,
            'ai_prediction': ai_result,
            'rule_score': rule_result
        }
    
    def _get_ai_prediction(self, text: str) -> Dict[str, Any]:
        """Get prediction from AI model"""
        if not self.model:
            return {'score': 0.5, 'confidence': 0.6, 'label': 'unknown'}
        
        try:
            if hasattr(self.model, 'predict'):
                #Traditional ML model
                if self.vectorizer:
                    vectorized = self.vectorizer.transform([text])
                    prediction = self.model.predict_proba(vectorized)[0]
                    return {
                        'score': prediction[1],  # Phishing probability
                        'confidence': max(prediction),
                        'label': 'phishing' if prediction[1] > 0.5 else 'legitimate'
                    }
            else:
                #HuggingFace model
                labels = ['phishing email', 'legitimate email', 'spam email']
                result = self.model(text, candidate_labels=labels)
                
                phishing_score = 0
                for i, label in enumerate(result['labels']):
                    if 'phishing' in label.lower():
                        phishing_score = result['scores'][i]
                        break
                
                return {
                    'score': phishing_score,
                    'confidence': result['scores'][0],
                    'label': result['labels'][0]
                }
        except Exception as e:
            logger.error(f"AI prediction failed: {e}")
            return {'score': 0.5, 'confidence': 0.3, 'label': 'error'}
    
    def _rule_based_analysis(self, subject: str, body: str) -> float:
        """Rule-based phishing detection"""
        score = 0.0
        text = f"{subject} {body}".lower()
        
        # Check for urgency indicators
        urgency_count = sum(1 for keyword in self.threat_keywords['urgency'] 
                           if keyword in text)
        score += min(urgency_count * 0.15, 0.3)
        
        # Check for financial keywords
        financial_count = sum(1 for keyword in self.threat_keywords['financial'] 
                             if keyword in text)
        score += min(financial_count * 0.1, 0.25)
        
        # Check for social engineering
        social_count = sum(1 for keyword in self.threat_keywords['social'] 
                          if keyword in text)
        score += min(social_count * 0.08, 0.2)
        
        # Check for technical threats
        tech_count = sum(1 for keyword in self.threat_keywords['technical'] 
                        if keyword in text)
        score += min(tech_count * 0.12, 0.25)
        
        # Check for suspicious URLs
        url_score = self._analyze_urls(body)
        score += url_score
        
        # Check for domain spoofing
        domain_score = self._check_domain_spoofing(text)
        score += domain_score
        
        return min(score, 1.0)
    
    def _analyze_urls(self, text: str) -> float:
        """Analyze URLs in the text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        if not urls:
            return 0.0
        
        score = 0.0
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for suspicious domain patterns
                for suspicious in self.suspicious_domains:
                    if suspicious in domain:
                        score += 0.3
                        break
                
                # Check for URL shorteners
                if any(short in domain for short in ['bit.ly', 'tinyurl', 't.co']):
                    score += 0.2
                
                # Check for suspicious TLDs
                if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf']):
                    score += 0.15
                
                # Check for IP addresses instead of domains
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    score += 0.25
                
            except Exception:
                continue
        
        return min(score, 0.4)
    
    def _check_domain_spoofing(self, text: str) -> float:
        """Check for domain spoofing attempts"""
        #Common spoofed domains
        legitimate_domains = [
            'amazon.com', 'paypal.com', 'apple.com', 'microsoft.com',
            'google.com', 'facebook.com', 'ebay.com', 'netflix.com'
        ]
        
        score = 0.0
        for domain in legitimate_domains:
            #Look for common spoofing patterns
            spoofed_patterns = [
                domain.replace('.', '-'),
                domain.replace('.', ''),
                domain.replace('o', '0'),
                domain.replace('e', '3'),
                domain + '.security',
                domain + '.verify'
            ]
            
            for pattern in spoofed_patterns:
                if pattern in text:
                    score += 0.3
                    break
        
        return min(score, 0.4)
    
    def _combine_scores(self, ai_result: Dict, rule_score: float) -> float:
        """Combine AI and rule-based scores"""
        ai_score = ai_result.get('score', 0.5)
        ai_confidence = ai_result.get('confidence', 0.5)
        
        #Weight the scores based on confidence
        if ai_confidence > 0.8:
            #High confidence AI prediction
            combined = ai_score * 0.7 + rule_score * 0.3
        elif ai_confidence > 0.6:
            #Medium confidence
            combined = ai_score * 0.6 + rule_score * 0.4
        else:
            #Low confidence, rely more on rules
            combined = ai_score * 0.4 + rule_score * 0.6
        
        return min(combined, 1.0)
    
    def _identify_risk_factors(self, subject: str, body: str) -> List[str]:
        """Identify specific risk factors"""
        risk_factors = []
        text = f"{subject} {body}".lower()
        
        #Check each category
        for category, keywords in self.threat_keywords.items():
            if any(keyword in text for keyword in keywords):
                risk_factors.append(category)
        
        #Check for URLs
        if re.search(r'https?://', body):
            risk_factors.append('suspicious_links')
        
        #Check for attachments mention
        if any(word in text for word in ['attachment', 'download', 'file']):
            risk_factors.append('attachment_request')
        
        return risk_factors
    
    def _highlight_suspicious_phrases(self, text: str) -> List[Dict[str, Any]]:
        """Highlight suspicious phrases in the text"""
        highlighted = []
        
        for category, keywords in self.threat_keywords.items():
            for keyword in keywords:
                if keyword in text.lower():
                    highlighted.append({
                        'phrase': keyword,
                        'category': category,
                        'risk_level': self._get_phrase_risk_level(category)
                    })
        
        return highlighted
    
    def _get_phrase_risk_level(self, category: str) -> str:
        """Get risk level for a phrase category"""
        risk_levels = {
            'urgency': 'high',
            'financial': 'critical',
            'social': 'medium',
            'technical': 'high',
            'impersonation': 'medium'
        }
        return risk_levels.get(category, 'low')
    
    def _generate_recommendations(self, score: float, risk_factors: List[str]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if score > 0.8:
            recommendations.extend([
                "Delete this email immediately",
                "Do not click any links or download attachments",
                "Report to your IT security team",
                "Block the sender's email address"
            ])
        elif score > 0.6:
            recommendations.extend([
                "Exercise extreme caution with this email",
                "Verify sender through alternative means",
                "Do not provide any personal information"
            ])
        elif score > 0.4:
            recommendations.extend([
                "Review email carefully before taking action",
                "Verify any requests independently"
            ])
        
        # Add specific recommendations based on risk factors
        if 'financial' in risk_factors:
            recommendations.append("Never provide financial information via email")
        
        if 'suspicious_links' in risk_factors:
            recommendations.append("Hover over links to verify destinations")
        
        if 'urgency' in risk_factors:
            recommendations.append("Ignore artificial urgency - legitimate companies don't rush")
        
        return recommendations
    
    def _get_threat_level(self, score: float) -> str:
        """Convert score to threat level"""
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'safe'
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a suspicious URL"""
        start_time = time.time()
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            score = 0.0
            risk_factors = []
            
            # Domain analysis
            if any(suspicious in domain for suspicious in self.suspicious_domains):
                score += 0.4
                risk_factors.append('suspicious_domain')
            
            # URL shortener check
            if any(short in domain for short in ['bit.ly', 'tinyurl', 't.co']):
                score += 0.3
                risk_factors.append('url_shortener')
            
            # IP address check
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                score += 0.5
                risk_factors.append('ip_address')
            
            # Suspicious TLD
            if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf']):
                score += 0.3
                risk_factors.append('suspicious_tld')
            
            processing_time = time.time() - start_time
            
            return {
                'threat_score': min(score, 1.0),
                'confidence': 0.8,
                'is_phishing': score > 0.5,
                'threat_level': self._get_threat_level(score),
                'risk_factors': risk_factors,
                'domain': domain,
                'processing_time': processing_time
            }
            
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            return {
                'threat_score': 0.5,
                'confidence': 0.3,
                'is_phishing': False,
                'threat_level': 'unknown',
                'risk_factors': ['analysis_error'],
                'processing_time': time.time() - start_time
            }

# Global detector instance
detector = PhishingDetector()