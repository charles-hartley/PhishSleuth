from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
import json


class ThreatAnalysis(models.Model):
    """Core domain entity representing a threat analysis"""
    
    THREAT_LEVELS = [
        ('safe', 'Safe'),
        ('low', 'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high', 'High Risk'),
        ('critical', 'Critical Risk'),
    ]
    
    CONTENT_TYPES = [
        ('text', 'Text/Email Content'),
        ('url', 'URL Analysis'),
        ('file', 'File Upload'),
    ]
    
    ANALYSIS_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    # Core identifiers
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='threat_analyses', null=True, blank=True)
    
    # Analysis metadata
    content_type = models.CharField(max_length=20, choices=CONTENT_TYPES)
    status = models.CharField(max_length=20, choices=ANALYSIS_STATUS, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Input data - unified fields
    subject = models.CharField(max_length=500, blank=True)
    body = models.TextField(blank=True)  # Using 'body' to match views
    url = models.URLField(blank=True)
    filename = models.CharField(max_length=255, blank=True)
    
    # Analysis results - unified naming
    threat_score = models.FloatField(null=True, blank=True)  # 0.0 to 1.0
    confidence = models.FloatField(null=True, blank=True)    # 0.0 to 1.0
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVELS, blank=True)
    is_phishing = models.BooleanField(default=False)
    
    # Processing metadata
    processing_time = models.FloatField(null=True, blank=True)
    ai_model_used = models.CharField(max_length=100, blank=True)
    
    # Detailed results (JSON fields)
    risk_factors = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    detected_threats = models.JSONField(default=list, blank=True)
    highlighted_content = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['threat_level', '-created_at']),
            models.Index(fields=['content_type', '-created_at']),
        ]
    
    def __str__(self):
        return f"Analysis {self.id} - {self.threat_level} ({self.content_type})"
    
    @property
    def is_high_risk(self):
        return self.threat_level in ['high', 'critical']
    
    @property
    def duration(self):
        if self.completed_at and self.created_at:
            return (self.completed_at - self.created_at).total_seconds()
        return None
    
    @property
    def threat_level_display(self):
        """Display threat level as percentage for UI compatibility"""
        if self.threat_score is not None:
            return f"{self.threat_score:.0%}"
        return "Unknown"
    
    def get_source_display(self):
        """Get display name for the source"""
        if self.content_type == 'text':
            return self.subject[:50] + ('...' if len(self.subject) > 50 else '') if self.subject else 'Email content'
        elif self.content_type == 'url':
            return self.url
        elif self.content_type == 'file':
            return self.filename or 'Uploaded file'
        return 'Unknown'


class ThreatPattern(models.Model):
    """Pattern definitions for threat detection"""
    
    PATTERN_CATEGORIES = [
        ('urgency', 'Urgency Indicators'),
        ('financial', 'Financial Terms'),
        ('social', 'Social Engineering'),
        ('technical', 'Technical Threats'),
        ('impersonation', 'Impersonation'),
    ]
    
    name = models.CharField(max_length=100)
    pattern = models.CharField(max_length=200)  # regex pattern or keyword
    category = models.CharField(max_length=20, choices=PATTERN_CATEGORIES)
    weight = models.FloatField(default=1.0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['category', 'name']
        unique_together = ['name', 'pattern']
    
    def __str__(self):
        return f"{self.name} ({self.category})"


class SuspiciousDomain(models.Model):
    """Domains flagged as suspicious"""
    
    DOMAIN_TYPES = [
        ('shortener', 'URL Shortener'),
        ('spoofed', 'Spoofed Domain'),
        ('malicious', 'Known Malicious'),
        ('suspicious', 'Suspicious Pattern'),
    ]
    
    domain = models.CharField(max_length=255, unique=True)
    domain_type = models.CharField(max_length=20, choices=DOMAIN_TYPES)
    risk_score = models.FloatField(default=0.5)
    is_active = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-risk_score', 'domain']
    
    def __str__(self):
        return f"{self.domain} ({self.domain_type})"


class AnalysisStatistics(models.Model):
    """Daily statistics for the platform"""
    
    date = models.DateField(unique=True)
    total_scans = models.IntegerField(default=0)
    threats_blocked = models.IntegerField(default=0)
    false_positives = models.IntegerField(default=0)
    processing_time_avg = models.FloatField(default=0.0)
    accuracy_rate = models.FloatField(default=0.0)
    
    class Meta:
        ordering = ['-date']
    
    def __str__(self):
        return f"Stats for {self.date}"


class UserAPIKey(models.Model):
    """API keys for users"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='api_key')
    key = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    usage_count = models.IntegerField(default=0)
    rate_limit = models.IntegerField(default=1000)  # requests per hour
    
    def __str__(self):
        return f"API Key for {self.user.username}"
    
    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        super().save(*args, **kwargs)
    
    def generate_key(self):
        import secrets
        return secrets.token_urlsafe(48)


# Alias for backward compatibility with existing views
ScanHistory = ThreatAnalysis