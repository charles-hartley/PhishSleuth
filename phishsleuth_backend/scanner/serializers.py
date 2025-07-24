# scanner/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import ThreatAnalysis, ThreatPattern, SuspiciousDomain, AnalysisStatistics
import re


class ThreatAnalysisInputSerializer(serializers.Serializer):
    """Serializer for threat analysis input - think of it as the 'order form' for analysis"""
    
    # Analysis type determines what we're analyzing
    analysis_type = serializers.ChoiceField(
        choices=['email', 'url', 'file'],
        default='email'
    )
    
    # Email analysis fields
    subject = serializers.CharField(max_length=500, required=False, allow_blank=True)
    content = serializers.CharField(max_length=10000, required=False, allow_blank=True)
    
    # URL analysis field
    url = serializers.URLField(required=False, allow_blank=True)
    
    # File analysis field
    file_content = serializers.CharField(max_length=50000, required=False, allow_blank=True)
    file_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    
    # Analysis options
    return_highlights = serializers.BooleanField(default=True)
    return_recommendations = serializers.BooleanField(default=True)
    detailed_analysis = serializers.BooleanField(default=False)
    
    def validate(self, data):
        """Validate that we have the right data for the analysis type"""
        analysis_type = data.get('analysis_type', 'email')
        
        if analysis_type == 'email':
            if not data.get('content') and not data.get('subject'):
                raise serializers.ValidationError(
                    "Email analysis requires either subject or content"
                )
        elif analysis_type == 'url':
            if not data.get('url'):
                raise serializers.ValidationError(
                    "URL analysis requires a URL"
                )
        elif analysis_type == 'file':
            if not data.get('file_content'):
                raise serializers.ValidationError(
                    "File analysis requires file content"
                )
        
        return data
    
    def validate_url(self, value):
        """Validate URL format"""
        if value:
            # Basic URL validation beyond Django's URLField
            if not re.match(r'^https?://', value):
                raise serializers.ValidationError(
                    "URL must start with http:// or https://"
                )
        return value


class HighlightedPhraseSerializer(serializers.Serializer):
    """Serializer for highlighted phrases in the analysis"""
    phrase = serializers.CharField()
    category = serializers.CharField()
    risk_level = serializers.CharField()
    position = serializers.IntegerField(required=False)


class ThreatAnalysisResultSerializer(serializers.ModelSerializer):
    """Serializer for threat analysis results - the 'report' we send back"""
    
    highlighted_phrases = HighlightedPhraseSerializer(many=True, read_only=True)
    duration = serializers.ReadOnlyField()
    is_high_risk = serializers.ReadOnlyField()
    
    class Meta:
        model = ThreatAnalysis
        fields = [
            'id', 'analysis_type', 'status', 'created_at', 'completed_at',
            'threat_score', 'confidence', 'threat_level', 'is_phishing',
            'is_high_risk', 'processing_time', 'duration', 'ai_model_used',
            'risk_factors', 'highlighted_phrases', 'recommendations',
            'ai_prediction'
        ]
        read_only_fields = ['id', 'created_at', 'completed_at', 'status']


class ThreatAnalysisHistorySerializer(serializers.ModelSerializer):
    """Serializer for threat analysis history - simplified view"""
    
    source = serializers.SerializerMethodField()
    timestamp = serializers.DateTimeField(source='created_at', format='%Y-%m-%d %H:%M:%S')
    
    class Meta:
        model = ThreatAnalysis
        fields = [
            'id', 'timestamp', 'source', 'analysis_type', 'threat_score',
            'threat_level', 'is_phishing', 'status'
        ]
    
    def get_source(self, obj):
        """Get a readable source identifier"""
        if obj.analysis_type == 'email':
            if obj.subject:
                return obj.subject[:50] + ('...' if len(obj.subject) > 50 else '')
            return 'Email content'
        elif obj.analysis_type == 'url':
            return obj.url
        elif obj.analysis_type == 'file':
            return obj.file_name or 'Uploaded file'
        return 'Unknown'


class StatisticsSerializer(serializers.ModelSerializer):
    """Serializer for platform statistics"""
    
    class Meta:
        model = AnalysisStatistics
        fields = '__all__'


class UserStatsSerializer(serializers.Serializer):
    """Serializer for user-specific statistics"""
    
    total_analyses = serializers.IntegerField()
    threats_detected = serializers.IntegerField()
    avg_threat_score = serializers.FloatField()
    most_common_threat_type = serializers.CharField()
    analyses_today = serializers.IntegerField()
    threat_trend = serializers.CharField()  # 'increasing', 'decreasing', 'stable'


class BulkAnalysisSerializer(serializers.Serializer):
    """Serializer for bulk analysis requests"""
    
    analyses = ThreatAnalysisInputSerializer(many=True, max_length=100)
    
    def validate_analyses(self, value):
        """Validate bulk analysis limit"""
        if len(value) > 100:
            raise serializers.ValidationError(
                "Maximum 100 analyses per bulk request"
            )
        return value


class APIKeySerializer(serializers.Serializer):
    """Serializer for API key requests"""
    
    description = serializers.CharField(max_length=255, required=False)
    rate_limit = serializers.IntegerField(min_value=100, max_value=10000, default=1000)


class ThreatKeywordSerializer(serializers.ModelSerializer):
    """Serializer for threat keywords management"""
    
    class Meta:
        model = ThreatPattern
        fields = '__all__'
        read_only_fields = ['created_at']


class SuspiciousDomainSerializer(serializers.ModelSerializer):
    """Serializer for suspicious domains management"""
    
    class Meta:
        model = SuspiciousDomain
        fields = '__all__'
        read_only_fields = ['added_at', 'last_seen']


class AnalysisExportSerializer(serializers.Serializer):
    """Serializer for exporting analysis data"""
    
    date_from = serializers.DateField()
    date_to = serializers.DateField()
    format = serializers.ChoiceField(choices=['csv', 'json', 'pdf'], default='csv')
    include_details = serializers.BooleanField(default=False)
    
    def validate(self, data):
        """Validate date range"""
        if data['date_from'] > data['date_to']:
            raise serializers.ValidationError(
                "date_from must be before date_to"
            )
        
        # Limit export range to 1 year
        from datetime import timedelta
        if (data['date_to'] - data['date_from']) > timedelta(days=365):
            raise serializers.ValidationError(
                "Export range cannot exceed 1 year"
            )
        
        return data


class QuickAnalysisSerializer(serializers.Serializer):
    """Serializer for quick analysis (no storage)"""
    
    text = serializers.CharField(max_length=5000)
    analysis_type = serializers.ChoiceField(
        choices=['email', 'url', 'text'],
        default='text'
    )
    
    def validate_text(self, value):
        """Basic text validation"""
        if not value.strip():
            raise serializers.ValidationError("Text cannot be empty")
        return value.strip()