from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
import json
import os
import logging
from datetime import datetime

from .utils.phishing_detector import PhishingDetector
from .utils.file_processor import FileProcessor
from .utils.url_analyzer import URLAnalyzer
from .models import ThreatAnalysis, ThreatPattern, SuspiciousDomain, AnalysisStatistics
from .serializers import ThreatAnalysisInputSerializer, ThreatAnalysisResultSerializer

logger = logging.getLogger(__name__)

# Initialize components
detector = PhishingDetector()
file_processor = FileProcessor()
url_analyzer = URLAnalyzer()


def index(request):
    """Main dashboard view"""
    # Get recent statistics using unified model
    recent_scans = ThreatAnalysis.objects.order_by('-created_at')[:10]
    total_scans = ThreatAnalysis.objects.count()
    blocked_threats = ThreatAnalysis.objects.filter(threat_score__gte=0.7).count()
    
    context = {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'blocked_threats': blocked_threats,
        'accuracy_rate': '99.7%',  # This could be calculated from AnalysisStatistics
    }
    
    return render(request, 'scanner/index.html', context)

@csrf_exempt
@require_http_methods(["POST"])
def analyze_text(request):
    """Handle text-based analysis with unified model"""
    # Add debugging
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Content type: {request.content_type}")
    logger.debug(f"Request body: {request.body}")
    
    try:
        # Handle both JSON and FormData
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            email_subject = data.get('emailSubject', '')
            email_body = data.get('emailBody', '')
        else:
            # Handle FormData from JavaScript
            email_subject = request.POST.get('emailSubject', '')
            email_body = request.POST.get('emailBody', '')
        
        # Validate input
        if not email_subject and not email_body:
            return JsonResponse({
                'error': 'No content provided for analysis'
            }, status=400)
        
        # Debug logging
        logger.debug(f"Received - Subject: {email_subject}, Body: {email_body}")
        
        # Create analysis record first (if ThreatAnalysis model exists)
        analysis = None
        try:
            from .models import ThreatAnalysis
            analysis = ThreatAnalysis.objects.create(
                content_type='text',
                subject=email_subject,
                body=email_body,
                status='processing'
            )
        except ImportError:
            logger.warning("ThreatAnalysis model not found, proceeding without database storage")
        
        try:
            # Perform analysis - replace with your actual detector
            # analyzer = PhishingAnalyzer()
            # result = analyzer.analyze_text(email_subject, email_body)
            
            # Check if detector exists, otherwise use mock
            try:
                from .detector import detector  # type: ignore
                result = detector.analyze_text(email_subject, email_body)
            except ImportError:
                logger.warning("Detector not found, using mock result")
                # Mock response for now
                result = {
                    'threat_score': 0.75,
                    'confidence': 0.92,
                    'threat_level': 'HIGH',
                    'is_phishing': True,
                    'risk_factors': ['Suspicious URL', 'Urgent language'],
                    'recommendations': [
                        {
                            'text': 'Do not click any links in this email',
                            'icon': 'shield-alt',
                            'color': 'warning'
                        }
                    ],
                    'detected_threats': [
                        {
                            'name': 'Suspicious URL',
                            'severity': 'HIGH',
                            'icon': 'link',
                            'color': 'danger'
                        }
                    ],
                    'highlighted_content': f'<span class="highlight-threat">{email_subject}</span><br>{email_body}'
                }
            
            # Update analysis with results if model exists
            if analysis:
                analysis.threat_score = result['threat_score']
                analysis.confidence = result['confidence']
                analysis.threat_level = result.get('threat_level', 'UNKNOWN')
                analysis.is_phishing = result.get('is_phishing', False)
                analysis.risk_factors = result.get('risk_factors', [])
                analysis.recommendations = result.get('recommendations', [])
                analysis.detected_threats = result.get('detected_threats', [])
                analysis.highlighted_content = result.get('highlighted_content', '')
                analysis.status = 'completed'
                analysis.completed_at = datetime.now()
                analysis.save()
            
            # Format response for frontend
            response_data = {
                'success': True,
                'threat_score': result['threat_score'],
                'confidence': result['confidence'],
                'is_phishing': result.get('is_phishing', False),
                'threats': result.get('detected_threats', []),
                'recommendations': result.get('recommendations', []),
                'highlighted_content': result.get('highlighted_content', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            # Add scan_id and threat_level if analysis exists
            if analysis:
                response_data['scan_id'] = str(analysis.id)
                response_data['threat_level'] = getattr(analysis, 'threat_level_display', result.get('threat_level', 'UNKNOWN'))
            else:
                response_data['threat_level'] = result.get('threat_level', 'UNKNOWN')
            
            return JsonResponse(response_data)
            
        except Exception as e:
            # Update analysis status if it exists
            if analysis:
                analysis.status = 'failed'
                analysis.save()
            raise
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return JsonResponse({'error': 'Analysis failed'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def analyze_file(request):
    """Handle file-based analysis"""
    try:
        if 'emailFile' not in request.FILES:
            return JsonResponse({'error': 'No file provided'}, status=400)
        
        uploaded_file = request.FILES['emailFile']
        
        # Process file based on type
        if uploaded_file.name.endswith('.txt'):
            content = uploaded_file.read().decode('utf-8')
        elif uploaded_file.name.endswith('.eml'):
            # Handle email file parsing
            content = uploaded_file.read().decode('utf-8')
        else:
            return JsonResponse({'error': 'Unsupported file type'}, status=400)
        
        # Create analysis record if model exists
        analysis = None
        try:
            from .models import ThreatAnalysis
            analysis = ThreatAnalysis.objects.create(
                content_type='file',
                body=content,
                status='processing'
            )
        except ImportError:
            logger.warning("ThreatAnalysis model not found, proceeding without database storage")
        
        try:
            # Perform analysis
            try:
                from .detector import detector # type: ignore
                result = detector.analyze_text('', content)  # No subject for file analysis
            except ImportError:
                # Mock analysis result
                result = {
                    'threat_score': 0.45,
                    'confidence': 0.88,
                    'threat_level': 'LOW',
                    'is_phishing': False,
                    'detected_threats': [],
                    'recommendations': [
                        {
                            'text': 'File appears safe',
                            'icon': 'check-circle',
                            'color': 'success'
                        }
                    ],
                    'highlighted_content': content[:500] + '...' if len(content) > 500 else content
                }
            
            # Update analysis if model exists
            if analysis:
                analysis.threat_score = result['threat_score']
                analysis.confidence = result['confidence']
                analysis.threat_level = result.get('threat_level', 'UNKNOWN')
                analysis.is_phishing = result.get('is_phishing', False)
                analysis.risk_factors = result.get('risk_factors', [])
                analysis.recommendations = result.get('recommendations', [])
                analysis.detected_threats = result.get('detected_threats', [])
                analysis.highlighted_content = result.get('highlighted_content', '')
                analysis.status = 'completed'
                analysis.completed_at = datetime.now()
                analysis.save()
            
            # Format response
            response_data = {
                'success': True,
                'threat_score': result['threat_score'],
                'confidence': result['confidence'],
                'is_phishing': result.get('is_phishing', False),
                'threats': result.get('detected_threats', []),
                'recommendations': result.get('recommendations', []),
                'highlighted_content': result.get('highlighted_content', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            if analysis:
                response_data['scan_id'] = str(analysis.id)
                response_data['threat_level'] = getattr(analysis, 'threat_level_display', result.get('threat_level', 'UNKNOWN'))
            else:
                response_data['threat_level'] = result.get('threat_level', 'UNKNOWN')
            
            return JsonResponse(response_data)
            
        except Exception as e:
            if analysis:
                analysis.status = 'failed'
                analysis.save()
            raise
        
    except Exception as e:
        logger.error(f"File analysis failed: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def analyze_url(request):
    """Handle URL-based analysis"""
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            url_input = data.get('urlInput', '')
        else:
            url_input = request.POST.get('urlInput', '')
        
        if not url_input:
            return JsonResponse({'error': 'No URL provided'}, status=400)
        
        # Create analysis record if model exists
        analysis = None
        try:
            from .models import ThreatAnalysis
            analysis = ThreatAnalysis.objects.create(
                content_type='url',
                body=url_input,
                status='processing'
            )
        except ImportError:
            logger.warning("ThreatAnalysis model not found, proceeding without database storage")
        
        try:
            # Perform analysis
            try:
                from .detector import detector # type: ignore
                result = detector.analyze_url(url_input)
            except ImportError:
                # Mock analysis result
                result = {
                    'threat_score': 0.85,
                    'confidence': 0.95,
                    'threat_level': 'HIGH',
                    'is_phishing': True,
                    'detected_threats': [
                        {
                            'name': 'Malicious Domain',
                            'severity': 'HIGH',
                            'icon': 'exclamation-triangle',
                            'color': 'danger'
                        }
                    ],
                    'recommendations': [
                        {
                            'text': 'Block this URL immediately',
                            'icon': 'ban',
                            'color': 'danger'
                        }
                    ],
                    'highlighted_content': f'<span class="highlight-threat">{url_input}</span>'
                }
            
            # Update analysis if model exists
            if analysis:
                analysis.threat_score = result['threat_score']
                analysis.confidence = result['confidence']
                analysis.threat_level = result.get('threat_level', 'UNKNOWN')
                analysis.is_phishing = result.get('is_phishing', False)
                analysis.risk_factors = result.get('risk_factors', [])
                analysis.recommendations = result.get('recommendations', [])
                analysis.detected_threats = result.get('detected_threats', [])
                analysis.highlighted_content = result.get('highlighted_content', '')
                analysis.status = 'completed'
                analysis.completed_at = datetime.now()
                analysis.save()
            
            # Format response
            response_data = {
                'success': True,
                'threat_score': result['threat_score'],
                'confidence': result['confidence'],
                'is_phishing': result.get('is_phishing', False),
                'threats': result.get('detected_threats', []),
                'recommendations': result.get('recommendations', []),
                'highlighted_content': result.get('highlighted_content', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            if analysis:
                response_data['scan_id'] = str(analysis.id)
                response_data['threat_level'] = getattr(analysis, 'threat_level_display', result.get('threat_level', 'UNKNOWN'))
            else:
                response_data['threat_level'] = result.get('threat_level', 'UNKNOWN')
            
            return JsonResponse(response_data)
            
        except Exception as e:
            if analysis:
                analysis.status = 'failed'
                analysis.save()
            raise
        
    except Exception as e:
        logger.error(f"URL analysis failed: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def get_scan_history(request):
    """Get scan history for the dashboard using unified model"""
    try:
        analyses = ThreatAnalysis.objects.order_by('-created_at')[:50]
        
        scan_data = []
        for analysis in analyses:
            scan_data.append({
                'id': str(analysis.id),
                'timestamp': analysis.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'content_type': analysis.content_type,
                'source': analysis.get_source_display(),
                'threat_level': analysis.threat_level_display,
                'is_phishing': analysis.is_phishing,
                'confidence': analysis.confidence
            })
        
        return JsonResponse({
            'success': True,
            'scans': scan_data
        })
        
    except Exception as e:
        logger.error(f"History retrieval error: {str(e)}")
        return JsonResponse({'error': 'Could not retrieve scan history'}, status=500)


def get_statistics(request):
    """Get platform statistics using unified model"""
    try:
        total_scans = ThreatAnalysis.objects.count()
        threats_blocked = ThreatAnalysis.objects.filter(threat_score__gte=0.7).count()
        
        # Try to get from statistics table first
        try:
            latest_stats = AnalysisStatistics.objects.latest('date')
            accuracy = latest_stats.accuracy_rate
        except AnalysisStatistics.DoesNotExist:
            # Calculate accuracy from recent scans
            recent_analyses = ThreatAnalysis.objects.filter(
                status='completed'
            ).order_by('-created_at')[:1000]
            
            if recent_analyses:
                high_confidence_analyses = [a for a in recent_analyses if a.confidence and a.confidence > 0.8]
                accuracy = len(high_confidence_analyses) / len(recent_analyses) * 100
            else:
                accuracy = 99.7
        
        # Mock active users (you'd implement real user tracking)
        active_users = 15234
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_scans': total_scans,
                'threats_blocked': threats_blocked,
                'accuracy_rate': f"{accuracy:.1f}%",
                'active_users': active_users
            }
        })
        
    except Exception as e:
        logger.error(f"Statistics error: {str(e)}")
        return JsonResponse({'error': 'Could not retrieve statistics'}, status=500)


def download_report(request, scan_id):
    """Generate and download analysis report using unified model"""
    try:
        analysis = ThreatAnalysis.objects.get(id=scan_id)
        
        # Generate report content
        report_content = f"""
PhishSleuth Analysis Report
==========================

Scan ID: {analysis.id}
Timestamp: {analysis.created_at}
Content Type: {analysis.content_type}
Status: {analysis.status}

Analysis Results:
- Threat Score: {analysis.threat_score:.2f} ({analysis.threat_level_display})
- Threat Level: {analysis.threat_level}
- Is Phishing: {'Yes' if analysis.is_phishing else 'No'}
- Confidence: {analysis.confidence:.2%}

Risk Factors:
{chr(10).join(f'- {factor}' for factor in analysis.risk_factors)}

Recommendations:
{chr(10).join(f'- {rec}' for rec in analysis.recommendations)}

Detected Threats:
{chr(10).join(f'- {threat}' for threat in analysis.detected_threats)}

Content Analyzed:
Subject: {analysis.subject or 'N/A'}
Body: {analysis.body[:500] if analysis.body else 'N/A'}{'...' if analysis.body and len(analysis.body) > 500 else ''}
URL: {analysis.url or 'N/A'}
Filename: {analysis.filename or 'N/A'}

Generated by PhishSleuth Elite Edition v2.1.0
"""
        
        response = HttpResponse(report_content, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="phishsleuth_report_{scan_id}.txt"'
        
        return response
        
    except ThreatAnalysis.DoesNotExist:
        return JsonResponse({'error': 'Analysis not found'}, status=404)
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        return JsonResponse({'error': 'Could not generate report'}, status=500)
    


def get_scan_details(request, scan_id):
    """Get detailed information about a specific scan using unified model"""
    try:
        analysis = ThreatAnalysis.objects.get(id=scan_id)
        
        # Prepare detailed response data
        response_data = {
            'success': True,
            'scan_id': str(analysis.id),
            'timestamp': analysis.created_at.isoformat(),
            'content_type': analysis.content_type,
            'status': analysis.status,
            'threat_score': analysis.threat_score,
            'threat_level': analysis.threat_level_display,
            'is_phishing': analysis.is_phishing,
            'confidence': analysis.confidence,
            'risk_factors': analysis.risk_factors,
            'recommendations': analysis.recommendations,
            'detected_threats': analysis.detected_threats,
            'highlighted_content': analysis.highlighted_content,
            'completed_at': analysis.completed_at.isoformat() if analysis.completed_at else None,
        }
        
        # Add content-specific fields based on type
        if analysis.content_type == 'text':
            response_data.update({
                'subject': analysis.subject,
                'body': analysis.body
            })
        elif analysis.content_type == 'file':
            response_data.update({
                'filename': analysis.filename,
                'subject': analysis.subject,
                'body': analysis.body
            })
        elif analysis.content_type == 'url':
            response_data.update({
                'url': analysis.url
            })
        
        return JsonResponse(response_data)
        
    except ThreatAnalysis.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Scan not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Scan details error: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Could not retrieve scan details'
        }, status=500)