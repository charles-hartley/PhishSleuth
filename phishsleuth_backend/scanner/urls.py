# scanner/urls.py
from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    # Main dashboard
    path('', views.index, name='index'),
    
    # Analysis endpoints
    path('analyze/text/', views.analyze_text, name='analyze_text'),
    path('analyze/file/', views.analyze_file, name='analyze_file'),
    path('analyze/url/', views.analyze_url, name='analyze_url'),
    
    # Data endpoints - fixed names to match template
    path('history/', views.get_scan_history, name='get_scan_history'),
    path('statistics/', views.get_statistics, name='get_statistics'),
    
    path('api/scan/<int:scan_id>/', views.get_scan_details, name='get_scan_details'),
    
    # Report generation
    path('report/<int:scan_id>/', views.download_report, name='download_report'),
]