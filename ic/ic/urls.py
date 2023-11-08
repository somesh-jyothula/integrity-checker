# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),

    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('upload/', views.upload_file, name='upload_file'),
    path('check_integrity/<int:file_id>/', views.check_integrity, name='check_integrity'),
    path('check_malware/<int:file_id>/', views.check_malware, name='check_malware'),
    path('success/', views.success, name='success'),
    path('check_url_reputation/', views.check_url_reputation, name='check_url_reputation'),
    path('execute-scan-for-malware/', views.execute_scan_for_malware, name='execute_scan_for_malware'),
    path('scan-report/', views.execute_scan_for_malware, name='scan_report'),
    path('execute-scan-for-malware/', views.execute_scan_for_malware, name='execute_scan_for_malware'),
    path('get-scan-report/<str:scan_id>/', views.get_scan_report, name='get_scan_report'),

]

