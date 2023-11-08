# models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
class UploadedFile(models.Model):
    STATUS_CHOICES = (
        ('CLEAN', 'Clean'),
        ('INFECTED', 'Infected'),
        ('MODIFIED', 'Modified'),
        ('INTEGRITY_CHECK_PASSED', 'Integrity Check Passed'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=23, choices=STATUS_CHOICES, default='CLEAN')
    checksum = models.CharField(max_length=32, blank=True, null=True)
    malware_scan_result = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.file.name
class SuspiciousActivity(models.Model):
    EVENT_CHOICES = [
        ('FILE_UPLOAD', 'File Upload'),
        ('INTEGRITY_CHECK_FAILURE', 'Integrity Check Failure'),
        ('MALWARE_DETECTION', 'Malware Detection'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=30, choices=EVENT_CHOICES)
    details = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def get_event_type_display(self):
        return dict(self.EVENT_CHOICES).get(self.event_type, self.event_type)
