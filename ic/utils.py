# utils.py
import hashlib
import pyclamd
from django.core.exceptions import ValidationError

def calculate_file_checksum(file_content):
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file_content.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

