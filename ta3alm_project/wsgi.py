"""
WSGI config for ta3alm_project project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/wsgi/
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path so all Django apps and packages can be imported
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ta3alm_project.settings')

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
app = application

try:
    from core.mo_compiler import ensure_mo_compiled
    ensure_mo_compiled(BASE_DIR)
except Exception:
    pass


