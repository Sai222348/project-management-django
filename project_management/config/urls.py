"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.urls import re_path
from django.contrib.staticfiles.views import serve as staticfiles_serve

handler403 = 'adminpanel.views.error_403'
handler404 = 'adminpanel.views.error_404'
handler500 = 'adminpanel.views.error_500'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('adminpanel.api_urls')),
    path('', include('adminpanel.urls')),
]

# Local-only fallback: serve static files even when DEBUG=False.
# Use a real web server (Nginx/Apache/CDN) for production static delivery.
if not settings.DEBUG:
    urlpatterns += [
        re_path(
            r'^static/(?P<path>.*)$',
            staticfiles_serve,
            {'insecure': True},
        ),
    ]
