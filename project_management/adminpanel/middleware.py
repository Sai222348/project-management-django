from django.conf import settings


class StaticAssetCacheControlMiddleware:
    """Adds Cache-Control for local static asset responses."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith('/static/'):
            cache_seconds = getattr(settings, 'STATIC_CACHE_SECONDS', 604800)
            response.setdefault('Cache-Control', f'public, max-age={cache_seconds}')
        return response

