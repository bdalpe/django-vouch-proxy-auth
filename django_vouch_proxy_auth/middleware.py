from django.contrib import auth
from django.contrib.auth.middleware import RemoteUserMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.core.cache import caches
import gzip
import base64
import jwt
import requests
import hashlib
from requests import HTTPError


class VouchProxyMiddleware(RemoteUserMiddleware):
    def __init__(self, *args, **kwargs):
        self.cookie_name = getattr(settings, 'VOUCH_PROXY_COOKIE_NAME', 'VouchCookie')
        self.cache_prefix = format(getattr(settings, 'VOUCH_PROXY_CACHE_PREFIX', '{}_'.format(self.cookie_name)))
        self.expiry_time = getattr(settings, 'VOUCH_PROXY_CACHE_TIMEOUT', 300)
        self.cache = caches[getattr(settings, 'VOUCH_PROXY_CACHE_BACKEND', 'default')]
        self.force_logout_if_no_cookie = getattr(settings, 'VOUCH_PROXY_FORCE_LOGOUT_IF_NO_COOKIE', False)
        self.verify_ssl_certificate = getattr(settings, 'VOUCH_PROXY_VERIFY_SSL', True)

        super().__init__(*args, **kwargs)

    def process_request(self, request):
        if request.path in getattr(settings, 'VOUCH_PROXY_DISABLED_PATHS', []):
            return

        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The Django Vouch Proxy auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the VouchProxyMiddleware class.")
        if not hasattr(settings, 'VOUCH_PROXY_VALIDATE_ENDPOINT'):
            raise ImproperlyConfigured(
                "You must provide a valid URL in VOUCH_PROXY_VALIDATE_ENDPOINT"
                " for the Vouch Proxy validation endpoint in your Django settings.")
        try:
            cookie = request.COOKIES[self.cookie_name]

            cache_key = '{}{}'.format(self.cache_prefix, hashlib.sha256(cookie.encode('ascii')).hexdigest())
            username = self.cache.get(cache_key)
            if not username:
                validate = requests.get(settings.VOUCH_PROXY_VALIDATE_ENDPOINT,
                                        cookies={self.cookie_name: cookie},
                                        verify=self.verify_ssl_certificate)
                validate.raise_for_status()

                # Vouch cookie is URL-safe Base64 encoded Gzipped data
                decompressed = gzip.decompress(base64.urlsafe_b64decode(cookie))
                payload = jwt.decode(decompressed, options={'verify_signature': False})
                username = payload['username']
                self.cache.set(cache_key, username, self.expiry_time)
        except (KeyError, HTTPError):
            # If specified header doesn't exist then remove any existing
            # authenticated remote-user, or return (leaving request.user set to
            # AnonymousUser by the AuthenticationMiddleware).
            if self.force_logout_if_no_cookie and request.user.is_authenticated:
                self._remove_invalid_user(request)
            return

        # If the user is already authenticated and that user is the user we are
        # getting passed in the headers, then the correct user is already
        # persisted in the session and we don't need to continue.
        if request.user.is_authenticated:
            if request.user.get_username() == self.clean_username(username, request):
                return
            else:
                # An authenticated user is associated with the request, but
                # it does not match the authorized user in the header.
                self._remove_invalid_user(request)

        # We are seeing this user for the first time in this session, attempt
        # to authenticate the user.
        user = auth.authenticate(request, remote_user=username)
        if user:
            # User is valid.  Set request.user and persist user in the session
            # by logging the user in.
            request.user = user
            auth.login(request, user)
