from django.contrib.auth.models import User, AnonymousUser
from django.test import TestCase, override_settings, RequestFactory
from django_vouch_proxy_auth.middleware import VouchProxyMiddleware
from django_vouch_proxy_auth.backends import VouchProxyUserBackend
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.core.cache import caches
import time
import hashlib
import jwt
import gzip
import base64
from unittest.mock import Mock, patch
from requests import HTTPError


class MiddlewareTest(TestCase):
    def setUp(self):
        self.middleware = VouchProxyMiddleware()
        self.request = RequestFactory()
        self.user = User.objects.create_user(username='user', email='user@example.net')

    def tearDown(self):
        self.middleware.cache.clear()

    def _build_vouch_cookie_request(self, username):
        vouch_data = {
            "username": username,
            "sites": [
                "localhost",
            ],
            "CustomClaims": {},
            "PAccessToken": "",
            "PIdToken": "",
            "exp": int(time.time()),
            "iss": "Vouch"
        }
        vouch_jwt = jwt.encode(vouch_data, '')
        cookie_data = base64.urlsafe_b64encode(gzip.compress(vouch_jwt.encode('ascii'))).decode('ascii')

        req = self.request.get('/')
        req.user = AnonymousUser()
        req.session = {}
        req.COOKIES['VouchCookie'] = cookie_data

        return req

    @override_settings()
    def test_throws(self):
        del settings.VOUCH_PROXY_VALIDATE_ENDPOINT
        with self.assertRaises(ImproperlyConfigured):
            self.middleware.process_request(Mock())

    def test_cookie_name_setting(self):
        self.assertEqual('VouchCookie', self.middleware.cookie_name)

        cookie = 'Cookies_are_Delicious'
        with self.settings(VOUCH_PROXY_COOKIE_NAME=cookie):
            m = VouchProxyMiddleware()

            self.assertEqual(cookie, m.cookie_name)

    def test_cache_backend_settings(self):
        self.assertEqual(caches['default'], self.middleware.cache)

        with self.settings(VOUCH_PROXY_CACHE_BACKEND='dummy'):
            m = VouchProxyMiddleware()

            self.assertEqual(caches['dummy'], m.cache)
            self.assertNotEqual(caches['default'], m.cache)

    def test_cache_prefix(self):
        self.assertEqual('VouchCookie_', self.middleware.cache_prefix)

        prefix = 'VouchIsAwesome!'
        with self.settings(VOUCH_PROXY_CACHE_PREFIX=prefix):
            m = VouchProxyMiddleware()
            self.assertEqual(prefix, m.cache_prefix)

    def test_cache_timeout_setting(self):
        expiry_time = 300
        self.assertEqual(expiry_time, self.middleware.expiry_time)
        now = int(time.time())
        self.middleware.cache.set('fake', 'fake', expiry_time)
        x = self.middleware.cache._expire_info.get(self.middleware.cache.make_key('fake'))
        self.assertAlmostEqual(now, x - expiry_time, None, None, 1)  # < 1 second delta

        expiry_time = 1
        with self.settings(VOUCH_PROXY_CACHE_TIMEOUT=expiry_time):
            m = VouchProxyMiddleware()
            self.assertEqual(expiry_time, m.expiry_time)
            now = int(time.time())
            m.cache.set('fake', 'fake', expiry_time)
            x = m.cache._expire_info.get(m.cache.make_key('fake'))
            self.assertAlmostEqual(now, x - expiry_time, None, None, 1)  # < 1 second delta

        # Validate immediate expiration
        expiry_time = 0
        with self.settings(VOUCH_PROXY_CACHE_TIMEOUT=expiry_time):
            m = VouchProxyMiddleware()
            self.assertEqual(expiry_time, m.expiry_time)

            m.cache.set('fake', 'fake', expiry_time)
            self.assertIsNone(m.cache.get('fake'))

    def test_disabled_paths(self):
        with self.settings(VOUCH_PROXY_DISABLED_PATHS=['/']):
            m = VouchProxyMiddleware()
            m_request = self.request.get('/')

            m_request.session = {}

            self.assertIsNone(m.process_request(request=m_request))

    @patch('django_vouch_proxy_auth.middleware.requests')
    def test_caching(self, requests_mock):
        req = self._build_vouch_cookie_request(self.user.username)

        requests_mock.get.status_code.return_value = 200

        self.middleware.process_request(request=req)
        self.middleware.process_request(request=req)

        requests_mock.get.assert_called_once_with('http://vouch/validate',
                                                  cookies={'VouchCookie': req.COOKIES[self.middleware.cookie_name]})

    @patch('django_vouch_proxy_auth.middleware.requests')
    def test_caching_disabled(self, requests_mock):
        req = self._build_vouch_cookie_request(self.user.username)

        requests_mock.get.status_code.return_value = 200

        self.middleware.expiry_time = 0

        self.middleware.process_request(request=req)
        requests_mock.get.assert_called_once_with('http://vouch/validate',
                                                  cookies={'VouchCookie': req.COOKIES[self.middleware.cookie_name]})
        requests_mock.get.reset_mock()

        self.middleware.process_request(request=req)
        requests_mock.get.assert_called_once_with('http://vouch/validate',
                                                  cookies={'VouchCookie': req.COOKIES[self.middleware.cookie_name]})

    @patch('django_vouch_proxy_auth.middleware.requests')
    def test_successful_auth(self, requests_mock):
        req = self._build_vouch_cookie_request(self.user.username)

        requests_mock.get.status_code.return_value = 200

        self.middleware.process_request(request=req)
        requests_mock.get.assert_called_once_with('http://vouch/validate',
                                                  cookies={'VouchCookie': req.COOKIES[self.middleware.cookie_name]})

        cache_key = '{}{}'.format(self.middleware.cache_prefix,
                                  hashlib.sha256(req.COOKIES[self.middleware.cookie_name].encode('ascii')).hexdigest())
        self.assertEqual(self.user.username, self.middleware.cache.get(cache_key))

    @patch('django_vouch_proxy_auth.middleware.requests')
    def test_failed_auth(self, requests_mock):
        req = self._build_vouch_cookie_request(self.user.username)

        requests_mock.get.status_code.return_value = 401
        requests_mock.get.side_effect = HTTPError(Mock(status=401), 'Access Denied')

        self.assertIsNone(self.middleware.process_request(request=req))

        cache_key = '{}{}'.format(self.middleware.cache_prefix,
                                  hashlib.sha256(req.COOKIES[self.middleware.cookie_name].encode('ascii')).hexdigest())
        self.assertIsNone(self.middleware.cache.get(cache_key))

    @patch('django_vouch_proxy_auth.middleware.requests')
    @patch('django_vouch_proxy_auth.middleware.VouchProxyMiddleware._remove_invalid_user')
    def test_force_logout_user_clash(self, invalid_user_mock, requests_mock):
        req = self._build_vouch_cookie_request('user2')
        req.user = self.user
        req.session = {'_auth_user_backend': 'django.contrib.auth.backends.ModelBackend'}

        requests_mock.get.status_code.return_value = 200
        self.middleware.process_request(request=req)

        invalid_user_mock.assert_called_once_with(req)

    @patch('django_vouch_proxy_auth.middleware.requests')
    @patch('django_vouch_proxy_auth.middleware.VouchProxyMiddleware._remove_invalid_user')
    def test_force_logout_validate_fail(self, invalid_user_mock, requests_mock):
        self.middleware.force_logout_if_no_cookie = True

        req = self._build_vouch_cookie_request(self.user.username)
        req.user = self.user

        requests_mock.get.status_code.return_value = 401
        requests_mock.get.side_effect = HTTPError(Mock(status=401), 'Access Denied')

        self.middleware.process_request(request=req)

        invalid_user_mock.assert_called_once_with(req)

    @patch('django_vouch_proxy_auth.middleware.requests')
    @patch('django_vouch_proxy_auth.middleware.auth')
    def test_authenticate_backend(self, auth_mock, requests_mock):
        req = self._build_vouch_cookie_request(self.user.username)

        requests_mock.get.status_code.return_value = 200
        auth_mock.authenticate.return_value = self.user

        self.middleware.process_request(request=req)

        auth_mock.authenticate.assert_called_once_with(req, remote_user=self.user.username)
        auth_mock.login.assert_called_once_with(req, self.user)


class BackendTests(TestCase):
    def setUp(self):
        self.backend = VouchProxyUserBackend()
        self.user = User.objects.create_user(username='user', email='user@example.net')
        self.request = RequestFactory()
        self.request.user = AnonymousUser()

    def test_auth(self):
        self.assertEqual(self.user, self.backend.authenticate(request=self.request, remote_user=self.user.username))

    def test_dont_create(self):
        self.backend.create_unknown_user = False
        self.assertIsNone(self.backend.authenticate(request=self.request, remote_user='doesnt_exist'))
