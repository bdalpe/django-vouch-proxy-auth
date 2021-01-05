# django-vouch-proxy-auth
Django Middleware enabling the use of the [Vouch Proxy](https://github.com/vouch/vouch-proxy) cookie for single sign-on.

This package subclasses Django's `RemoteUserMiddleware` and `RemoteUserBackend`.

## How it Works

1. The middleware checks for the presence of the Vouch Proxy cookie.
2. If the cookie exists, it attempts to load a previous validation from Django cache.
3. If the validation result is not in the Cache, send the contents of the `VouchCookie` cookie to the Vouch Proxy `/validate` endpoint.
4. If the validation is successful, decode and decompress the cookie and extract the username from the JWT payload.
5. Save the username in cache with a short expiration and use the SHA256 sum of the `VouchCookie` as the key. (i.e. `VouchCookie_` + `sha256sum(VouchCookie)`)

## Installation and Usage 

`pip install django-vouch-proxy-auth` or add `django-vouch-proxy-auth` to your requirements file.

To enable the middleware, add `django_vouch_proxy_auth.middleware.VouchProxyMiddleware` after Django's `AuthenticationMiddleware`.

```python
MIDDLEWARE = [
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    ...
    'django_vouch_proxy_auth.middleware.VouchProxyMiddleware'
]
```

This middleware is also dependent on the `VouchProxyUserBackend` Authentication Backend. Add anywhere in your `AUTHENTICATION_BACKENDS`.

```python
AUTHENTICATION_BACKENDS = (
    'django_vouch_proxy_auth.backends.VouchProxyUserBackend'
)
```

Finally, you MUST tell the middleware where the `/validate` endpoint is. Add the `VOUCH_PROXY_VALIDATE_ENDPOINT` to your Django `settings.py` file.

```python
VOUCH_PROXY_VALIDATE_ENDPOINT = 'https://login.avacado.lol/validate'
```

## Settings
### `VOUCH_PROXY_VALIDATE_ENDPOINT`
Location of the Vouch Proxy validation endpoint. You MUST provide this value, or the Middleware will raise an `ImproperlyConfigured` exception.

### `VOUCH_PROXY_COOKIE_NAME`
Default: `VouchCookie`

Change this setting if you are using a custom Vouch Proxy cookie name.

### `VOUCH_PROXY_CACHE_TIMEOUT`
Default: `300` (seconds)

This middleware will cache the username if a successful response from the `/validate` query is returned. To reduce the load on Vouch Proxy, the middleware will only validate the cookie every 300 seconds (5 minutes) by default.

Set this value to a positive integer if you want to change the cache timeout.

Set this to `0` if you want Django to query the Vouch Proxy `/validate` endpoint on every request.

### `VOUCH_PROXY_CACHE_PREFIX`
Default: defaults to the configured value for `VOUCH_PROXY_COOKIE_NAME` plus underscore (i.e. `VouchCookie_`)

Set this value if you want to change the prefix for the CacheKey.

### `VOUCH_PROXY_CACHE_BACKEND`
Default: `default`

Set this value if you want to store cached results in a different cache.

### `VOUCH_PROXY_DISABLED_PATHS`
Default: `[]`

Set this value (as an array) to full paths that you want to disable the middleware. 

For example, if you have other middleware that causes conflict:
```python
VOUCH_PROXY_DISABLED_PATHS = ['/oidc/authenticate/', '/oidc/callback/']
```

### `VOUCH_PROXY_CREATE_UNKNOWN_USER`
Default: `True`

Set this to False if you do not want the middleware to automatically create a user entry on first login. You must use the

### `VOUCH_PROXY_FORCE_LOGOUT_IF_NO_COOKIE`
Default: `False`

Set this to `True` if you want Django to logout the user if the Vouch Cookie is not present.