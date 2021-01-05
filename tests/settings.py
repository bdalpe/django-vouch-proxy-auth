SECRET_KEY = 'django-vouch-proxy-auth'

DEBUG = True

USE_TZ = True

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    },
    'dummy': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
    }
}

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
]

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

MIDDLEWARE = []

VOUCH_PROXY_VALIDATE_ENDPOINT = 'http://vouch/validate'
