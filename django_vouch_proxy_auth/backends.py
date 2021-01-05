from django.contrib.auth.backends import RemoteUserBackend
from django.conf import settings


class VouchProxyUserBackend(RemoteUserBackend):
    def __init__(self, *args, **kwargs):
        self.create_unknown_user = getattr(settings, 'VOUCH_PROXY_CREATE_UNKNOWN_USER', True)

        super().__init__(*args, **kwargs)