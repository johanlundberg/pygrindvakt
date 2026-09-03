"""The process-wide ``Provider``, built once at import time.

With ``gunicorn --preload`` (or any server that imports the app before
forking workers) build it lazily in the worker or in a ``post_fork`` hook
instead: the Provider owns native runtime threads that are not inherited
across ``fork()``, and an in-memory token-use store must not be shared by
copy across workers anyway (use ``provider.RedisStore`` there).
"""

from django.conf import settings

from common.op_config import build_provider

OP = build_provider(settings.OP_ISSUER)
TOKEN_URL = f"{settings.OP_ISSUER}/token"
