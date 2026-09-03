Installation
============

Requirements
------------

* Python 3.10 or newer. The wheels are built against the stable ABI
  (``abi3``), so one wheel per platform covers every supported interpreter.
* Nothing else at runtime: TLS is provided by ``rustls`` with a bundled
  Mozilla root store (compiled in), so there is no OpenSSL dependency, and
  outbound HTTP uses the bundled ``reqwest`` client.
* For the PKCS#11 / HSM signing path: a PKCS#11 module such as SoftHSM2 or
  Kryoptic. The module is loaded with ``dlopen`` at runtime, so it is needed
  only to use a token, not to install or import pygrindvakt.
* For :class:`pygrindvakt.provider.RedisStore`: a reachable Redis server. The
  Redis client is compiled in; no Python Redis package is required.

From a wheel
------------

.. code-block:: console

   pip install pygrindvakt

or, with `uv <https://docs.astral.sh/uv/>`_:

.. code-block:: console

   uv pip install pygrindvakt

Prebuilt ``manylinux`` wheels include the compiled extension (with grindvakt's
``pkcs11`` and ``redis`` features enabled) and PEP 561 type stubs, so no Rust
toolchain is required.

.. tip:: HSM / PKCS#11 deployments

   If you will sign with a PKCS#11 token in production, prefer building the
   wheel **on, or against, the target host** rather than relying on the
   generic prebuilt wheel. The PKCS#11 module is loaded at runtime from that
   host; building where the token tooling and system libraries live avoids
   glibc / loader mismatches and lets you validate signing against the real
   module before shipping. See :doc:`api/keys`.

From source
-----------

Building from source needs a Rust toolchain (1.75 or newer) and `maturin
<https://www.maturin.rs>`_. The project uses uv:

.. code-block:: console

   uv venv
   uv pip install --python .venv/bin/python "maturin==1.14.1"
   VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --release --uv
   .venv/bin/python -c "import pygrindvakt; print(pygrindvakt.__version__)"

.. note::

   The pygrindvakt repository requires every package install to go through
   ``sfw`` (Socket Firewall), which proxies registry traffic and blocks
   known-malicious packages: ``sfw uv pip install ...``. That is a policy of
   the project's own development environment; plain ``uv`` or ``pip`` works
   everywhere else.

Optional dependencies
---------------------

The library itself has no Python dependencies. The examples and the test
suite use a few:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Package
     - Used by
   * - ``cryptography``
     - The DPoP tests, which build client-side proofs with a fresh EC key.
   * - ``flask``
     - ``examples/flask-op`` and ``examples/flask-rp``.
   * - ``django``
     - ``examples/django-op``.
   * - ``fastapi`` and ``httpx``
     - ``examples/fastapi-op`` (``httpx`` drives FastAPI's test client).
   * - ``pytest``
     - The test suite.

Install them all with:

.. code-block:: console

   uv pip install --python .venv/bin/python pytest cryptography flask django fastapi httpx
   .venv/bin/python -m pytest tests/

Tests that need a SoftHSM2 token or a Redis server skip themselves when the
tooling is missing.

Redis
-----

:class:`pygrindvakt.provider.RedisStore` talks to Redis directly from Rust.
Tests marked ``redis`` run only when ``REDIS_URL`` is set:

.. code-block:: console

   REDIS_URL=redis://127.0.0.1/ .venv/bin/python -m pytest tests/ -m redis

See :doc:`guides/stores` for when a Redis-backed store is required and how to
construct it safely in a multi-process server.

SoftHSM2
--------

The PKCS#11 tests provision a throw-away SoftHSM2 token with ``softhsm2-util``
and ``pkcs11-tool`` (from OpenSC). On Debian / Ubuntu:

.. code-block:: console

   sudo apt install softhsm2 opensc

The tests look for the module at the usual locations
(``/usr/lib/softhsm/libsofthsm2.so``,
``/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so``) and skip when neither
the module nor the tools are present. Loading a key from a token in your own
code is one call:

.. code-block:: python

   from pygrindvakt import keys

   key = keys.signing_key_from_pkcs11(
       "/usr/lib/softhsm/libsofthsm2.so", "1234", "op-signing-key", "ES256", kid="hsm-1"
   )

Type checking
-------------

The package ships ``py.typed`` and a ``.pyi`` stub per submodule, so mypy and
pyright pick up types with no extra configuration:

.. code-block:: python

   from pygrindvakt import client

   c = client.Client("demo", redirect_uris=["https://rp.example.com/cb"])
   reveal_type(c.redirect_uris)   # list[str]

Building this documentation
---------------------------

The API reference is hand-written (no autodoc), so the docs build does not
need the compiled extension. From the repository root:

.. code-block:: console

   uv pip install --python .venv/bin/python --group docs
   .venv/bin/python -m sphinx -b html -W docs docs/_build/html
