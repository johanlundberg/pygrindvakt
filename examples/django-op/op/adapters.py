"""Django <-> pygrindvakt request / response adapters."""

from django.http import HttpRequest, HttpResponse

from pygrindvakt.http import HttpRequestData, Response


def request_data(request: HttpRequest) -> HttpRequestData:
    """Normalize a Django request into an ``HttpRequestData``.

    ``request.headers`` is Django's view of ``META``'s ``HTTP_*`` entries (plus
    ``CONTENT_TYPE`` / ``CONTENT_LENGTH``); pygrindvakt wants the names lower-cased.
    """
    body = request.body  # read before ``POST`` so the raw bytes stay available
    return HttpRequestData(
        path=request.path.lstrip("/"),
        method=request.method or "GET",
        uri=request.build_absolute_uri(),
        query=[(key, value) for key, values in request.GET.lists() for value in values],
        form=[(key, value) for key, values in request.POST.lists() for value in values],
        body=body,
        headers={k.lower(): v for k, v in request.headers.items()},
        cookies=dict(request.COOKIES),
    )


def to_django(resp: Response) -> HttpResponse:
    """Turn a pygrindvakt ``Response`` into a Django ``HttpResponse``."""
    out = HttpResponse(resp.body, status=resp.status)
    del out["Content-Type"]  # keep only what pygrindvakt set
    for name, value in resp.headers:
        out[name] = value
    return out
