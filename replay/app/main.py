"""Restricted WARC replay service.

Everything that leaves this service is either:

* JSON metadata for the index/control page, or
* a sanitized HTML document / stored PNG rendered inside a sandboxed,
  script-less iframe.

The replay responses never point the browser at the live web: missing
resources become explicit inline gaps, and the Content-Security-Policy pins
images to this origin alone.
"""
from __future__ import annotations

import html as _html
import os

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response as FastResponse

from .rewriter import sanitize_and_rewrite
from .storage import ARCHIVE, _parse_cutoff, record_datetime
from .validate import validate_target_uri
from .warc_parser import WARCFormatError

MAX_UPLOAD = 64 * 1024
# The static control page is the only origin allowed to frame and read JSON.
WEB_ORIGIN = os.environ.get("WEB_ORIGIN", "http://localhost:8080")

app = FastAPI(title="restricted-warc-replay", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["content-type"],
)


# ---- shared response hardening --------------------------------------------

def _no_network_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        # Images may only come back from this replay service; nothing else
        # (script/style/frame/font/connect) may load at all.
        "Content-Security-Policy": (
            "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; "
            "frame-ancestors " + WEB_ORIGIN + "; sandbox; base-uri 'none'"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Resource-Policy": "cross-origin",
        "Cache-Control": "no-store",
    }
    if extra:
        headers.update(extra)
    return headers


@app.exception_handler(WARCFormatError)
async def _warc_error(_: Request, exc: WARCFormatError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": str(exc)},
        headers=_no_network_headers(),
    )


# ---- import / index --------------------------------------------------------

@app.post("/api/import")
async def import_archive(request: Request) -> JSONResponse:
    data = await request.body()
    if len(data) > MAX_UPLOAD:
        return JSONResponse(
            status_code=413,
            content={"error": f"upload exceeds {MAX_UPLOAD} bytes"},
            headers=_no_network_headers(),
        )
    summary = ARCHIVE.load(data)
    return JSONResponse(summary, headers=_no_network_headers())


@app.get("/api/index")
async def index() -> JSONResponse:
    return JSONResponse(ARCHIVE.summary(), headers=_no_network_headers())


@app.get("/healthz")
async def healthz() -> FastResponse:
    return FastResponse("ok", headers={"Cache-Control": "no-store"})


# ---- replay ----------------------------------------------------------------

def _selection_or_gap(canonical_uri: str, cutoff_str: str):
    from fastapi import HTTPException

    try:
        cutoff = _parse_cutoff(cutoff_str)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="bad cutoff")
    record = ARCHIVE.lookup_at(canonical_uri, cutoff)
    return cutoff, record


def _replay_url(uri: str, cutoff: str, *, raw: bool) -> str:
    kind = "raw" if raw else "view"
    return f"/{kind}/{cutoff}/{uri}"


@app.get("/api/select")
async def select(cutoff: str, uri: str) -> JSONResponse:
    """Metadata about which record the fixed instant resolves to."""
    try:
        canonical = validate_target_uri(uri)
        cutoff_dt, record = _selection_or_gap(canonical, cutoff)
    except WARCFormatError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)},
                            headers=_no_network_headers())
    if record is None:
        return JSONResponse(
            status_code=404,
            content={
                "gap": True,
                "canonical_uri": canonical,
                "cutoff": cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reason": "no capture at or before the cutoff",
            },
            headers=_no_network_headers(),
        )
    return JSONResponse(
        {
            "gap": False,
            "canonical_uri": canonical,
            "cutoff": cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "record_id": record.record_id,
            "captured_at": record.date_iso,
            "content_type": record.content_type,
            "body_length": len(record.body),
        },
        headers=_no_network_headers(),
    )


def _gap_page(label: str, detail: str, status: int = 404) -> HTMLResponse:
    body = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<style>body{font:14px/1.5 system-ui;background:#f6f6f6;color:#333}"
        ".g{max-width:640px;margin:3rem auto;padding:1.2rem 1.4rem;border:1px solid #ccc;"
        "background:#fff;border-radius:8px}</style></head><body>"
        "<div class=\"g\"><strong>Content gap</strong><p>"
        + _html.escape(label) + "</p><p style=\"color:#777\">"
        + _html.escape(detail)
        + "</p><p>The viewer never fetches this resource from the live web.</p></div>"
        "</body></html>"
    )
    return HTMLResponse(body, status_code=status, headers=_no_network_headers())


@app.get("/view/{cutoff}/{uri:path}")
async def view(cutoff: str, uri: str) -> Response:
    """Sanitized, rewritten HTML page for the sandbox iframe."""
    try:
        canonical = validate_target_uri(uri)
    except WARCFormatError as exc:
        return _gap_page("Unsupported URI", str(exc), status=400)
    try:
        cutoff_dt, record = _selection_or_gap(canonical, cutoff)
    except Exception:
        return _gap_page("Bad cutoff", cutoff, status=400)
    if record is None:
        return _gap_page(
            canonical,
            f"No archived capture at or before {cutoff}. The live site was not contacted.",
        )
    if record.content_type != "text/html; charset=utf-8":
        return _gap_page(canonical, "The capture at this instant is not archived UTF-8 HTML.")

    result = sanitize_and_rewrite(
        record.body,
        canonical,
        cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        lambda u: ARCHIVE.lookup_at(u, cutoff_dt),
        _replay_url,
    )
    import html as _h
    provenance = (
        "<!-- replay-provenance record-id=" + record.record_id
        + " captured-at=" + record.date_iso
        + " uri=" + _h.escape(canonical) + " -->\n"
    )
    styled = result.html.replace(
        "<body",
        "<body style=\"font:14px/1.5 system-ui;margin:1rem;color:#1a1a1a;background:#fff\"",
        1,
    )
    gap_meta = ""
    if result.gaps:
        gap_meta = "<!-- gaps: " + _h.escape("; ".join(result.gaps)) + " -->\n"
    return HTMLResponse(
        provenance + gap_meta + styled,
        headers=_no_network_headers(
            {"X-Warc-Record-Id": record.record_id, "X-Warc-Date": record.date_iso}
        ),
    )


@app.get("/raw/{cutoff}/{uri:path}")
async def raw(cutoff: str, uri: str) -> Response:
    """Stored bytes for embedded resources (PNG only)."""
    try:
        canonical = validate_target_uri(uri)
    except WARCFormatError:
        return Response(status_code=400, headers=_no_network_headers())
    try:
        cutoff_dt, record = _selection_or_gap(canonical, cutoff)
    except Exception:
        return Response(status_code=400, headers=_no_network_headers())
    if record is None or record.content_type != "image/png":
        # Inline gap image would itself be an image; returning 404 with no
        # body means the browser renders nothing and makes no further request.
        return Response(status_code=404, headers=_no_network_headers())
    return Response(
        content=record.body,
        media_type="image/png",
        headers=_no_network_headers(
            {"X-Warc-Record-Id": record.record_id, "X-Warc-Date": record.date_iso}
        ),
    )
