"""Restricted WARC replay service.

Serves two kinds of traffic, both locked to archive contents only:

* ``/api/*``   -- import/inspect the in-memory archive;
* ``/replay``  -- a single frozen-instant capture of one URI, served
                  either as sanitised HTML or as the archived PNG.

The service never opens a connection to the original sites.  A URI is
resolved to the newest capture dated at or before the user-supplied
instant; references inside sanitised HTML are rewritten to the same
instant on this same service.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote, unquote

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response as PlainResponse

from .rewriter import sanitize_and_rewrite
from .storage import HTML as HTML_CT, PNG as PNG_CT, MAX_RECORDS, MAX_TOTAL_BYTES, store
from .warcparse import WarcFormatError, parse_warc

INSTANT_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"

# Where the (separate) static viewer page is served from.  Configurable so
# the Compose deployment and the local test harness can state their own.
_DEFAULT_VIEWER_ORIGINS = ("http://localhost:8080", "http://127.0.0.1:8080")
VIEWER_ORIGINS = tuple(
    o for o in os.environ.get("VIEWER_ORIGINS", "").split(",") if o
) or _DEFAULT_VIEWER_ORIGINS

app = FastAPI(title="restricted-warc-replay", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(VIEWER_ORIGINS),
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
    expose_headers=["x-archive-record-id", "x-archive-capture-date"],
    max_age=60,
)

GAP_PAGE = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<title>Archive gap</title></head><body>"
    "<p><strong>[archive gap]</strong> {message}</p>"
    "<p>No request was made to the original site.</p>"
    "</body></html>"
)


def replay_url(uri: str, at: datetime | str) -> str:
    instant = at if isinstance(at, str) else at.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"/replay?at={quote(instant, safe='')}&uri={quote(uri, safe='')}"


def parse_instant(value: str) -> datetime:
    if not re.fullmatch(INSTANT_RE, value or ""):
        raise WarcFormatError("instant must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise WarcFormatError(f"{value!r} is not a valid instant")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    return response


def replay_csp() -> str:
    # Images may only come from this replay service; nothing else at all.
    # frame-ancestors permits the separate viewer origin; the CSP sandbox
    # and the iframe sandbox attribute independently deny scripting.
    return (
        "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; "
        "frame-ancestors " + " ".join(VIEWER_ORIGINS) +
        "; base-uri 'none'; form-action 'none'; sandbox"
    )


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;")
    )


def gap_response(message: str, status: int = 404) -> HTMLResponse:
    safe = (
        message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    return HTMLResponse(
        GAP_PAGE.format(message=safe),
        status_code=status,
        headers={"Content-Security-Policy": replay_csp()},
    )


# ---------------------------------------------------------------------------
# Archive management / inspection
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/api/reset")
async def reset():
    store.reset()
    return {"ok": True, "stats": store.stats()}


@app.get("/api/stats")
async def stats():
    return store.stats()


@app.post("/api/import")
async def import_warc(request: Request):
    data = await request.body()
    try:
        records = parse_warc(data)
        store.add_batch(records)
    except WarcFormatError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        status = getattr(exc, "status", 409)
        return JSONResponse({"error": str(exc)}, status_code=status)
    return {
        "imported": [r.to_dict() for r in records],
        "stats": store.stats(),
        "limits": {"max_records": MAX_RECORDS, "max_total_bytes": MAX_TOTAL_BYTES},
    }


@app.get("/api/records")
async def records():
    return [r.to_dict() for r in store.list_records()]


@app.get("/api/uris")
async def uris():
    grouped: dict[str, list[dict]] = {}
    for rec in store.list_records():
        grouped.setdefault(rec.uri, []).append(
            {"date": rec.date.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "record_id": rec.record_id, "content_type": rec.content_type}
        )
    return [{"uri": uri, "captures": caps} for uri, caps in sorted(grouped.items())]


@app.get("/api/select")
async def select(uri: str, at: str):
    try:
        instant = parse_instant(at)
    except WarcFormatError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    record = store.select(unquote(uri), instant)
    if record is None:
        return JSONResponse(
            {"uri": uri, "at": at, "status": "gap",
             "reason": "no capture dated at or before the instant"},
            status_code=404,
        )
    return {
        "status": "selected",
        "uri": uri,
        "at": at,
        "record": record.to_dict(),
        "replay_url": replay_url(record.uri, at),
    }


# ---------------------------------------------------------------------------
# Frozen-instant replay
# ---------------------------------------------------------------------------

@app.get("/replay")
async def replay(at: str, uri: str):
    try:
        instant = parse_instant(at)
    except WarcFormatError as exc:
        return gap_response(str(exc), status=400)

    target = unquote(uri)
    record = store.select(target, instant)
    if record is None:
        return gap_response(
            f"no capture of {target} dated at or before {at}", status=404
        )

    base_headers = {
        "Content-Security-Policy": replay_csp(),
        "X-Archive-Record-Id": record.record_id,
        "X-Archive-Capture-Date": record.date.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if record.content_type == PNG_CT:
        return PlainResponse(
            record.body, media_type="image/png",
            headers={**base_headers, "Cache-Control": "no-store"},
        )

    # HTML: sanitise and rewrite every reference against THIS instant.
    sanitized, references = sanitize_and_rewrite(
        record.body, record.uri, instant, store.select
    )
    banner = (
        '<div id="archive-provenance" '
        'style="border-bottom:2px solid #2456a6;background:#eef3fc;'
        'color:#16233b;font:12px/1.5 system-ui,sans-serif;'
        'padding:6px 10px;margin:0 0 10px">'
        '<strong>归档时点内容</strong> · 原 URI: '
        f'{_escape(record.uri)}<br>截止时刻: {_escape(at)} · '
        f'实际抓取: {record.date.strftime("%Y-%m-%dT%H:%M:%SZ")} · '
        f'Record-ID: {_escape(record.record_id)}'
        '</div>'
    )
    body = (
        '<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
        '<title>归档回放</title></head><body>'
        + banner + sanitized + "</body></html>"
    )
    return HTMLResponse(
        body,
        headers={
            **base_headers,
            "Cache-Control": "no-store",
            "X-Archive-Original-URI": quote(record.uri, safe=""),
            "X-Archive-References": quote(json.dumps(references), safe=""),
        },
    )
