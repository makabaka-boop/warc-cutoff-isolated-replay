"""Whitelist sanitizer + fixed-instant link/image rewriter.

Two completely separate steps:

1. :func:`sanitize` keeps only an explicit whitelist of tags/attributes, so
   scripts, forms, styles, embeds and all event handlers are physically gone.
2. :func:`rewrite` resolves links/images first against the archive URI and
   then the first legal ``<base>``, maps them to the *same cutoff* on this
   replay service, and turns anything missing / non-http(s) / wrong media
   type into an inert inline gap marker.  There is no fallback URL left in
   the markup that a browser could fetch online.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, NavigableString

# ---- Explicit whitelists ---------------------------------------------------

ALLOWED_TAGS = frozenset(
    {
        "html", "head", "title", "body",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "p", "br", "hr", "blockquote", "pre", "div", "span",
        "ul", "ol", "li", "dl", "dt", "dd",
        "a", "img",
        "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
        "strong", "em", "b", "i", "u", "small", "sub", "sup", "code", "kbd", "samp", "var",
        "abbr", "cite", "q", "time", "figure", "figcaption",
    }
)

# Attributes are valid only for the tags they are listed for.
ALLOWED_ATTRS: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "title"}),
    "img": frozenset({"src", "alt", "width", "height"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan", "scope"}),
    "col": frozenset({"span"}),
    "colgroup": frozenset({"span"}),
    "time": frozenset({"datetime"}),
    "q": frozenset({"cite"}),
}

# Tags in this set disappear *with all their content*.  Everything else not
# whitelisted is unwrapped (text survives).
DROP_WITH_CONTENT = frozenset(
    {
        "script", "style", "iframe", "object", "embed", "applet", "noscript",
        "template", "form", "input", "button", "select", "textarea", "option",
        "optgroup", "output", "label", "fieldset", "legend", "datalist",
        "canvas", "svg", "math", "audio", "video", "track", "source",
        "frame", "frameset", "base", "link", "meta", "title-in-meta",
    }
)


@dataclass
class RewriteResult:
    html: str
    title: str | None
    base_href: str | None
    gaps: list[str]          # human-readable descriptions of every gap


def sanitize_and_rewrite(
    raw_html: bytes,
    archive_uri: str,
    cutoff: str,
    lookup,
    replay_url_for,
) -> RewriteResult:
    """Return inert, replayed HTML.

    ``lookup(canonical_uri) -> Record | None`` resolves a mapped URI at the
    fixed cutoff; ``replay_url_for(uri, cutoff)`` builds a replay-service URL.
    """
    text = raw_html.decode("utf-8")
    soup = BeautifulSoup(text, "html.parser")

    # Kill comments and processing instructions up front.
    for c in soup.find_all(string=lambda s: s.__class__.__name__ in ("Comment", "CData", "ProcessingInstruction", "Doctype")):
        c.extract()

    # 1) Resolve the *first* legal <base href> then remove every <base>.
    base_href = None
    base_tag = soup.find("base")
    if base_tag is not None:
        candidate = base_tag.get("href", "").strip()
        if candidate:
            joined = urljoin(archive_uri, candidate)
            if _is_http_url(joined):
                base_href = joined
    for b in soup.find_all("base"):
        b.decompose()
    document_base = base_href or archive_uri

    gaps: list[str] = []

    # 2) Structural sanitization: whitelist tags/attributes.
    for el in list(soup.find_all(True)):
        if el.parent is None:
            continue  # parent was already dropped with its content
        if el.name in ALLOWED_TAGS:
            allowed = ALLOWED_ATTRS.get(el.name, frozenset())
            for attr in list(el.attrs):
                if attr.lower() not in allowed:
                    del el.attrs[attr]
            continue
        if el.name in DROP_WITH_CONTENT:
            el.decompose()
        else:
            el.unwrap()

    title_tag = soup.find("title")
    title = title_tag.get_text() if title_tag else None
    if title is not None:
        title = title.strip() or None

    # 3) Rewrite images: only a same-cutoff PNG record may survive.
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        resolved = _resolve(document_base, src)
        target = resolved and lookup(resolved)
        if src == "" or resolved is None:
            why = "non-http(s) or unresolvable image source"
            gaps.append(f"img {src!r}: {why}")
            _gap_for(soup, img, f"image gap: {why}")
        elif target is None:
            gaps.append(f"img {src!r}: no capture at this instant")
            _gap_for(soup, img, "image gap: no archived capture at this instant")
        elif target.content_type != "image/png":
            gaps.append(f"img {src!r}: archived resource is not PNG")
            _gap_for(soup, img, "image gap: archived resource is not PNG")
        else:
            img["src"] = replay_url_for(resolved, cutoff, raw=True)

    # 4) Rewrite links: only same-cutoff HTML records stay links; links to
    #    missing/other-scheme/unsupported-type resources become inline gaps,
    #    so there is never an href that could escape to the network.
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        if href == "":
            gaps.append("anchor with no href: dropped")
            a.unwrap()
            continue
        resolved = _resolve(document_base, href)
        if resolved is None:
            gaps.append(f"link {href!r}: non-http(s) scheme")
            _text_gap_for(a, "link gap: scheme not archived")
        else:
            target = lookup(resolved)
            if target is None:
                gaps.append(f"link {href!r}: no capture at this instant")
                _text_gap_for(a, "link gap: no archived capture at this instant")
            elif target.content_type != "text/html; charset=utf-8":
                gaps.append(f"link {href!r}: target is not archived HTML")
                _text_gap_for(a, "link gap: target is not archived HTML")
            else:
                a["href"] = replay_url_for(resolved, cutoff, raw=False)

    # 5) Serialize with the standard escaping formatter.
    if soup.body is not None:
        body_html = "".join(str(c) for c in soup.body.children)
    else:
        body_html = "".join(str(c) for c in soup.find_all(recursive=False)) or soup.decode()
    head_extra = ""
    if title:
        import html as _html
        head_extra = f"<title>{_html.escape(title)}</title>"

    final = (
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">"
        + head_extra
        + "</head><body data-replay=\"1\">"
        + body_html
        + "</body></html>"
    )
    return RewriteResult(final, title, base_href, gaps)


# ---- helpers ---------------------------------------------------------------

def _is_http_url(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() in ("http", "https") and bool(
            urlsplit(url).hostname
        )
    except ValueError:
        return False


def _resolve(base: str, ref: str) -> str | None:
    """Resolve ``ref`` against ``base``; return canonical URI or None."""
    from .validate import validate_target_uri

    try:
        joined = urljoin(base, ref)
    except (ValueError, TypeError):
        return None
    if not _is_http_url(joined):
        return None
    try:
        return validate_target_uri(joined)
    except Exception:
        # urljoin result could carry backslashes/control chars/userinfo.
        return None


def _gap_for(soup, img, label: str) -> None:
    """Replace an <img> with an inert placeholder span carrying no URL."""
    span = soup.new_tag("span")
    span["data-gap"] = "image"
    span.string = f"[{label}]"
    img.replace_with(span)


def _text_gap_for(a, label: str) -> None:
    """Turn an anchor into plain, bracketed gap text (no href remains)."""
    a.attrs = {}
    a.name = "span"
    a["data-gap"] = "link"
    text = a.get_text()
    a.string = f"[{text} — {label}]" if text else f"[{label}]"
