"""Safe HTML sanitisation and fixed-point link rewriting.

Parsing uses the mature :mod:`bs4` library; policy lives here.

Policy
------
* explicit tag and attribute whitelists only;
* text, ordinary hyperlinks (``a href``), tables and PNG images survive;
* scripts, forms, styles, embeds/objects, iframes and every event
  handler / URL-bearing attribute outside the whitelist are removed;
* relative URLs are first resolved against the archived document URI and
  the first legal ``<base href>`` (mirroring browser behaviour), then
  mapped to the *fixed instant* snapshot served by the replay endpoint;
* links to missing captures, non-http(s) schemes or unsupported content
  become a visible gap placeholder and are never fetched from the network.
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urldefrag, urlsplit, urlunsplit

from bs4 import BeautifulSoup

# Structural/text tags that may appear, with exactly the attributes they
# may carry.  Anything not listed is dropped (its safe text is kept unless
# it is one of the dangerous tags stripped wholesale).
ALLOWED_TAGS: dict[str, frozenset[str]] = {
    "html": frozenset(),
    "body": frozenset(),
    "a": frozenset({"href"}),
    "img": frozenset({"src", "alt", "width", "height"}),
    # text structure
    "p": frozenset(),
    "br": frozenset(),
    "hr": frozenset(),
    "h1": frozenset(), "h2": frozenset(), "h3": frozenset(),
    "h4": frozenset(), "h5": frozenset(), "h6": frozenset(),
    "div": frozenset(),
    "span": frozenset({"class"}),
    "blockquote": frozenset(),
    "pre": frozenset(),
    "code": frozenset(),
    "b": frozenset(), "strong": frozenset(),
    "i": frozenset(), "em": frozenset(),
    "u": frozenset(), "small": frozenset(), "sub": frozenset(), "sup": frozenset(),
    "abbr": frozenset({"title"}),
    "cite": frozenset(),
    "time": frozenset({"datetime"}),
    # lists
    "ul": frozenset(), "ol": frozenset({"start", "type"}), "li": frozenset({"value"}),
    "dl": frozenset(), "dt": frozenset(), "dd": frozenset(),
    # tables
    "table": frozenset({"summary"}),
    "caption": frozenset(),
    "thead": frozenset(), "tbody": frozenset(), "tfoot": frozenset(),
    "tr": frozenset(),
    "th": frozenset({"colspan", "rowspan", "scope"}),
    "td": frozenset({"colspan", "rowspan"}),
    "colgroup": frozenset({"span"}),
    "col": frozenset({"span"}),
    # figure
    "figure": frozenset(), "figcaption": frozenset(),
    "picture": frozenset(),  # children source are dropped, img kept
}

# Tags removed together with their text content.
DROP_WITH_CONTENT = frozenset({
    "script", "noscript", "style", "template", "iframe", "object", "embed",
    "applet", "frame", "frameset", "link", "meta", "base",
    "svg", "math",
})

_ATTR_IS_EVENT = re.compile(r"^on[a-z]+$").match
_SAFE_DIM = re.compile(r"^[0-9]{1,5}$").fullmatch
_SAFE_SCOPE = frozenset({"row", "col", "rowgroup", "colgroup"})


class Gap(Exception):
    """A reference that cannot be satisfied from the frozen archive."""


def _first_legal_base(html: str, doc_uri: str) -> str:
    """Return the effective base URI.

    Mirrors the browser rule: the first ``<base href>`` appearing in the
    document wins, but only if it resolves to an absolute http(s) URL with
    the same host as the archived document.  Anything fishy is ignored and
    the archived document URI is used instead.
    """
    soup = BeautifulSoup(html, "html.parser")
    doc_parts = urlsplit(doc_uri)
    base = doc_uri
    for base_tag in soup.find_all("base"):
        href = base_tag.get("href")
        if not href or not href.strip():
            continue
        candidate = _resolve(base, href.strip())
        parts = urlsplit(candidate)
        if parts.scheme not in ("http", "https"):
            continue
        if parts.hostname != doc_parts.hostname or parts.port != doc_parts.port:
            continue
        return candidate
    return base


def _resolve(base: str, ref: str) -> str:
    """Conservative relative resolution without network access.

    Host casing and percent-encoding are preserved verbatim: archived URIs
    are literal record identities, not live HTTP requests to normalise.
    """
    ref = ref.strip()
    parts = urlsplit(ref)
    if parts.scheme:
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                           parts.query, ""))
    base_parts = urlsplit(base)
    if ref.startswith("//"):
        return urlunsplit((base_parts.scheme, parts.netloc, parts.path or "/",
                           parts.query, ""))
    if ref.startswith("/"):
        path = parts.path
    elif not parts.path:
        path = base_parts.path or "/"
        if not parts.query and not parts.fragment:
            return urlunsplit((base_parts.scheme, base_parts.netloc, path,
                               base_parts.query, ""))
    else:
        base_dir = base_parts.path.rsplit("/", 1)[0]
        path = _normalise(base_dir + "/" + parts.path)
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((base_parts.scheme, base_parts.netloc, path,
                       parts.query, ""))


def _normalise(path: str) -> str:
    out: list[str] = []
    for seg in path.split("/"):
        if seg == "..":
            if out:
                out.pop()
        elif seg not in (".", ""):
            out.append(seg)
    return "/".join(out)


def sanitize_and_rewrite(
    html_bytes: bytes,
    doc_uri: str,
    cutoff: datetime,
    exists_at,
) -> tuple[str, list[dict]]:
    """Sanitise archived HTML and map references to frozen local captures.

    ``exists_at(uri, cutoff)`` returns the stored record selected for the
    instant, or ``None``.  References to non-HTML captures inside ``a`` are
    treated as gaps too (the viewer only navigates between HTML pages).

    Returns ``(rewritten_html, references)`` where references describes
    every resolution outcome for the UI/tests.
    """
    html = html_bytes.decode("utf-8")
    base_uri = _first_legal_base(html, doc_uri)

    soup = BeautifulSoup(html, "html.parser")

    references: list[dict] = []

    # Remove dangerous elements together with their contents.
    for tag in soup.find_all():
        if tag.name in DROP_WITH_CONTENT or tag.name == "base":
            tag.decompose()

    # Comments and processing instructions never survive.
    from bs4 import Comment, Doctype, ProcessingInstruction
    for node in list(soup.find_all(string=True)):
        if isinstance(node, (Comment, Doctype, ProcessingInstruction)):
            node.extract()

    def map_reference(ref: str, *, as_image: bool) -> tuple[str, object]:
        """Resolve ref -> local replay URL or raise Gap."""
        if not ref or ref.isspace():
            raise Gap("empty reference")
        lowered = ref.strip().lower()
        # Explicitly refuse anything that can execute or leave the scheme.
        if lowered.startswith(("javascript:", "data:", "vbscript:", "file:",
                               "blob:", "about:")):
            raise Gap("non-navigation scheme")
        absolute = _resolve(base_uri, ref)
        no_frag, _frag = urldefrag(absolute)
        parts = urlsplit(no_frag)
        if parts.scheme not in ("http", "https"):
            raise Gap(f"unsupported scheme {parts.scheme!r}")
        record = exists_at(no_frag, cutoff)
        if record is None:
            raise Gap("no capture at the selected instant")
        if as_image:
            if record.content_type != "image/png":
                raise Gap("captured resource is not PNG")
        else:
            if record.content_type != "text/html;charset=utf-8":
                raise Gap("captured resource is not HTML")
        # Local import on purpose: app.main imports this module, so a
        # module-level import here would be a cycle.
        from .main import replay_url
        return replay_url(no_frag, cutoff), record

    for a in soup.find_all("a"):
        raw = a.get("href")
        entry: dict = {"kind": "link", "raw": raw}
        try:
            if raw is None:
                raise Gap("missing href")
            local, record = map_reference(raw, as_image=False)
            a["href"] = local
            entry.update(status="mapped", resolved_to=record.uri,
                         record_id=record.record_id)
        except Gap as gap:
            entry.update(status="gap", reason=str(gap))
            _render_gap_anchor(a, str(gap))
        references.append(entry)

    for img in soup.find_all("img"):
        raw = img.get("src")
        entry: dict = {"kind": "image", "raw": raw}
        try:
            if raw is None:
                raise Gap("missing src")
            local, record = map_reference(raw, as_image=True)
            img["src"] = local
            # Defensive: never let an img navigate or carry event attrs.
            entry.update(status="mapped", resolved_to=record.uri,
                         record_id=record.record_id)
        except Gap as gap:
            entry.update(status="gap", reason=str(gap))
            alt = img.get("alt")
            label = f" (alt: {alt})" if alt and isinstance(alt, str) else ""
            placeholder = soup.new_tag("span", attrs={"class": "archive-gap"})
            placeholder.string = f"[archived image missing{label}: {gap}]"
            img.replace_with(placeholder)
        references.append(entry)

    # Whitelist pass over every surviving tag/attribute.
    for tag in soup.find_all():
        allowed_attrs = ALLOWED_TAGS.get(tag.name)
        if allowed_attrs is None:
            # Unknown tag: unwrap (keep safe textual content).
            tag.unwrap()
            continue
        for attr in list(tag.attrs):
            value = tag.attrs[attr]
            attr_l = attr.lower()
            if _ATTR_IS_EVENT(attr_l) or attr_l.startswith("xmlns"):
                del tag.attrs[attr]
                continue
            if attr_l not in allowed_attrs:
                del tag.attrs[attr]
                continue
            if isinstance(value, list):
                # bs4 splits class (and other multi-valued attrs) into
                # lists; allow a single exact class token, reject others.
                value = " ".join(value)
                tag.attrs[attr] = value
            if tag.name == "span" and attr_l == "class" and value != "archive-gap":
                del tag.attrs[attr]
            elif tag.name == "img" and attr_l in ("width", "height"):
                if not _SAFE_DIM(value):
                    del tag.attrs[attr]
            elif tag.name == "ol" and attr_l == "start":
                if not re.fullmatch(r"-?[0-9]{1,6}", value):
                    del tag.attrs[attr]
            elif tag.name == "ol" and attr_l == "type":
                if value not in ("1", "A", "a", "I", "i"):
                    del tag.attrs[attr]
            elif tag.name in ("th", "td", "col", "colgroup") and attr_l in (
                "colspan", "rowspan", "span",
            ):
                if not re.fullmatch(r"[1-9][0-9]{0,2}", value):
                    del tag.attrs[attr]
            elif tag.name == "th" and attr_l == "scope":
                if value not in _SAFE_SCOPE:
                    del tag.attrs[attr]
            elif tag.name == "time" and attr_l == "datetime":
                if not re.fullmatch(r"[0-9TZ:.,+\-]{1,40}", value or ""):
                    del tag.attrs[attr]
            elif tag.name == "a" and attr_l == "href":
                if not value.startswith("/replay?"):
                    del tag.attrs[attr]
            elif tag.name == "img" and attr_l == "src":
                if not value.startswith("/replay?"):
                    del tag.attrs[attr]

    out = str(soup)
    # Structural last-resort guard: parse the serialised output again and
    # prove nothing forbidden survived (no regex guessing over text nodes).
    check = BeautifulSoup(out, "html.parser")
    for tag in check.find_all():
        if tag.name not in ALLOWED_TAGS:
            raise ValueError(f"sanitiser left forbidden tag {tag.name!r}")
        for attr in tag.attrs:
            if _ATTR_IS_EVENT(attr.lower()) or attr.lower() not in ALLOWED_TAGS[tag.name]:
                raise ValueError(f"sanitiser left forbidden attribute {attr!r}")
        if tag.name == "a" and tag.get("href", "").startswith(
            ("javascript:", "data:", "vbscript:")
        ):
            raise ValueError("sanitiser left a dangerous href")
    return out, references


def _render_gap_anchor(a, reason: str) -> None:
    """Replace a dangling anchor with an inert, visibly marked gap."""
    text = a.get_text()
    a.name = "span"
    a.attrs = {"class": "archive-gap", "title": f"not in archive: {reason}"}
    a.clear()
    if text:
        a.string = text + " "
    a.append("[link unavailable in archive]")
