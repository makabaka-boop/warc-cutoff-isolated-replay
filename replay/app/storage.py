"""In-memory archive storage with fixed-cutoff record selection."""
from __future__ import annotations

import datetime as _dt
import threading

from .warc_parser import Record, parse_archive
from .warc_parser import WARCFormatError


def _parse_cutoff(value: str) -> _dt.datetime:
    """Accept YYYY-MM-DDTHH:MM:SSZ, second-less variants or datetime-local."""
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1]
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
            try:
                dt = _dt.datetime.strptime(v, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unrecognized cutoff: {value!r}")
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    else:
        # datetime-local from the page has no zone: interpret explicitly as UTC.
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
            try:
                dt = _dt.datetime.strptime(v, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unrecognized cutoff: {value!r}")
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def record_datetime(rec: Record) -> _dt.datetime:
    return _dt.datetime.strptime(rec.date_iso, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=_dt.timezone.utc
    )


class Archive:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: list[Record] = []

    # -- mutation -----------------------------------------------------------

    def load(self, data: bytes) -> dict:
        records = parse_archive(data)
        # Same capture instant for the same URI is a conflict -> reject all.
        seen: set[tuple[str, str]] = set()
        for r in records:
            key = (r.target_uri, r.date_iso)
            if key in seen:
                raise WARCFormatError(
                    f"two records for {r.target_uri} at the same instant {r.date_iso}"
                )
            seen.add(key)
        with self._lock:
            self._records = list(records)
        return self.summary()

    # -- reads --------------------------------------------------------------

    def summary(self) -> dict:
        with self._lock:
            by_uri: dict[str, list[Record]] = {}
            for r in self._records:
                by_uri.setdefault(r.target_uri, []).append(r)
            uris = []
            for uri, recs in sorted(by_uri.items()):
                dates = sorted(record_datetime(x) for x in recs)
                types = sorted({x.content_type.split(";")[0] for x in recs})
                uris.append(
                    {
                        "uri": uri,
                        "captures": [
                            d.strftime("%Y-%m-%dT%H:%M:%SZ") for d in dates
                        ],
                        "types": types,
                        "record_ids": [x.record_id for x in recs],
                    }
                )
            return {
                "record_count": len(self._records),
                "bytes": sum(len(r.body) for r in self._records),
                "uris": uris,
            }

    def all_records(self) -> list[Record]:
        with self._lock:
            return list(self._records)

    def lookup_at(self, canonical_uri: str, cutoff: _dt.datetime) -> Record | None:
        """Newest record for the URI not later than the cutoff, else None."""
        candidates = [
            r
            for r in self._records
            if r.target_uri == canonical_uri and record_datetime(r) <= cutoff
        ]
        if not candidates:
            return None
        return max(candidates, key=record_datetime)


ARCHIVE = Archive()
